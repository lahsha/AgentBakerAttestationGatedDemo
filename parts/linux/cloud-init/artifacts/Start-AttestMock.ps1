[CmdletBinding(DefaultParameterSetName='Start')]
param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [int]$Port = 9080,
  [string]$HashAlg = 'sha256',
  [string]$Pcrs = '0,7,11',
  [int]$MaxWaitSeconds = 25,
  [switch]$Stop,
  [switch]$NoRestartAttest,   # if set, do not restart attest.service after mock start
  [switch]$ForceEphemeralAK   # inject AK_HANDLE= to force ephemeral creation
)

$ErrorActionPreference = 'Stop'

function Resolve-Node {
  Write-Host "Resolving nodeResourceGroup..."
  $nodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
  if (-not $nodeRG) { throw "Could not resolve nodeResourceGroup" }
  Write-Host "Fetching providerID for $NodeName..."
  $provId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
  if (-not $provId) { throw "Could not get providerID" }
  $m = [regex]::Match($provId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
  if (-not $m.Success) { throw "Could not parse providerID '$provId'" }
  @{
    NodeResourceGroup = $nodeRG
    Vmss = $m.Groups[1].Value
    InstanceId = $m.Groups[2].Value
  }
}

$nodeInfo = Resolve-Node
Write-Host "Target => NodeRG=$($nodeInfo.NodeResourceGroup) VMSS=$($nodeInfo.Vmss) IID=$($nodeInfo.InstanceId)"

if ($Stop) {
  $stopScript = @"
#!/bin/sh
set -eu
if [ -f /var/run/attest-mock.pid ]; then
  kill "\$(cat /var/run/attest-mock.pid)" 2>/dev/null || true
  rm -f /var/run/attest-mock.pid
fi
pkill -f /opt/attest-mock/server.py 2>/dev/null || true
echo "Stopped mock server"
"@
  $tmpStop = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
  [IO.File]::WriteAllText($tmpStop, ($stopScript -replace "`r`n","`n"), [Text.UTF8Encoding]::UTF8)
  az vmss run-command invoke -g $nodeInfo.NodeResourceGroup -n $nodeInfo.Vmss --instance-id $nodeInfo.InstanceId --command-id RunShellScript --scripts "@$tmpStop"
  Remove-Item -Force $tmpStop
  return
}

# Remote script to start mock + configure attest
$remote = @"
#!/usr/bin/env bash
set -euo pipefail

PORT="__PORT__"
HASH_ALG="__HASH_ALG__"
PCRS="__PCRS__"
FORCE_EPHEMERAL="__FORCE_EPHEMERAL__"
RESTART_ATTEST="__RESTART_ATTEST__"

log(){ echo "[start-mock] \$(date --iso-8601=seconds) \$*" >&2; }

install -d -m 0755 /opt/attest-mock /etc/default /var/run

# Dependencies (best-effort, avoid big upgrades)
if ! command -v python3 >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y --no-install-recommends python3 || true
fi

cat > /opt/attest-mock/server.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, os, time, random

def randhex(n=16):
    return "".join("%02x" % random.randrange(256) for _ in range(n))

class H(BaseHTTPRequestHandler):
    def _ok(self, code=200):
        self.send_response(code); self.send_header("Content-Type","application/json"); self.end_headers()
    def log_message(self, *args): return
    def do_GET(self):
        if self.path.startswith("/challenge"):
            nonce = randhex()
            self._ok(); self.wfile.write(json.dumps({"nonce": nonce}).encode())
        else:
            self._ok(404); self.wfile.write(b"{}")
    def do_POST(self):
        if self.path.startswith("/verify"):
            ln = int(self.headers.get("content-length","0"))
            raw = self.rfile.read(ln) if ln else b"{}"
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            resp = {
                "ok": True,
                "verifier": "mock",
                "sub": data.get("node"),
                "token": "mock-token-" + randhex(8),
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
            self._ok(); self.wfile.write(json.dumps(resp).encode())
        else:
            self._ok(404); self.wfile.write(b"{}")

if __name__ == "__main__":
    httpd = HTTPServer(("127.0.0.1", __PORT__), H)
    with open("/var/run/attest-mock.pid","w") as f: f.write(str(os.getpid()))
    httpd.serve_forever()
PY

chmod 0755 /opt/attest-mock/server.py

# Stop previous instance
if [ -f /var/run/attest-mock.pid ]; then
  kill "\$(cat /var/run/attest-mock.pid)" 2>/dev/null || true
  rm -f /var/run/attest-mock.pid || true
fi
pkill -f /opt/attest-mock/server.py 2>/dev/null || true

# Start new mock
nohup python3 /opt/attest-mock/server.py >/var/log/attest-mock.log 2>&1 &

# Probe readiness
for i in \$(seq 1 10); do
  if curl -fsS "http://127.0.0.1:$PORT/challenge" >/dev/null 2>&1; then
    log "Mock ready (attempt \$i)"
    break
  fi
  sleep 1
done

# Configure /etc/default/attest
touch /etc/default/attest
update_kv() {
  k="\$1"; v="\$2"
  if grep -q "^\$k=" /etc/default/attest 2>/dev/null; then
    sed -i "s|^\$k=.*|\$k=\$v|" /etc/default/attest
  else
    printf "%s=%s\n" "\$k" "\$v" >> /etc/default/attest
  fi
}

update_kv MODE "MOCK"
update_kv CHALLENGE_URL "http://127.0.0.1:$PORT/challenge"
update_kv VERIFIER_URL  "http://127.0.0.1:$PORT/verify"
update_kv PCRS "\$PCRS"
update_kv TPM_HASH_ALG "\$HASH_ALG"
update_kv REQUIRE_TPM "true"
update_kv REQUIRE_SECURE_BOOT "true"

if [ "\$FORCE_EPHEMERAL" = "true" ]; then
  # Force ephemeral by invalidating persistent handle variable
  sed -i '/^AK_HANDLE=/d' /etc/default/attest || true
fi

# Clean old state
rm -f /var/lib/attest/status.json /var/lib/attest/verdict.jwt || true

# Ensure kubelet drop-in does NOT hard gate
DROPIN=/etc/systemd/system/kubelet.service.d/10-attestation.conf
if [ -f "\$DROPIN" ]; then
  sed -i '/^Requires=attest.service/d' "\$DROPIN"
  grep -q '^After=attest.service' "\$DROPIN" || echo 'After=attest.service' > "\$DROPIN"
fi

systemctl daemon-reload

if [ "\$RESTART_ATTEST" = "true" ]; then
  systemctl reset-failed attest.service || true
  systemctl restart attest.service || true
fi

# Basic endpoint test
echo "MARKER-START"
echo "== endpoints =="
curl -fsS "http://127.0.0.1:$PORT/challenge" || true
curl -fsS -X POST "http://127.0.0.1:$PORT/verify" -d '{}' || true
echo "== service =="
systemctl show attest.service -p Result -p ActiveState
echo "== status.json =="
[ -f /var/lib/attest/status.json ] && sed -n '1,200p' /var/lib/attest/status.json || echo "(missing)"
echo "== verdict.jwt =="
[ -f /var/lib/attest/verdict.jwt ] && head -n 2 /var/lib/attest/verdict.jwt || echo "(missing)"
echo "MARKER-END"
"@

$remote = $remote `
  .Replace('__PORT__', $Port.ToString()) `
  .Replace('__HASH_ALG__', $HashAlg) `
  .Replace('__PCRS__', $Pcrs) `
  .Replace('__FORCE_EPHEMERAL__', ($(if ($ForceEphemeralAK) {'true'} else {'false'}))) `
  .Replace('__RESTART_ATTEST__', ($(if ($NoRestartAttest) {'false'} else {'true'})))

$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
[IO.File]::WriteAllText($tmp, ($remote -replace "`r`n","`n"), [Text.UTF8Encoding]::UTF8)

try {
  Write-Host "Invoking RunCommand..."
  $resp = az vmss run-command invoke -g $nodeInfo.NodeResourceGroup -n $nodeInfo.Vmss --instance-id $nodeInfo.InstanceId --command-id RunShellScript --scripts "@$tmp"
  $resp
} finally {
  Remove-Item -Force $tmp
}
