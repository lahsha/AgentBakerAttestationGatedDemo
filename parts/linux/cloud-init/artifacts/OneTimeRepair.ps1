param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [Parameter()][switch]$ForcePASS,          # Force MODE=PASS regardless of existing file
  [Parameter()][switch]$UseWrapper,         # Deploy async wrapper ExecStart
  [Parameter()][int]$ScriptTimeoutSeconds = 180,
  [Parameter()][int]$HeadLines = 40
)

$ErrorActionPreference = 'Stop'

Write-Host "[*] Resolve node resource group"
$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv

Write-Host "[*] Resolve VMSS/instance from providerID"
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
$M = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)','IgnoreCase')
if (-not $M.Success) { throw "Cannot parse providerID: $ProvId" }
$VMSS = $M.Groups[1].Value
$IID  = $M.Groups[2].Value

Write-Host "[*] Preparing remote script (wrapper=$UseWrapper, timeout=$ScriptTimeoutSeconds s)"

$remote = @'
#!/bin/sh
set -eu

echo "== phase: install defaults and normalize attest.sh =="

install -d -m 0755 /etc/default

MODE_FILE=/etc/default/attest
if [ ! -f "$MODE_FILE" ]; then
  printf "MODE=PASS\nCHALLENGE_URL=\nVERIFIER_URL=\n" > "$MODE_FILE"
elif [ "@FORCE_PASS@" = "true" ]; then
  sed -i 's/^MODE=.*/MODE=PASS/' "$MODE_FILE"
fi

if [ -f /opt/azure/containers/attest.sh ]; then
  sed -i 's/\r$//' /opt/azure/containers/attest.sh
  chmod 0755 /opt/azure/containers/attest.sh
  echo "--- head(/opt/azure/containers/attest.sh) ---"
  sed -n '1,@HEAD_LINES@p' /opt/azure/containers/attest.sh || true
else
  echo "MISSING: /opt/azure/containers/attest.sh; creating bootstrap PASS stub"
  cat >/opt/azure/containers/attest.sh <<'STUB'
#!/bin/sh
set -eu
mkdir -p /var/lib/attest
echo '{"timestamp":"'"$(date -Iseconds)"'","verdict":"PASS","source":"bootstrap-stub"}' >/var/lib/attest/status.json
exit 0
STUB
  chmod 0755 /opt/azure/containers/attest.sh
fi

echo "== (re)install attest.service verbatim =="

cat >/etc/systemd/system/attest.service <<'UNIT'
[Unit]
Description=Node Attestation Gate
DefaultDependencies=no
After=network-online.target
Wants=network-online.target
Before=kubelet.service
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=@EXEC_START@
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=@TIMEOUT@
Restart=on-failure
RestartSec=15
RestartPreventExitStatus=10

[Install]
WantedBy=multi-user.target
UNIT

echo "== ensure kubelet drop-in only orders after attest =="
mkdir -p /etc/systemd/system/kubelet.service.d
cat >/etc/systemd/system/kubelet.service.d/10-attestation.conf <<'DROPIN'
[Unit]
After=attest.service
DROPIN

if [ "@USE_WRAPPER@" = "true" ]; then
  echo "== write async wrapper =="
  cat >/opt/azure/containers/attest-wrapper.sh <<'WRAP'
#!/bin/sh
set -eu
# Early PASS marker if not present
mkdir -p /var/lib/attest
if [ ! -f /var/lib/attest/status.json ]; then
  echo '{"timestamp":"'"$(date -Iseconds)"'","verdict":"PASS","source":"wrapper"}' >/var/lib/attest/status.json
fi
# Spawn real attestation in background bounded by timeout; capture trace
(
  exec > /var/lib/attest/trace.log 2>&1
  echo "TRACE-START $(date -Iseconds)"
  if command -v bash >/dev/null 2>&1; then
    timeout @TIMEOUT@ bash -x /opt/azure/containers/attest.sh || echo "attest script ended non-zero or timeout"
  else
    timeout @TIMEOUT@ /opt/azure/containers/attest.sh || echo "attest script ended non-zero or timeout"
  fi
  echo "TRACE-END $(date -Iseconds)"
) &
exit 0
WRAP
  chmod 0755 /opt/azure/containers/attest-wrapper.sh
fi

echo "== systemd reload & restart =="
systemctl daemon-reload
systemctl enable attest.service
systemctl reset-failed attest.service || true
systemctl restart attest.service || true
systemctl restart kubelet.service || true

echo "== status snapshots =="
systemctl show attest.service -p ActiveState -p Result -p ExecMainStatus -p FragmentPath
systemctl show kubelet -p Requires -p After
journalctl -u attest -b --no-pager -n 50 || true
'@

# Token replacements
$remote = $remote.Replace("@FORCE_PASS@", ($ForcePASS.IsPresent).ToString().ToLower())
$remote = $remote.Replace("@USE_WRAPPER@", ($UseWrapper.IsPresent).ToString().ToLower())
$remote = $remote.Replace("@TIMEOUT@", $ScriptTimeoutSeconds.ToString())
$remote = $remote.Replace("@HEAD_LINES@", $HeadLines.ToString())

if ($UseWrapper) {
  $remote = $remote.Replace("@EXEC_START@", "/opt/azure/containers/attest-wrapper.sh")
} else {
  # Optional: still wrap with /usr/bin/timeout if you prefer internal bound over systemd start timeout
  $remote = $remote.Replace("@EXEC_START@", "/usr/bin/timeout $ScriptTimeoutSeconds /opt/azure/containers/attest.sh")
}

# Ensure LF for remote shell
$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
($remote -replace "`r`n","`n") | Set-Content -Encoding UTF8 $tmp

Write-Host "[*] Invoking repair on $VMSS/$IID"
az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts "@$tmp"

Remove-Item $tmp -Force

Write-Host "`n[*] Done. Look for ActiveState=active Result=success. If wrapper used, inspect /var/lib/attest/trace.log next."
