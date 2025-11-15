[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [ValidateSet('AUTO','VERIFY','STUB','MOCK')][string]$Mode='AUTO',
  [string]$VerifierUrl='',
  [string]$ChallengeUrl='',
  [switch]$SkipPrereqs,
  [int]$TimeoutStartSec = 120,
  [int]$RestartSec = 20,
  [string]$ScriptVersion='2025.11.15',
  [string]$ArtifactsDir = "$(Split-Path -Parent $PSCommandPath)"
)

$ErrorActionPreference = 'Stop'

function Resolve-NodeIdentity {
  Write-Host "Resolving nodeResourceGroup..."
  $nodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
  if (-not $nodeRG) { throw "Could not resolve nodeResourceGroup" }

  Write-Host "Fetching providerID for $NodeName..."
  $provId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}' 2>$null
  if (-not $provId) { throw "Could not get providerID for $NodeName" }

  $m = [Regex]::Match($provId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
  if (-not $m.Success) { throw "Could not parse providerID '$provId'" }

  @{
    NodeResourceGroup = $nodeRG
    Vmss       = $m.Groups[1].Value
    InstanceId = $m.Groups[2].Value
  }
}

function Load-FileOrDie([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Missing required $Name file at path: $Path"
  }
  $content = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::UTF8)
  if (-not $content.Trim()) { throw "$Name file empty: $Path" }
  return $content
}

function Patch-ServiceUnit([string]$Content) {
  # Ensure [Service] section exists
  if ($Content -notmatch '(?m)^\[Service\]') {
    $Content = $Content.TrimEnd() + "`n[Service]`n"
  }

  # TimeoutStartSec
  if ($Content -match '(?m)^TimeoutStartSec=\d+') {
    $Content = [Regex]::Replace($Content,'(?m)^TimeoutStartSec=\d+',"TimeoutStartSec=$TimeoutStartSec")
  } else {
    $Content = $Content -replace '(?m)^\[Service\]',"[Service]`nTimeoutStartSec=$TimeoutStartSec"
  }

  # RestartSec
  if ($Content -match '(?m)^RestartSec=\d+') {
    $Content = [Regex]::Replace($Content,'(?m)^RestartSec=\d+',"RestartSec=$RestartSec")
  } else {
    $Content = $Content -replace '(?m)^\[Service\]',"[Service]`nRestartSec=$RestartSec"
  }

  # Remove any old ExecStartPost for tainting if present
  $Content = [Regex]::Replace($Content,'(?m)^ExecStartPost=/usr/local/bin/attest-gating\.sh\s*','')

  return $Content
}

$info = Resolve-NodeIdentity
Write-Host "Target => NodeRG=$($info.NodeResourceGroup) VMSS=$($info.Vmss) IID=$($info.InstanceId)"

# Local artifact paths
$attestScriptPath  = Join-Path $ArtifactsDir 'attest.sh'
$servicePath       = Join-Path $ArtifactsDir 'attest.service'
$dropinPath        = Join-Path $ArtifactsDir 'kubelet.service.d/10-attestation.conf'   # optional override

# Load and prepare contents
$AttestScriptRaw = Load-FileOrDie $attestScriptPath 'attest.sh'
$ServiceRaw      = Load-FileOrDie $servicePath 'attest.service'

# Stamp script version placeholder if present
$AttestScript = $AttestScriptRaw -replace '__SCRIPT_VERSION__', $ScriptVersion

# Patch service unit
$ServiceUnit = Patch-ServiceUnit $ServiceRaw

# Load drop-in or use default gating drop-in
if (Test-Path $dropinPath) {
  $DropinUnit = Load-FileOrDie $dropinPath 'kubelet attestation drop-in'
} else {
  $DropinUnit = @"
[Unit]
Requires=attest.service
After=attest.service
"@
}

# Ensure drop-in has Requires and After
if ($DropinUnit -notmatch '(?m)^Requires=attest\.service\s*$') {
  if ($DropinUnit -match '(?m)^\[Unit\]') {
    $DropinUnit = $DropinUnit -replace '(?m)^\[Unit\]',"[Unit]`nRequires=attest.service"
  } else {
    $DropinUnit = "[Unit]`nRequires=attest.service`n" + $DropinUnit
  }
}
if ($DropinUnit -notmatch '(?m)^After=attest\.service\s*$') {
  if ($DropinUnit -match '(?m)^\[Unit\]') {
    $DropinUnit = $DropinUnit -replace '(?m)^\[Unit\]',"[Unit]`nAfter=attest.service"
  } else {
    $DropinUnit = "[Unit]`nAfter=attest.service`n" + $DropinUnit
  }
}

# Remote script template, will fill placeholders with raw contents
$Remote = @'
#!/usr/bin/env bash
set -euo pipefail

MODE="__MODE__"
VERIFIER_URL="__VERIFIER_URL__"
CHALLENGE_URL="__CHALLENGE_URL__"
SKIP_PREREQS="__SKIP_PREREQS__"

log(){ echo "[deploy-attest] $(date --iso-8601=seconds) $*" >&2; }

if [[ "$SKIP_PREREQS" != "true" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  # flock binary is provided by util-linux on Ubuntu
  apt-get install -y --no-install-recommends jq curl tpm2-tools util-linux || true
fi

mkdir -p /opt/azure/containers
mkdir -p /etc/systemd/system/kubelet.service.d

# Install attest.sh
cat <<'EOF_ATTEST' >/opt/azure/containers/attest.sh
__ATTEST_SH__
EOF_ATTEST
chmod +x /opt/azure/containers/attest.sh

# Install attest.service
cat <<'EOF_SERVICE' >/etc/systemd/system/attest.service
__SERVICE_UNIT__
EOF_SERVICE

# Install kubelet drop-in
cat <<'EOF_DROPIN' >/etc/systemd/system/kubelet.service.d/10-attestation.conf
__DROPIN_UNIT__
EOF_DROPIN

systemctl daemon-reload
systemctl enable attest.service || true

if ! systemctl restart attest.service; then
  log "attest.service restart failed"
fi

echo "== attest.service status =="
systemctl show attest.service -p Result -p ActiveState

DROPIN=/etc/systemd/system/kubelet.service.d/10-attestation.conf
echo "== kubelet drop-in =="
if [ -f "$DROPIN" ]; then
  sed -n '1,25p' "$DROPIN"
else
  echo "(missing)"
fi

echo "== status.json (first 160 chars) =="
if [ -f /var/lib/attest/status.json ]; then
  sed -n '1,160p' /var/lib/attest/status.json
else
  echo "(missing)"
fi
'@

# Fill in placeholders
$Remote = $Remote.Replace('__MODE__', $Mode)
$Remote = $Remote.Replace('__VERIFIER_URL__', $VerifierUrl)
$Remote = $Remote.Replace('__CHALLENGE_URL__', $ChallengeUrl)
$Remote = $Remote.Replace('__SKIP_PREREQS__', ($SkipPrereqs ? 'true' : 'false'))

# Insert raw file contents into heredocs
$Remote = $Remote.Replace('__ATTEST_SH__', $AttestScript)
$Remote = $Remote.Replace('__SERVICE_UNIT__', $ServiceUnit)
$Remote = $Remote.Replace('__DROPIN_UNIT__', $DropinUnit)

# Write remote script to a temp file and invoke RunCommand
$Temp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
[IO.File]::WriteAllText($Temp, ($Remote -replace "`r`n","`n"), [Text.UTF8Encoding]::UTF8)

try {
  Write-Host "Invoking RunCommand (VMSS=$($info.Vmss) IID=$($info.InstanceId))..."
  $resp = az vmss run-command invoke -g $info.NodeResourceGroup -n $info.Vmss `
    --instance-id $info.InstanceId --command-id RunShellScript --scripts "@$Temp"
  $resp
} finally {
  Remove-Item -Force $Temp
}

Write-Host "Completed attestation push for node: $NodeName"
