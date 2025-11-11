<#
  push-attest.ps1
  Push attestation artifacts to a single AKS VMSS instance, install deps, enable the gate, and restart kubelet.

  Highlights:
    - Resolves nodeResourceGroup, parses providerID to VMSS + Instance
    - Base64 transports local artifacts safely via RunCommand
    - Optional fallback attestation script if local script is missing (unless -RequireLocalScript)
    - Normalizes endings, sets permissions, installs tpm2-tools jq curl
    - Hardens the unit if needed (Type=oneshot, RemainAfterExit=yes, TimeoutStartSec=300)
#>

param(
  [Parameter(Mandatory = $true)] [string] $AksResourceGroup,
  [Parameter(Mandatory = $true)] [string] $ClusterName,
  [Parameter(Mandatory = $true)] [string] $NodeName,

  # Defaults relative to this script file
  [string] $AttestLocal = "$PSScriptRoot/attest.sh",
  [string] $UnitLocal   = "$PSScriptRoot/attest.service",
  [string] $DropInLocal = "$PSScriptRoot/kubelet.service.d/10-attestation.conf",

  [switch] $RequireLocalScript,
  [switch] $VerboseRemote
)

$ErrorActionPreference = "Stop"

# Fallback attestation script (very small PASS/AUTO behavior)
$FallbackAttest = @'
#!/bin/bash
set -euo pipefail
STATUS_DIR=/var/lib/attest
mkdir -p "$STATUS_DIR"

MODE="PASS"
[ -f /etc/default/attest ] && source /etc/default/attest || true

secure_boot="unknown"
if command -v mokutil >/dev/null 2>&1; then
  mokutil --sb-state 2>/dev/null | grep -qi enabled && secure_boot="enabled" || secure_boot="disabled"
elif command -v bootctl >/dev/null 2>&1; then
  bootctl status 2>/dev/null | grep -qi 'Secure Boot: enabled' && secure_boot="enabled" || secure_boot="disabled"
fi

tpm_state="absent"
[ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ] && tpm_state="present"

if [ "$MODE" = "AUTO" ]; then
  if [ "$tpm_state" = "present" ]; then MODE="PASS"; else MODE="FAIL"; fi
fi

rc=0
[ "$MODE" = "FAIL" ] && rc=10

cat > "$STATUS_DIR/status.json" <<EOF
{"timestamp":"$(date -Iseconds)","secure_boot":"$secure_boot","tpm_state":"$tpm_state","verdict":"$MODE","source":"fallback-inline"}
EOF
printf '%s\n' "$MODE" > "$STATUS_DIR/verdict.jwt"
echo "attestation_mode=$MODE"
echo "secure_boot=$secure_boot"
echo "tpm_state=$tpm_state"
echo "exit_code=$rc"
exit $rc
'@

function Read-LFOrFallback {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [string] $Fallback = "",
    [switch] $Mandatory,
    [switch] $IsScript
  )
  if (Test-Path -LiteralPath $Path) {
    (Get-Content -Raw -LiteralPath $Path) -replace "`r`n","`n" -replace "`r","`n"
  } else {
    if ($Mandatory) { throw "Missing mandatory local file: $Path" }
    if ($IsScript) {
      Write-Warning "Local attestation script not found, will use fallback."
      return $Fallback
    }
    throw "Fallback given for a non-script file: $Path"
  }
}

Write-Host "Resolving nodeResourceGroup..."
$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
if (-not $NodeRG) { throw "Could not resolve nodeResourceGroup for '$ClusterName' in '$AksResourceGroup'" }

Write-Host "Fetching providerID for $NodeName..."
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
if (-not $ProvId) { throw "providerID missing for node $NodeName" }

$Match = [regex]::Match($ProvId, 'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)', 'IgnoreCase')
if (-not $Match.Success) { throw "Unable to parse VMSS and Instance ID from providerID: $ProvId" }
$VMSS = $Match.Groups[1].Value
$IID  = $Match.Groups[2].Value
Write-Host "Target => NodeRG=$NodeRG VMSS=$VMSS IID=$IID"

# Load artifacts
$AttestRaw = Read-LFOrFallback -Path $AttestLocal -Fallback $FallbackAttest -IsScript -Mandatory:$RequireLocalScript
$UnitRaw   = Read-LFOrFallback -Path $UnitLocal   -Mandatory
$DropRaw   = Read-LFOrFallback -Path $DropInLocal -Mandatory

# Encode artifacts
$AttestB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($AttestRaw))
$UnitB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($UnitRaw))
$DropB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($DropRaw))

# Remote script as single-quoted template with placeholders
$remoteTemplate = @'
#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive

# Install minimal deps
if [ -f /etc/os-release ]; then . /etc/os-release; fi
if printf "%s" "${ID_LIKE:-}\n${ID:-}" | grep -qi mariner; then
  tdnf makecache -q || true
  tdnf install -y tpm2-tools jq curl || true
else
  i=0
  until apt-get update -qq >/dev/null 2>&1 || [ $i -ge 2 ]; do
    i=$((i+1)); sleep 2
  done
  apt-get install -y --no-install-recommends tpm2-tools jq curl || true
fi

# Ensure directories
install -d -m 0755 /opt/azure/containers
install -d -m 0755 /etc/systemd/system/kubelet.service.d
install -d -m 0755 /etc/default
install -d -m 0700 /var/lib/attest

# Lay down artifacts
printf '%s' '__ATTEST_B64__' | base64 -d > /opt/azure/containers/attest.sh
printf '%s' '__UNIT_B64__'   | base64 -d > /etc/systemd/system/attest.service
printf '%s' '__DROP_B64__'   | base64 -d > /etc/systemd/system/kubelet.service.d/10-attestation.conf

# Normalize endings and perms
sed -i 's/\r$//' /opt/azure/containers/attest.sh /etc/systemd/system/attest.service /etc/systemd/system/kubelet.service.d/10-attestation.conf
chmod 0755 /opt/azure/containers/attest.sh
chmod 0644 /etc/systemd/system/attest.service /etc/systemd/system/kubelet.service.d/10-attestation.conf

# Seed defaults if absent
if [ ! -s /etc/default/attest ]; then
  printf 'MODE=AUTO\nCHALLENGE_URL=\n' > /etc/default/attest
fi

# Harden the unit if caller forgot
if ! grep -q '^Type=' /etc/systemd/system/attest.service; then
  sed -i '/^\[Service\]/a Type=oneshot' /etc/systemd/system/attest.service
fi
if ! grep -q '^RemainAfterExit=' /etc/systemd/system/attest.service; then
  sed -i '/^\[Service\]/a RemainAfterExit=yes' /etc/systemd/system/attest.service
fi
if ! grep -q '^TimeoutStartSec=' /etc/systemd/system/attest.service; then
  sed -i '/^\[Service\]/a TimeoutStartSec=300' /etc/systemd/system/attest.service
fi

systemctl daemon-reload
systemctl enable attest.service
systemctl reset-failed attest.service || true
systemctl start attest.service || true

# Apply kubelet drop-in now
systemctl restart kubelet.service || true

# Summaries
echo '== attest.service status =='
systemctl --no-pager -l status attest.service || true
echo '== kubelet Requires/After =='
systemctl show kubelet -p Requires -p After || true
echo '== files =='
ls -l /opt/azure/containers/attest.sh || true
head -n 20 /etc/systemd/system/attest.service || true
echo '== kubelet drop-in =='
sed -n '1,60p' /etc/systemd/system/kubelet.service.d/10-attestation.conf || true
echo '== attestation state =='
ls -l /var/lib/attest 2>/dev/null || true
[ -f /var/lib/attest/status.json ] && sed -n '1,80p' /var/lib/attest/status.json || true
'@

$remoteScript = $remoteTemplate.
  Replace('__ATTEST_B64__', $AttestB64).
  Replace('__UNIT_B64__',   $UnitB64).
  Replace('__DROP_B64__',   $DropB64)

if ($VerboseRemote) {
  Write-Host "---- Remote Script (preview) ----"
  Write-Host $remoteScript
  Write-Host "---- End Remote Script ----"
}

# Write remote script to temp file to avoid quoting limits
$RemotePath = [System.IO.Path]::GetTempFileName().Replace(".tmp",".sh")
Set-Content -Path $RemotePath -Value $remoteScript -Encoding UTF8

Write-Host "Invoking RunCommand with @file (VMSS=$VMSS InstanceID=$IID)..."
$run = az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts "@$RemotePath" | ConvertFrom-Json

Remove-Item -Force $RemotePath -ErrorAction SilentlyContinue

if ($run.value) {
  $entry = $run.value[0]
  Write-Host "Provisioning Status: $($entry.displayStatus)"
  if ($entry.message) {
    Write-Host "---- Remote Output ----"
    Write-Host $entry.message
  } else {
    Write-Warning "No message returned from RunCommand."
  }
} else {
  Write-Warning "Unexpected RunCommand response format."
}

Write-Host "Completed attestation push for node: $NodeName"
