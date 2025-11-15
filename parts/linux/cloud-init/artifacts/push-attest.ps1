<#
  push-attest.ps1
  Push attestation artifacts to a single AKS VMSS instance, install deps, enable the gate, and restart kubelet.

  Artifacts used from your repo (relative to this script):
    - ./attest.sh
    - ./attest.service
    - ./kubelet.service.d/10-attestation.conf
#>

[CmdletBinding()]
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

function Read-LFOrFallback {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [string] $Fallback = "",
    [switch] $Mandatory,
    [switch] $IsScript
  )
  if (Test-Path -LiteralPath $Path) {
    # Normalize CRLF to LF for remote
    (Get-Content -Raw -LiteralPath $Path) -replace "`r`n","`n" -replace "`r","`n"
  } else {
    if ($Mandatory) { throw "Missing mandatory local file: $Path" }
    if ($IsScript) {
      if ($Fallback) { return $Fallback }
      throw "Local script missing and no fallback provided: $Path"
    }
    throw "Missing file: $Path"
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

# Load artifacts strictly from repo
$AttestRaw = Read-LFOrFallback -Path $AttestLocal -Mandatory:$RequireLocalScript -IsScript
$UnitRaw   = Read-LFOrFallback -Path $UnitLocal   -Mandatory
$DropRaw   = Read-LFOrFallback -Path $DropInLocal -Mandatory

# Encode artifacts for transport
$AttestB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($AttestRaw))
$UnitB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($UnitRaw))
$DropB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($DropRaw))

# Remote script with small guardrails
$remoteTemplate = @'
#!/usr/bin/env bash
set -euo pipefail
export LANG=C
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive

# 0) OS prereqs
if [ -f /etc/os-release ]; then . /etc/os-release; fi
if printf "%s\n%s\n" "${ID_LIKE:-}" "${ID:-}" | grep -qi mariner; then
  tdnf makecache -q || true
  tdnf install -y tpm2-tools jq curl util-linux || true
else
  i=0
  until apt-get update -qq >/dev/null 2>&1 || [ $i -ge 2 ]; do i=$((i+1)); sleep 2; done
  apt-get install -y --no-install-recommends tpm2-tools jq curl util-linux || true
fi

# 1) Directories
install -d -m 0755 /opt/azure/containers
install -d -m 0755 /etc/systemd/system/kubelet.service.d
install -d -m 0755 /etc/default
install -d -m 0700 /var/lib/attest

# 2) Write artifacts
printf '%s' '__ATTEST_B64__' | base64 -d > /opt/azure/containers/attest.sh
printf '%s' '__UNIT_B64__'   | base64 -d > /etc/systemd/system/attest.service
printf '%s' '__DROP_B64__'   | base64 -d > /etc/systemd/system/kubelet.service.d/10-attestation.conf

# Normalize endings
sed -i 's/\r$//' /opt/azure/containers/attest.sh /etc/systemd/system/attest.service /etc/systemd/system/kubelet.service.d/10-attestation.conf

chmod 0755 /opt/azure/containers/attest.sh
chmod 0644 /etc/systemd/system/attest.service /etc/systemd/system/kubelet.service.d/10-attestation.conf

# 3) Light guardrails
# If your unit accidentally has StartLimit* under [Service], move them to [Unit] server-side
if grep -q '^StartLimitIntervalSec=' /etc/systemd/system/attest.service; then
  sed -i '/^\[Service\]/,/^\[/{/^StartLimitIntervalSec=/d;/^StartLimitBurst=/d}' /etc/systemd/system/attest.service
fi
# Ensure kubelet drop-in has a [Unit] header and contains only After=attest.service
if ! head -n1 /etc/systemd/system/kubelet.service.d/10-attestation.conf | grep -q '^\[Unit\]'; then
  sed -i '1s;^;[Unit]\n;' /etc/systemd/system/kubelet.service.d/10-attestation.conf
fi
sed -i '/^Requires=attest\.service/d' /etc/systemd/system/kubelet.service.d/10-attestation.conf
grep -q '^After=attest\.service' /etc/systemd/system/kubelet.service.d/10-attestation.conf || echo 'After=attest.service' >> /etc/systemd/system/kubelet.service.d/10-attestation.conf

# 4) Defaults file presence
[ -f /etc/default/attest ] || printf 'MODE=AUTO\n' > /etc/default/attest

# 5) Reload and restart
systemctl daemon-reload
systemctl enable attest.service >/dev/null 2>&1 || true
systemctl reset-failed attest.service || true
systemctl restart attest.service || true
systemctl restart kubelet.service || true

# 6) Summary
echo '== attest.service status =='
systemctl show attest.service -p ActiveState -p Result -p FragmentPath
echo '== kubelet Requires/After =='
systemctl show kubelet -p Requires -p After
echo '== attest.service head =='
sed -n '1,40p' /etc/systemd/system/attest.service || true
echo '== status.json (first 200 chars) =='
[ -f /var/lib/attest/status.json ] && sed -n '1,200p' /var/lib/attest/status.json || echo '(missing)'
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

# Send as @file to avoid quoting issues
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
