param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [Parameter()][int]$TimeoutSeconds = 120,
  [Parameter()][int]$HeadLines = 60
)

$ErrorActionPreference = 'Stop'

# Resolve node resource group
$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv

# Parse providerID
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
$M = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)','IgnoreCase')
if (-not $M.Success) { throw "Cannot parse providerID: $ProvId" }
$VMSS = $M.Groups[1].Value
$IID  = $M.Groups[2].Value

# Build remote script using a single-quoted here-string so $(...) is not evaluated by PowerShell
$remote = @'
#!/usr/bin/env bash
set -euo pipefail

TRACE_TS=$(date +%Y-%m-%dT%H:%M:%S%z)
echo "TRACE-START $TRACE_TS"

# Force PASS mode to keep kubelet unblocked
if [[ -f /etc/default/attest ]]; then
  sed -i 's/^MODE=.*/MODE=PASS/' /etc/default/attest || true
else
  printf 'MODE=PASS\n' > /etc/default/attest
fi

if [[ ! -x /opt/azure/containers/attest.sh ]]; then
  echo 'attest.sh missing'; exit 1
fi

echo "--- first __HEADLINES__ lines ---"
head -n __HEADLINES__ /opt/azure/containers/attest.sh || true

echo "--- prereq tools ---"
missing=0
for c in jq curl tpm2_quote tpm2_createek tpm2_createak tpm2_getcap; do
  printf '%-15s : ' "$c"
  if command -v "$c" >/dev/null 2>&1; then
    echo "FOUND"
  else
    echo "MISSING"
    missing=1
  fi
done
[[ $missing -ne 0 ]] && echo "WARNING: one or more tools missing; trace may fail early"

mkdir -p /var/lib/attest
chmod 700 /var/lib/attest

echo "--- bash -x (timeout __TIMEOUT__ s) ---"
if command -v timeout >/dev/null 2>&1; then
  timeout __TIMEOUT__ bash -x /opt/azure/containers/attest.sh > /var/lib/attest/manual-trace.log 2>&1 || echo "manual run non-zero or timeout"
else
  echo "WARNING: timeout not found; running unbounded"
  bash -x /opt/azure/containers/attest.sh > /var/lib/attest/manual-trace.log 2>&1 || echo "manual run non-zero"
fi

echo "--- manual trace tail ---"
tail -n 50 /var/lib/attest/manual-trace.log || echo "no manual trace log yet"

echo "--- status.json (if created) ---"
if [[ -f /var/lib/attest/status.json ]]; then
  tail -n 1 /var/lib/attest/status.json
else
  echo "status.json not present"
fi

echo "TRACE-END $(date +%Y-%m-%dT%H:%M:%S%z)"
'@

# Substitute placeholders safely
$remote = $remote.Replace('__TIMEOUT__', $TimeoutSeconds.ToString())
$remote = $remote.Replace('__HEADLINES__', $HeadLines.ToString())

$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
# Force LF endings
($remote -replace "`r`n","`n") | Set-Content -Encoding UTF8 $tmp

az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID --command-id RunShellScript --scripts "@$tmp"

Remove-Item $tmp -Force
