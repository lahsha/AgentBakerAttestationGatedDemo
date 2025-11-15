param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [Parameter()][string]$LocalScriptPath = "$PSScriptRoot/attest.sh"
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $LocalScriptPath)) { throw "Local script not found: $LocalScriptPath" }

$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
$ProvId  = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
$M = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)','IgnoreCase')
if (-not $M.Success) { throw "Cannot parse providerID: $ProvId" }
$VMSS = $M.Groups[1].Value
$IID  = $M.Groups[2].Value

# Normalize LF
$raw = Get-Content $LocalScriptPath -Raw
$lf  = ($raw -replace "`r`n","`n")

$remote = @"
#!/bin/sh
set -e
# (not -u: avoid abrupt exit if a later unbound variable appears in your script)

install -d -m 0755 /opt/azure/containers
cat > /opt/azure/containers/attest.sh <<'EOF'
$lf
EOF
chmod 0755 /opt/azure/containers/attest.sh

echo '--- attest.sh stat ---'
ls -l /opt/azure/containers/attest.sh || echo 'missing'

echo '--- first 40 lines ---'
head -n 40 /opt/azure/containers/attest.sh || true

echo '--- bash syntax check ---'
if command -v bash >/dev/null 2>&1; then
  if ! bash -n /opt/azure/containers/attest.sh 2>&1; then
    echo 'SYNTAX_ERROR' >&2
    exit 1
  fi
else
  echo 'bash not found; skipping syntax check'
fi

echo '--- sha256 ---'
(sha256sum /opt/azure/containers/attest.sh 2>/dev/null) || \
 (busybox sha256sum /opt/azure/containers/attest.sh 2>/dev/null) || \
 echo 'sha256 unavailable'

echo '--- prereq commands ---'
missing=0
for c in jq curl tpm2_quote tpm2_createek tpm2_createak tpm2_getcap; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "FOUND: $c"
  else
    echo "MISSING: $c"
    missing=1
  fi
done

if [ \$missing -ne 0 ]; then
  echo 'One or more prerequisites missing' >&2
  # non-fatal for now; you can choose exit 2 here
fi

echo 'DEPLOY_COMPLETE'
"@

$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
($remote -replace "`r`n","`n") | Set-Content -Encoding UTF8 $tmp

az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID --command-id RunShellScript --scripts "@$tmp"
Remove-Item $tmp -Force
