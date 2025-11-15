[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)] [string]$AksResourceGroup,
  [Parameter(Mandatory=$true)] [string]$ClusterName,
  [Parameter(Mandatory=$true)] [string]$NodeName
)

$ErrorActionPreference = "Stop"

$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
if (-not $NodeRG) { throw "Could not resolve nodeResourceGroup" }
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
$M = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
if (-not $M.Success) { throw "Could not parse providerID => VMSS/IID" }
$VMSS = $M.Groups[1].Value
$IID  = $M.Groups[2].Value

$remoteStop = @"
#!/bin/sh
set -eu
if [ -f /var/run/attest-mock.pid ]; then
  kill "\$(cat /var/run/attest-mock.pid)" 2>/dev/null || true
  rm -f /var/run/attest-mock.pid
fi
pkill -f /opt/attest-mock/server.py 2>/dev/null || true
echo "stopped"
"@

$Tmp = [IO.Path]::GetTempFileName().Replace(".tmp",".sh")
[IO.File]::WriteAllText($Tmp, ($remoteStop -replace "`r`n","`n"), [Text.UTF8Encoding]::UTF8)
$resp = az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID --command-id RunShellScript --scripts "@$Tmp"
Remove-Item -Force $Tmp

$resp
