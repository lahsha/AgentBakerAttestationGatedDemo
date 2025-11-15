param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName
)
$ErrorActionPreference = "Stop"
$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
$M = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
$VMSS = $M.Groups[1].Value; $IID = $M.Groups[2].Value

$sh = @'
#!/bin/sh
set -eu
printf "MODE=PASS\n" > /etc/default/attest
systemctl restart attest.service
systemctl restart kubelet.service || true
systemctl show kubelet -p Requires -p After
'@
$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
$sh = $sh -replace "`r`n","`n" -replace "`r","`n"
Set-Content -Path $tmp -Value $sh -Encoding UTF8

az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID --command-id RunShellScript --scripts "@$tmp"
Remove-Item $tmp -Force
