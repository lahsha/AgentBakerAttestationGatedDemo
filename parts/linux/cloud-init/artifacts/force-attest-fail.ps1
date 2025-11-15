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
printf "MODE=FAIL\n" > /etc/default/attest
systemctl restart attest.service || true
systemctl restart kubelet.service || true
echo "attest:" $(systemctl show -p ActiveState --value attest.service) "/" $(systemctl show -p Result --value attest.service)
echo "kubelet active?"; systemctl is-active kubelet || echo "blocked as expected"
'@
$tmp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
$sh = $sh -replace "`r`n","`n" -replace "`r","`n"
Set-Content -Path $tmp -Value $sh -Encoding UTF8

az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID --command-id RunShellScript --scripts "@$tmp"
Remove-Item $tmp -Force
