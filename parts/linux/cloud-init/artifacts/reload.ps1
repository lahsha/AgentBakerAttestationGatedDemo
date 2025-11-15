# Resolve targets
$NodeRG = az aks show -g csiattestationtest_group -n TVMAKSCluster --query nodeResourceGroup -o tsv
$VMSS   = "aks-nodepool1-15023252-vmss"
$IID    = "0"

# Write the check script to a temp file, normalize to LF
$checkSh = @'
#!/bin/sh
set -eu
echo "MARKER-START"
echo "== attest.service summary =="
systemctl show attest.service -p ActiveState -p Result -p FragmentPath
echo "== attest.service head =="
sed -n '1,40p' /etc/systemd/system/attest.service || true
echo "== kubelet Requires/After =="
systemctl show kubelet -p Requires -p After
echo "== recent attest journal =="
journalctl -u attest -b --no-pager -n 30 || true
echo "MARKER-END"
'@
$tmp = [System.IO.Path]::GetTempFileName().Replace(".tmp",".sh")
$checkSh = $checkSh -replace "`r`n","`n" -replace "`r","`n"
Set-Content -Path $tmp -Value $checkSh -Encoding ASCII

# Invoke via @file so AZ CLI uploads the script as a file
az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts "@$tmp"

Remove-Item $tmp -Force
