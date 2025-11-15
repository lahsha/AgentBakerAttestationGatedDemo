$NodeRG = az aks show -g csiattestationtest_group -n TVMAKSCluster --query nodeResourceGroup -o tsv
$VMSS   = "aks-nodepool1-15023252-vmss"
$IID    = "0"

$check = @'
#!/bin/sh
set -eu
echo "== attest.service summary =="
systemctl show attest.service -p ActiveState -p Result -p FragmentPath
echo "== attest.service unit head =="
sed -n '1,40p' /etc/systemd/system/attest.service || true
echo "== kubelet Requires/After =="
systemctl show kubelet -p Requires -p After
echo "== recent attest journal =="
journalctl -u attest -b --no-pager -n 30 || true
'@

az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts $check
