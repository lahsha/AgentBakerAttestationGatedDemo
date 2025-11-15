param(
  [Parameter(Mandatory=$true)] [string]$AksResourceGroup,
  [Parameter(Mandatory=$true)] [string]$ClusterName,
  [Parameter(Mandatory=$true)] [string]$NodeName
)

$ErrorActionPreference = "Stop"

# Resolve node RG
$NodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
if (-not $NodeRG) { throw "Could not resolve nodeResourceGroup for $ClusterName in $AksResourceGroup" }

# Parse providerID → VMSS and instance ID
$ProvId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}'
if (-not $ProvId) { throw "providerID not found for node $NodeName" }
$Match = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
if (-not $Match.Success) { throw "Could not parse VMSS and Instance from providerID: $ProvId" }
$VMSS = $Match.Groups[1].Value
$IID  = $Match.Groups[2].Value

# Correct unit text
$UnitText = @"
[Unit]
Description=Node Attestation Gate
DefaultDependencies=no
After=network-online.target
Wants=network-online.target
Before=kubelet.service
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=oneshot
ExecStart=/opt/azure/containers/attest.sh
RemainAfterExit=yes
StandardOutput=journal+console
StandardError=journal+console
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=10
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
"@
$UnitB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($UnitText))

# Remote script
$Remote = @'
#!/bin/sh
set -eu
printf "%s" "__UNIT_B64__" | base64 -d > /etc/systemd/system/attest.service
sed -i "s/\r$//" /etc/systemd/system/attest.service
chmod 0644 /etc/systemd/system/attest.service

systemctl daemon-reload
systemctl enable attest.service >/dev/null 2>&1 || true
systemctl restart attest.service || true
systemctl restart kubelet.service || true

echo "== attest.service =="
systemctl --no-pager -l status attest.service || true
echo "== kubelet Requires/After =="
systemctl show kubelet -p Requires -p After || true
'@
$Remote = $Remote.Replace('__UNIT_B64__', $UnitB64)

# Invoke on the node
az vmss run-command invoke `
  -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts $Remote
