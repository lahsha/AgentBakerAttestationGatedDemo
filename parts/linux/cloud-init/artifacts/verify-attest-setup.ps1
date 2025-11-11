# 1) Set your AKS identifiers
$AKS_RG  = "csiattestationtest_group"
$CLUSTER = "TVMAKSCluster"
$NODE    = "aks-nodepool1-15023252-vmss000000"

# Resolve node RG / VMSS / Instance ID dynamically (reuse logic from push script)
$NodeRG = az aks show -g $AKS_RG -n $CLUSTER --query nodeResourceGroup -o tsv
if (-not $NodeRG) { throw "Could not resolve nodeResourceGroup" }

$ProvId = kubectl get node $NODE -o jsonpath='{.spec.providerID}'
if (-not $ProvId) { throw "No providerID for node $NODE" }

$Match = [regex]::Match($ProvId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
if (-not $Match.Success) { throw "Could not parse VMSS + instance from providerID: $ProvId" }

$VMSS = $Match.Groups[1].Value
$IID  = $Match.Groups[2].Value

Write-Host "Verifying node => RG: $NodeRG  VMSS: $VMSS  Instance: $IID"

# Remote verification script (single-quoted here-string to avoid PowerShell interpolation)
$verify = @'
#!/bin/sh
set -eu
# optional verbosity: set -x if VERBOSE=1
[ "${VERBOSE:-0}" = "1" ] && set -x

echo '== Files & perms =='
ls -l /opt/azure/containers/attest.sh 2>/dev/null || echo 'MISSING: /opt/azure/containers/attest.sh'
[ -f /etc/systemd/system/attest.service ] && head -n 20 /etc/systemd/system/attest.service || echo 'MISSING: attest.service'
[ -f /etc/systemd/system/kubelet.service.d/10-attestation.conf ] && sed -n '1,120p' /etc/systemd/system/kubelet.service.d/10-attestation.conf || echo 'MISSING: drop-in'

echo '== Normalize line endings (guard) =='
if [ -f /opt/azure/containers/attest.sh ]; then
  sed -i 's/\r$//' /opt/azure/containers/attest.sh || true
  chmod 0755 /opt/azure/containers/attest.sh || true
fi

echo '== Packages & devices =='
command -v tpm2_quote >/dev/null 2>&1 && echo 'tpm2-tools present' || echo 'WARN: tpm2_tools missing (tpm2_quote not in PATH)'
ls -l /dev/tpm* 2>/dev/null || echo 'No /dev/tpm* nodes'

echo '== Systemd wiring =='
systemctl daemon-reload || true
systemctl is-enabled attest.service 2>/dev/null || echo 'attest.service not enabled (yet)'
echo '--- kubelet (first 80 lines of merged unit) ---'
systemctl cat kubelet 2>/dev/null | sed -n '1,80p' || echo 'kubelet unit not found'
echo '--- kubelet dependency edges ---'
systemctl show kubelet -p Requires -p After 2>/dev/null || true

echo '== Prepare PASS config =='
mkdir -p /etc
[ -f /etc/default/attest ] || touch /etc/default/attest
if grep -q '^CHALLENGE_URL=' /etc/default/attest; then
  sed -i 's|^CHALLENGE_URL=.*|CHALLENGE_URL=|' /etc/default/attest
else
  echo 'CHALLENGE_URL=' >> /etc/default/attest
fi
grep -q '^MODE=' /etc/default/attest || echo 'MODE=PASS' >> /etc/default/attest

echo '== Start attest.service =='
if systemctl start attest.service 2>/dev/null; then
  :
else
  echo 'ERROR: systemctl start attest.service failed'
fi

# Capture status without failing script prematurely
ACTIVE_STATE=$(systemctl show -p ActiveState --value attest.service 2>/dev/null || echo unknown)
RESULT_FIELD=$(systemctl show -p Result --value attest.service 2>/dev/null || echo unknown)

echo "attest.service ActiveState=$ACTIVE_STATE Result=$RESULT_FIELD"

echo '== attest recent logs =='
journalctl -u attest -b --no-pager 2>/dev/null | tail -n 80 || echo 'No logs'

echo '== Quick gating classification =='
if systemctl show kubelet -p Requires -p After 2>/dev/null | grep -q 'attest.service'; then
  echo 'GATE: dependency (Requires/After) mode'
elif grep -q 'ExecStartPre=.*attest.sh' /etc/systemd/system/kubelet.service.d/10-attestation.conf 2>/dev/null; then
  echo 'GATE: ExecStartPre mode'
else
  echo 'GATE: NO gating linkage detected'
fi

# Decide pass/fail (optional): treat non-success as soft warning
if [ "$RESULT_FIELD" = "success" ] || [ "$ACTIVE_STATE" = "active" ]; then
  echo 'VERIFICATION: PASS'
else
  echo 'VERIFICATION: WARNING (attest.service not successful)'
fi

echo '== Done =='
'@

# Execute verification
az vmss run-command invoke -g $NodeRG -n $VMSS --instance-id $IID `
  --command-id RunShellScript --scripts $verify
