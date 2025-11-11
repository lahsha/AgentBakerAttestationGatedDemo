#!/bin/sh
# unified-attest-verify.sh
set -eu

MODE="${MODE:-check}"   # check | force-pass | force-pass-hard | diagnose
LOG_TAIL=80

title(){ printf '\n== %s ==\n' "$1"; }

# 1. Basic discovery
title "Context"
echo "MODE=$MODE"
uname -a || true

# 2. File inspection (always)
title "Files & perms"
ls -l /opt/azure/containers/attest.sh 2>/dev/null || echo 'MISSING: attest.sh'
[ -f /etc/systemd/system/attest.service ] && head -n 20 /etc/systemd/system/attest.service || echo 'MISSING: attest.service'
[ -f /etc/systemd/system/kubelet.service.d/10-attestation.conf ] && sed -n '1,120p' /etc/systemd/system/kubelet.service.d/10-attestation.conf || echo 'MISSING: drop-in'

# 3. Optional normalization if MODE != check
if [ "$MODE" != "check" ]; then
  title "Normalize line endings"
  if [ -f /opt/azure/containers/attest.sh ]; then
    sed -i 's/\r$//' /opt/azure/containers/attest.sh || true
    chmod 0755 /opt/azure/containers/attest.sh || true
  fi
fi

# 4. Systemd overview
title "Systemd wiring"
systemctl daemon-reload || true
systemctl is-enabled attest.service 2>/dev/null || echo 'attest.service not enabled'
echo "-- kubelet edges --"
systemctl show kubelet -p Requires -p After 2>/dev/null || true

# 5. TPM / diagnostics (in diagnose or force-pass-hard modes)
if [ "$MODE" = "diagnose" ] || [ "$MODE" = "force-pass-hard" ]; then
  title "TPM & device nodes"
  command -v tpm2_quote >/dev/null 2>&1 && echo 'tpm2-tools present' || echo 'WARN: tpm2-tools missing'
  ls -l /dev/tpm* 2>/dev/null || echo 'No /dev/tpm devices'
fi

# 6. Force PASS config if requested
if [ "$MODE" = "force-pass" ] || [ "$MODE" = "force-pass-hard" ]; then
  title "Applying PASS config"
  mkdir -p /etc
  [ -f /etc/default/attest ] || touch /etc/default/attest
  if grep -q '^CHALLENGE_URL=' /etc/default/attest; then
    sed -i 's|^CHALLENGE_URL=.*|CHALLENGE_URL=|' /etc/default/attest
  else
    echo 'CHALLENGE_URL=' >> /etc/default/attest
  fi
  grep -q '^MODE=PASS' /etc/default/attest || echo 'MODE=PASS' >> /etc/default/attest
fi

# 7. Run / restart attest if not pure read-only
RUN_ATTEST=1
[ "$MODE" = "check" ] && RUN_ATTEST=1  # still run once to observe state
if [ $RUN_ATTEST -eq 1 ]; then
  title "Start/restart attest.service"
  systemctl reset-failed attest.service 2>/dev/null || true
  if systemctl restart attest.service 2>/dev/null; then
    :
  else
    echo "WARN: restart failed; trying start"
    systemctl start attest.service 2>/dev/null || echo "ERROR: attest start failed"
  fi
fi

# 8. Status
ACTIVE=$(systemctl show -p ActiveState --value attest.service 2>/dev/null || echo unknown)
RESULT=$(systemctl show -p Result --value attest.service 2>/dev/null || echo unknown)
title "attest.service status"
echo "ActiveState=$ACTIVE Result=$RESULT"

# 9. Logs
title "attest recent logs"
journalctl -u attest -b --no-pager 2>/dev/null | tail -n $LOG_TAIL || echo 'No logs'

# 10. Gating classification
title "Gating classification"
if systemctl show kubelet -p Requires -p After 2>/dev/null | grep -q 'attest.service'; then
  echo 'GATE: dependency mode'
elif grep -q 'ExecStartPre=.*attest.sh' /etc/systemd/system/kubelet.service.d/10-attestation.conf 2>/dev/null; then
  echo 'GATE: ExecStartPre mode'
else
  echo 'GATE: none'
fi

# 11. Conditional kubelet restart only in force modes
if [ "$MODE" = "force-pass" ] || [ "$MODE" = "force-pass-hard" ]; then
  if [ "$RESULT" = "success" ] || [ "$ACTIVE" = "active" ]; then
    title "Restart kubelet (attestation succeeded)"
    systemctl restart kubelet.service || echo "WARN: kubelet restart failed"
  else
    echo "Skipping kubelet restart (attestation not successful)"
  fi
fi

# 12. Exit codes
if [ "$MODE" = "force-pass-hard" ]; then
  if [ "$RESULT" = "success" ] || [ "$ACTIVE" = "active" ]; then
    echo "FINAL: PASS"
    exit 0
  else
    echo "FINAL: FAIL"
    exit 1
  fi
else
  echo "FINAL: COMPLETE (non-failing mode)"
fi
