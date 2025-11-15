#!/usr/bin/env bash
# attest-gating.sh
# Gate node readiness based on /var/lib/attest/status.json
set -euo pipefail

LOG=/var/log/attest-gating.log
STATUS=/var/lib/attest/status.json

TAINT_KEY="attest"
TAINT_VALUE="failed"
TAINT_EFFECT="NoSchedule"
LABEL_KEY="attestation"
LABEL_PASS="passed"
LABEL_FAIL="failed"

# Always use the kubelet’s kubeconfig on AKS nodes
KCFG="/var/lib/kubelet/kubeconfig"
KCTL="/usr/local/bin/kubectl"

log(){ echo "[gating] $(date --iso-8601=seconds) $*" | tee -a "$LOG" >&2; }

need(){ command -v "$1" >/dev/null 2>&1 || { log "$1 missing; skipping"; exit 0; }; }

need "$KCTL"
if [ ! -s "$KCFG" ]; then
  log "kubeconfig $KCFG missing; skipping"
  exit 0
fi

NODE_NAME="$(hostname)"

api_ok(){
  # Cheap reachability check using the kubelet creds
  "$KCTL" --kubeconfig "$KCFG" get --raw='/readyz' >/dev/null 2>&1
}

# If status file is required to be present to avoid false positive, toggle here if desired
REQUIRE_FILE="false"

if [ ! -f "$STATUS" ]; then
  if [ "$REQUIRE_FILE" = "true" ]; then
    log "Missing status.json -> taint"
    "$KCTL" --kubeconfig "$KCFG" taint nodes "$NODE_NAME" "${TAINT_KEY}=${TAINT_VALUE}:${TAINT_EFFECT}" --overwrite || true
    "$KCTL" --kubeconfig "$KCFG" label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_FAIL}" --overwrite || true
  else
    log "Missing status.json but REQUIRE_FILE=false -> ignore"
  fi
  exit 0
fi

# Make sure apiserver is reachable using node creds
if ! api_ok; then
  log "apiserver not reachable, one retry in 5s"
  sleep 5
  if ! api_ok; then
    log "apiserver not reachable, giving up for now"
    exit 0
  fi
fi

status="$(jq -r '.status // empty' "$STATUS" 2>/dev/null || true)"
reason="$(jq -r '.reason // empty' "$STATUS" 2>/dev/null || true)"

if [ "$status" = "passed" ]; then
  log "Passed -> clear taint, label passed"
  "$KCTL" --kubeconfig "$KCFG" taint nodes "$NODE_NAME" "${TAINT_KEY}-" || true
  "$KCTL" --kubeconfig "$KCFG" label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_PASS}" --overwrite || true
else
  log "Not passed (status=${status:-null} reason=${reason:-unknown}) -> apply taint"
  "$KCTL" --kubeconfig "$KCFG" taint nodes "$NODE_NAME" "${TAINT_KEY}=${TAINT_VALUE}:${TAINT_EFFECT}" --overwrite || true
  "$KCTL" --kubeconfig "$KCFG" label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_FAIL}" --overwrite || true
fi
