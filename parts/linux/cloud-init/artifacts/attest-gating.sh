#!/usr/bin/env bash
# Tokens: __TAINT_KEY__ __TAINT_VALUE__ __TAINT_EFFECT__ __LABEL_KEY__ __LABEL_PASS__ __LABEL_FAIL__ __REQUIRE_FILE__
set -euo pipefail
LOG=/var/log/attest-gating.log
STATUS=/var/lib/attest/status.json
TAINT_KEY="__TAINT_KEY__"
TAINT_VALUE="__TAINT_VALUE__"
TAINT_EFFECT="__TAINT_EFFECT__"
LABEL_KEY="__LABEL_KEY__"
LABEL_PASS="__LABEL_PASS__"
LABEL_FAIL="__LABEL_FAIL__"
REQUIRE_FILE="__REQUIRE_FILE__"
log(){ echo "[gating] $(date --iso-8601=seconds) $*" | tee -a "$LOG" >&2; }
NODE_NAME="$(hostname)"
if ! command -v kubectl >/dev/null 2>&1; then log "kubectl missing; skipping"; exit 0; fi
if [[ ! -f "$STATUS" ]]; then
  if [[ "$REQUIRE_FILE" == "true" ]]; then
    log "Missing status.json -> taint"
    kubectl taint nodes "$NODE_NAME" "${TAINT_KEY}=${TAINT_VALUE}:${TAINT_EFFECT}" --overwrite || true
    kubectl label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_FAIL}" --overwrite || true
  else
    log "Missing status.json but REQUIRE_FILE=false -> ignore"
  fi
  exit 0
fi
status="$(jq -r '.status // empty' "$STATUS" 2>/dev/null || true)"
reason="$(jq -r '.reason // empty' "$STATUS" 2>/dev/null || true)"
if [[ "$status" == "passed" ]]; then
  log "Passed -> clear taint, label passed"
  kubectl taint nodes "$NODE_NAME" "${TAINT_KEY}-" || true
  kubectl label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_PASS}" --overwrite || true
else
  log "Not passed (status=${status:-null} reason=${reason:-unknown}) -> apply taint"
  kubectl taint nodes "$NODE_NAME" "${TAINT_KEY}=${TAINT_VALUE}:${TAINT_EFFECT}" --overwrite || true
  kubectl label node "$NODE_NAME" "${LABEL_KEY}=${LABEL_FAIL}" --overwrite || true
fi
