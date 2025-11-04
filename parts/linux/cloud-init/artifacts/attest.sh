#!/usr/bin/env bash
set -euo pipefail
umask 027

# ========= Config (override in /etc/default/attest) =========
: "${LOG:=/var/log/attest.log}"
: "${STATE_DIR:=/var/lib/attest}"
: "${STATUS_FILE:=${STATE_DIR}/status.json}"
: "${TOKEN_FILE:=${STATE_DIR}/verdict.jwt}"
: "${RETRY_MAX:=20}"
: "${BACKOFF_BASE:=5}"                 # seconds
: "${BACKOFF_CAP:=60}"                 # max sleep between attempts
: "${PCRS:=0,7,11}"                    # tune to your policy
: "${REQUIRE_SECURE_BOOT:=true}"
: "${REQUIRE_TPM:=true}"
: "${VERIFIER_URL:=}"                  # e.g., https://attest.example/verify
: "${CHALLENGE_URL:=}"                 # e.g., https://attest.example/challenge
: "${CURL_TIMEOUT:=10}"                # seconds
: "${AK_HANDLE:=}"                     # e.g., 0x81000001 (optional)
: "${TPM_HASH_ALG:=sha256}"
: "${SCHEMA_VERSION:=1}"
: "${POLICY_HASH:=}"                   # AgentBaker-rendered policy hash (optional)

# Exit codes (must match systemd RestartPreventExitStatus)
readonly EXIT_SUCCESS=0
readonly EXIT_PERMANENT_FAILURE=10     # No retry (blocks kubelet permanently)
readonly EXIT_TRANSIENT_FAILURE=11     # Retry (systemd will restart)

mkdir -p "$(dirname "$LOG")" "$STATE_DIR"
chmod 700 "$STATE_DIR"

# Load optional defaults AFTER making dirs, so shellcheck isn't mad.
[[ -f /etc/default/attest ]] && . /etc/default/attest

log(){ echo "[attest] $(date --iso-8601=seconds) $*" | tee -a "$LOG" ; }
wstatus(){ printf '%s\n' "$1" > "$STATUS_FILE"; chmod 600 "$STATUS_FILE"; }

need() {
  command -v "$1" >/dev/null 2>&1 || {
    log "FATAL: $1 missing";
    wstatus "{\"status\":\"failed\",\"reason\":\"${1}Missing\"}";
    exit "$EXIT_PERMANENT_FAILURE"
  }
}

b64() { base64 -w0 "$1" 2>/dev/null || base64 "$1"; }

# --- Identity (prefer IMDS) ---
fetch_imds() {
  curl -sS --fail --max-time 2 -H "Metadata:true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" || true
}

get_node_identity() {
  local imds_json
  imds_json="$(fetch_imds)"

  if [[ -n "$imds_json" ]]; then
    local node_id
    node_id="$(echo "$imds_json" | jq -r '.compute | "\(.subscriptionId)/\(.resourceGroupName)/\(.name)"' 2>/dev/null || true)"
    if [[ -n "$node_id" && "$node_id" != "null" ]]; then
      echo "$node_id"
      return 0
    fi
  fi

  # Fallback to machine-id or hostname
  cat /etc/machine-id 2>/dev/null || hostname
}

NODE_ID="${NODE_ID:-$(get_node_identity)}"

# --- Platform checks ---
secure_boot_enabled() {
  if command -v mokutil >/dev/null 2>&1; then
    mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled' && return 0
  fi
  if command -v bootctl >/dev/null 2>&1; then
    bootctl status 2>/dev/null | grep -qi 'Secure Boot: enabled' && return 0
  fi
  return 2  # unknown
}

tpm_present(){ [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]] ; }

# --- TPM / AK helpers ---
detect_ak_handle() {
  # Use provided persistent handle if set
  if [[ -n "$AK_HANDLE" ]]; then
    log "Using provided AK handle: $AK_HANDLE"
    echo "$AK_HANDLE"
    return 0
  fi

  # Try to find a persistent handle that has a public portion
  if command -v tpm2_getcap >/dev/null 2>&1; then
    while read -r h; do
      if tpm2_readpublic -c "$h" >/dev/null 2>&1; then
        log "Found persistent AK handle: $h"
        echo "$h"
        return 0
      fi
    done < <(tpm2_getcap handles-persistent 2>/dev/null | grep -Eo '0x[0-9a-f]+')
  fi

  # Create an ephemeral AK under a (possibly ephemeral) EK
  log "No AK handle provided/found; creating ephemeral AK context"

  if ! tpm2_createek -G rsa -u "$STATE_DIR/ek.pub" -c "$STATE_DIR/ek.ctx" 2>/dev/null; then
    log "Failed to create EK"
    return 1
  fi

  if ! tpm2_createak -G ecc -g "$TPM_HASH_ALG" -s ecdsa \
    -C "$STATE_DIR/ek.ctx" -u "$STATE_DIR/ak.pub" -c "$STATE_DIR/ak.ctx" -n "$STATE_DIR/ak.name" 2>/dev/null; then
    log "Failed to create AK"
    return 1
  fi

  log "Created ephemeral AK context"
  echo "$STATE_DIR/ak.ctx"
}

perform_quote() {
  local ak="$1" nonce="$2"
  local qmsg="$STATE_DIR/quote.msg" qsig="$STATE_DIR/quote.sig" qpcr="$STATE_DIR/quote.pcrs"

  if ! tpm2_quote -c "$ak" -l "${TPM_HASH_ALG}:${PCRS}" -q "$nonce" -m "$qmsg" -s "$qsig" -o "$qpcr" 2>/dev/null; then
    log "tpm2_quote command failed"
    return 1
  fi

  local ak_pub="" ak_name=""
  [[ -f "$STATE_DIR/ak.pub"  ]] && ak_pub="$(b64 "$STATE_DIR/ak.pub")"
  [[ -f "$STATE_DIR/ak.name" ]] && ak_name="$(b64 "$STATE_DIR/ak.name")"

  jq -n \
    --arg node "$NODE_ID" \
    --arg nonce "$nonce" \
    --arg pcrs "$PCRS" \
    --arg hash "$TPM_HASH_ALG" \
    --arg quote "$(b64 "$qmsg")" \
    --arg signature "$(b64 "$qsig")" \
    --arg akPub "$ak_pub" \
    --arg akName "$ak_name" \
    '{node:$node,nonce:$nonce,pcrs:$pcrs,hash:$hash,quote:$quote,signature:$signature,akPub:$akPub,akName:$akName}'
}

fetch_nonce() {
  if [[ -n "$CHALLENGE_URL" ]]; then
    local resp nonce
    if ! resp=$(curl -sS --fail --max-time "$CURL_TIMEOUT" -H 'Accept: application/json' "$CHALLENGE_URL" 2>/dev/null); then
      log "Challenge URL request failed"
      return 1
    fi

    nonce=$(echo "$resp" | jq -r '.nonce // empty' 2>/dev/null || true)
    if [[ -z "$nonce" || "$nonce" == "null" ]]; then
      log "No valid nonce in challenge response"
      return 1
    fi

    log "Fetched nonce from challenge service"
    echo "$nonce"
    return 0
  fi

  # Generate local nonce (32 hex chars = 16 bytes)
  head -c 16 /dev/urandom | xxd -p | tr -d '\n'
}

verify_remote() {
  local payload="$1"

  if [[ -z "$VERIFIER_URL" ]]; then
    log "No VERIFIER_URL set; using stub verification (PASS)"
    jq -n --arg at "$(date --iso-8601=seconds)" '{ok:true,verifier:"stub",at:$at}'
    return 0
  fi

  local resp
  if ! resp=$(curl -sS --fail --max-time "$CURL_TIMEOUT" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "$VERIFIER_URL" 2>/dev/null); then
    log "Verifier request failed"
    return 1
  fi

  echo "$resp"
}

# --- Concurrency guard ---
single_instance_lock() {
  exec 200>"$STATE_DIR/.lock"
  if ! flock -n 200; then
    log "Another attestation instance is running (lock held)"
    exit "$EXIT_TRANSIENT_FAILURE"
  fi
}

sleep_backoff() {
  local attempt="$1"
  local s=$(( BACKOFF_BASE * attempt ))
  (( s > BACKOFF_CAP )) && s="$BACKOFF_CAP"
  # Add small jitter (0..4 seconds)
  s=$(( s + RANDOM % 5 ))
  log "Sleeping ${s}s before retry..."
  sleep "$s"
}

main() {
  log "=== Attestation starting (PID=$$) ==="
  single_instance_lock

  # Prereqs (missing tools = permanent failure)
  need jq
  need curl
  need tpm2_quote
  need tpm2_createek
  need tpm2_createak

  # Platform sanity checks
  if [[ "$REQUIRE_TPM" == "true" ]]; then
    if ! tpm_present; then
      log "FATAL: No TPM device present (/dev/tpmrm0 or /dev/tpm0 missing)"
      wstatus '{"status":"failed","reason":"tpmAbsent"}'
      exit "$EXIT_PERMANENT_FAILURE"
    fi
    log "TPM device detected"
  fi

  if [[ ! -c /dev/tpmrm0 && -c /dev/tpm0 ]]; then
    log "WARNING: /dev/tpmrm0 not present; TPM resource manager not available (continuing with /dev/tpm0)"
  fi

  # Secure Boot check (retry once if unknown)
  if [[ "$REQUIRE_SECURE_BOOT" == "true" ]]; then
    sb_code=0
    secure_boot_enabled || sb_code=$?

    case "$sb_code" in
      0)
        log "Secure Boot: ENABLED"
        ;;
      1)
        log "FATAL: Secure Boot is DISABLED"
        wstatus '{"status":"failed","reason":"secureBootDisabled"}'
        exit "$EXIT_PERMANENT_FAILURE"
        ;;
      2)
        if [[ ! -f "$STATE_DIR/.sb_checked_once" ]]; then
          log "Secure Boot state unknown; will retry once"
          : > "$STATE_DIR/.sb_checked_once"
          wstatus '{"status":"pending","reason":"secureBootUnknown"}'
          exit "$EXIT_TRANSIENT_FAILURE"
        else
          log "FATAL: Secure Boot state persistently unknown"
          wstatus '{"status":"failed","reason":"secureBootUnknown"}'
          exit "$EXIT_PERMANENT_FAILURE"
        fi
        ;;
    esac
  fi

  # Acquire AK (persistent or ephemeral)
  local ak
  if ! ak="$(detect_ak_handle)"; then
    log "Unable to obtain Attestation Key (AK) - will retry"
    wstatus '{"status":"failed","reason":"akUnavailable"}'
    exit "$EXIT_TRANSIENT_FAILURE"
  fi
  log "AK ready: $ak"

  # Attestation loop with retry
  for attempt in $(seq 1 "$RETRY_MAX"); do
    log "--- Attempt $attempt/$RETRY_MAX ---"

    # Step 1: Fetch nonce
    local nonce
    if ! nonce="$(fetch_nonce)"; then
      log "Nonce fetch failed (attempt $attempt/$RETRY_MAX)"
      sleep_backoff "$attempt"
      continue
    fi

    # Step 2: Perform TPM quote
    local quote_json
    if ! quote_json="$(perform_quote "$ak" "$nonce")"; then
      log "TPM quote failed (attempt $attempt/$RETRY_MAX)"
      sleep_backoff "$attempt"
      continue
    fi
    log "TPM quote collected successfully"

    # Step 3: Send to verifier
    local verdict
    if ! verdict="$(verify_remote "$quote_json")"; then
      log "Verifier unreachable (attempt $attempt/$RETRY_MAX)"
      sleep_backoff "$attempt"
      continue
    fi

    # Step 4: Parse verdict
    local ok
    ok="$(echo "$verdict" | jq -r '.ok // empty' 2>/dev/null || true)"

    if [[ "$ok" == "true" ]]; then
      # Optional subject sanity check
      local vsub
      vsub="$(echo "$verdict" | jq -r '.sub // empty' 2>/dev/null || true)"
      if [[ -n "$vsub" && "$vsub" != "null" && "$vsub" != "$NODE_ID" ]]; then
        log "WARNING: Verifier subject mismatch (expected=$NODE_ID, got=$vsub) - treating as transient"
        wstatus '{"status":"failed","reason":"subjectMismatch"}'
        exit "$EXIT_TRANSIENT_FAILURE"
      fi

      # Success! Write combined status
      local combined
      combined="$(jq -n \
        --arg ver "$SCHEMA_VERSION" \
        --arg policy "$POLICY_HASH" \
        --argjson quote "$quote_json" \
        --argjson verdict "$verdict" \
        '{version:$ver,policy:$policy,status:"passed",quote:$quote,verdict:$verdict}')"
      wstatus "$combined"

      # Persist optional token/JWT for controllers
      echo "$verdict" | jq -r '.token // empty' > "$TOKEN_FILE" 2>/dev/null || true
      chmod 600 "$TOKEN_FILE" 2>/dev/null || true

      log "=== Attestation PASSED ==="
      exit "$EXIT_SUCCESS"
    fi

    # Attestation failed - extract reason and retry
    local reason
    reason="$(echo "$verdict" | jq -r '.reason // "verificationFailed"' 2>/dev/null || echo "verificationFailed")"
    wstatus "{\"status\":\"failed\",\"reason\":\"${reason}\"}"
    log "Verifier REJECTED: reason=$reason (attempt $attempt/$RETRY_MAX)"
    sleep_backoff "$attempt"
  done

  # Exhausted all retries
  log "=== Exhausted $RETRY_MAX retry attempts ==="
  wstatus '{"status":"failed","reason":"maxRetries"}'
  exit "$EXIT_TRANSIENT_FAILURE"
}

main
