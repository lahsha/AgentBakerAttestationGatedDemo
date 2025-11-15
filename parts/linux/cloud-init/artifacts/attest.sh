#!/usr/bin/env bash
set -euo pipefail
umask 027

export LANG=C
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# Prefer /dev/tpmrm0 then fall back to /dev/tpm0
if [[ -c /dev/tpmrm0 ]]; then
  export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
elif [[ -c /dev/tpm0 ]]; then
  export TPM2TOOLS_TCTI="device:/dev/tpm0"
fi

# ========= Config (override in /etc/default/attest) =========
: "${LOG:=/var/log/attest.log}"
: "${STATE_DIR:=/var/lib/attest}"
: "${STATUS_FILE:=${STATE_DIR}/status.json}"
: "${TOKEN_FILE:=${STATE_DIR}/verdict.jwt}"
: "${RETRY_MAX:=20}"
: "${BACKOFF_BASE:=5}"
: "${BACKOFF_CAP:=60}"
: "${PCRS:=0,7,11}"
: "${REQUIRE_SECURE_BOOT:=true}"
: "${REQUIRE_TPM:=true}"
: "${VERIFIER_URL:=}"
: "${CHALLENGE_URL:=}"
: "${CURL_TIMEOUT:=10}"
: "${AK_HANDLE:=}"
: "${TPM_HASH_ALG:=sha256}"
: "${SCHEMA_VERSION:=1}"
: "${POLICY_HASH:=}"

# ========= Exit codes (must match systemd RestartPreventExitStatus) =========
readonly EXIT_SUCCESS=0
readonly EXIT_PERMANENT_FAILURE=10
readonly EXIT_TRANSIENT_FAILURE=11

mkdir -p "$(dirname "$LOG")" "$STATE_DIR"
chmod 700 "$STATE_DIR"
[[ -f /etc/default/attest ]] && . /etc/default/attest

# ========= Logging / helpers =========
log(){ echo "[attest] $(date --iso-8601=seconds) $*" | tee -a "$LOG" >&2 ; }
wstatus(){ printf '%s\n' "$1" > "$STATUS_FILE"; chmod 600 "$STATUS_FILE"; }
need(){ command -v "$1" >/dev/null 2>&1 || { log "FATAL: $1 missing"; wstatus "{\"status\":\"failed\",\"reason\":\"${1}Missing\"}"; exit "$EXIT_PERMANENT_FAILURE"; }; }
b64(){ base64 -w0 "$1" 2>/dev/null || base64 "$1"; }

# ========= Identity (prefer IMDS) =========
fetch_imds(){ curl -sS --fail --max-time 2 -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" || true; }
get_node_identity(){
  local imds_json node_id
  imds_json="$(fetch_imds)"
  if [[ -n "$imds_json" ]]; then
    node_id="$(echo "$imds_json" | jq -r '.compute | "\(.subscriptionId)/\(.resourceGroupName)/\(.name)"' 2>/dev/null || true)"
    if [[ -n "$node_id" && "$node_id" != "null" ]]; then
      echo "$node_id"; return 0
    fi
  fi
  cat /etc/machine-id 2>/dev/null || hostname
}
NODE_ID="${NODE_ID:-$(get_node_identity)}"

# ========= Platform checks =========
secure_boot_enabled(){
  if command -v mokutil >/dev/null 2>&1; then
    mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled' && return 0 || return 1
  fi
  if command -v bootctl >/dev/null 2>&1; then
    bootctl status 2>/dev/null | grep -qi 'Secure Boot: enabled' && return 0 || return 1
  fi
  return 2
}
tpm_present(){ [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]; }

# ========= TPM / AK helpers =========
detect_ak_handle(){
  if [[ -n "$AK_HANDLE" ]]; then
    if [[ "$AK_HANDLE" =~ ^0x[0-9a-fA-F]+$ ]]; then
      log "Using provided AK handle: $AK_HANDLE"
      echo "$AK_HANDLE"; return 0
    else
      log "Provided AK_HANDLE malformed: $AK_HANDLE"; return 1
    fi
  fi
  if command -v tpm2_getcap >/dev/null 2>&1; then
    while read -r h; do
      [[ -z "$h" ]] && continue
      if timeout 5s tpm2_readpublic -c "$h" >/dev/null 2>&1; then
        log "Found persistent AK handle: $h"
        echo "$h"; return 0
      fi
    done < <(tpm2_getcap handles-persistent 2>/dev/null | grep -Eo '0x[0-9a-fA-F]+')
  fi
  log "No persistent AK, creating ephemeral AK"
  tpm2_createek -G rsa -u "$STATE_DIR/ek.pub" -c "$STATE_DIR/ek.ctx" >/dev/null 2>&1 || { log "Failed to create EK"; return 1; }
  tpm2_createak -G ecc -g "$TPM_HASH_ALG" -s ecdsa -C "$STATE_DIR/ek.ctx" \
    -u "$STATE_DIR/ak.pub" -c "$STATE_DIR/ak.ctx" -n "$STATE_DIR/ak.name" >/dev/null 2>&1 || { log "Failed to create AK"; return 1; }
  log "Created ephemeral AK context"
  echo "$STATE_DIR/ak.ctx"
}

perform_quote(){
  local ak="$1" nonce="$2"
  local qmsg="$STATE_DIR/quote.msg" qsig="$STATE_DIR/quote.sig" qpcr="$STATE_DIR/quote.pcrs"
  if [[ "$ak" =~ ^0x[0-9a-fA-F]+$ || -f "$ak" ]]; then :; else
    log "AK handle/context invalid: $ak"; return 1
  fi
  if ! timeout 15s tpm2_quote -c "$ak" -l "${TPM_HASH_ALG}:${PCRS}" -q "$nonce" \
       -m "$qmsg" -s "$qsig" -o "$qpcr" >/dev/null 2>&1; then
    log "tpm2_quote command failed"; return 1
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

fetch_nonce(){
  if [[ -n "$CHALLENGE_URL" ]]; then
    local resp nonce
    if ! resp=$(curl -sS --fail --max-time "$CURL_TIMEOUT" --connect-timeout 3 --retry 2 --retry-delay 2 \
                 -H 'Accept: application/json' "$CHALLENGE_URL" 2>/dev/null); then
      log "Challenge URL request failed"; return 1
    fi
    nonce="$(echo "$resp" | jq -r '.nonce // empty' 2>/dev/null || true)"
    [[ -n "$nonce" && "$nonce" != "null" ]] || { log "No valid nonce in challenge response"; return 1; }
    log "Fetched nonce from challenge service"
    echo "$nonce"; return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    log "Using random nonce from openssl"
    openssl rand -hex 16
  else
    log "Using random nonce from xxd"
    head -c 16 /dev/urandom | xxd -p | tr -d '\n'
  fi
}

verify_remote(){
  local payload="$1"
  if [[ -z "$VERIFIER_URL" ]]; then
    log "No VERIFIER_URL set, stub PASS"
    jq -n --arg at "$(date --iso-8601=seconds)" '{ok:true,verifier:"stub",at:$at}'
    return 0
  fi
  curl -sS --fail --max-time "$CURL_TIMEOUT" --connect-timeout 3 --retry 2 --retry-delay 2 \
       -H 'Content-Type: application/json' -d "$payload" "$VERIFIER_URL" 2>/dev/null || { log "Verifier request failed"; return 1; }
}

single_instance_lock(){ exec 200>"$STATE_DIR/.lock"; flock -n 200 || { log "Another instance running"; exit "$EXIT_TRANSIENT_FAILURE"; }; }
sleep_backoff(){
  local attempt="$1"
  local s=$(( BACKOFF_BASE * attempt ))
  (( s > BACKOFF_CAP )) && s="$BACKOFF_CAP"
  s=$(( s + RANDOM % 5 ))
  log "Sleeping ${s}s before retry..."
  sleep "$s"
}

main(){
  log "=== Attestation starting (PID=$$) ==="
  single_instance_lock

  # Prereqs
  need jq; need curl; need timeout; need flock
  need tpm2_quote; need tpm2_createek; need tpm2_createak; need tpm2_readpublic
  command -v xxd >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 || { log "FATAL: need xxd or openssl"; wstatus '{"status":"failed","reason":"entropyToolMissing"}'; exit "$EXIT_PERMANENT_FAILURE"; }

  # TPM presence
  if [[ "$REQUIRE_TPM" == "true" ]]; then
    if ! tpm_present; then
      log "FATAL: no TPM device present"
      wstatus '{"status":"failed","reason":"tpmAbsent"}'
      exit "$EXIT_PERMANENT_FAILURE"
    fi
    log "TPM device detected"
  fi
  if [[ ! -c /dev/tpmrm0 && -c /dev/tpm0 ]]; then
    log "Warning, /dev/tpmrm0 missing, using /dev/tpm0"
  fi

  # Secure Boot
  if [[ "$REQUIRE_SECURE_BOOT" == "true" ]]; then
    sb_code=0; secure_boot_enabled || sb_code=$?
    case "$sb_code" in
      0) log "Secure Boot: ENABLED" ;;
      1) log "FATAL: Secure Boot DISABLED"; wstatus '{"status":"failed","reason":"secureBootDisabled"}'; exit "$EXIT_PERMANENT_FAILURE" ;;
      2)
        if [[ ! -f "$STATE_DIR/.sb_checked_once" ]]; then
          log "Secure Boot unknown, will retry once"
          : > "$STATE_DIR/.sb_checked_once"
          wstatus '{"status":"pending","reason":"secureBootUnknown"}'
          exit "$EXIT_TRANSIENT_FAILURE"
        else
          log "FATAL: Secure Boot persistently unknown"
          wstatus '{"status":"failed","reason":"secureBootUnknown"}'
          exit "$EXIT_PERMANENT_FAILURE"
        fi
        ;;
    esac
  fi

  # Acquire AK
  local ak
  if ! ak="$(detect_ak_handle)"; then
    log "Unable to obtain AK (initial)"; wstatus '{"status":"failed","reason":"akUnavailable"}'; exit "$EXIT_TRANSIENT_FAILURE"
  fi
  ak="$(printf '%s' "$ak" | tr -d '\r\n\t ')"
  log "AK ready: $ak"

  # Retry loop
  for attempt in $(seq 1 "$RETRY_MAX"); do
    log "--- Attempt $attempt/$RETRY_MAX ---"
    local nonce
    if ! nonce="$(fetch_nonce)"; then
      log "Nonce fetch failed"
      sleep_backoff "$attempt"; continue
    fi

    local quote_json
    if ! quote_json="$(perform_quote "$ak" "$nonce")"; then
      log "TPM quote failed"
      if [[ $attempt -eq 3 && "$ak" =~ ^0x[0-9a-fA-F]+$ ]]; then
        log "Switching to ephemeral AK after repeated quote failures"
        if ak="$(detect_ak_handle)"; then
          ak="$(printf '%s' "$ak" | tr -d '\r\n\t ')"
          log "New AK: $ak"
        fi
      fi
      sleep_backoff "$attempt"; continue
    fi
    log "TPM quote collected"

    local verdict ok
    if ! verdict="$(verify_remote "$quote_json")"; then
      log "Verifier unreachable"
      sleep_backoff "$attempt"; continue
    fi
    ok="$(echo "$verdict" | jq -r '.ok // empty' 2>/dev/null || true)"

    if [[ "$ok" == "true" ]]; then
      local vsub
      vsub="$(echo "$verdict" | jq -r '.sub // empty' 2>/dev/null || true)"
      if [[ -n "$vsub" && "$vsub" != "null" && "$vsub" != "$NODE_ID" ]]; then
        log "Subject mismatch (expected=$NODE_ID got=$vsub)"
        wstatus '{"status":"failed","reason":"subjectMismatch"}'
        exit "$EXIT_TRANSIENT_FAILURE"
      fi
      local combined
      combined="$(jq -n \
        --arg ver "$SCHEMA_VERSION" \
        --arg policy "$POLICY_HASH" \
        --argjson quote "$quote_json" \
        --argjson verdict "$verdict" \
        '{version:$ver,policy:$policy,status:"passed",quote:$quote,verdict:$verdict}')"
      wstatus "$combined"
      # write token only if non-empty
      local token
      token="$(echo "$verdict" | jq -r '.token // empty' 2>/dev/null || true)"
      if [[ -n "$token" ]]; then
        printf '%s\n' "$token" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE" 2>/dev/null || true
      fi
      log "=== Attestation PASSED ==="
      exit "$EXIT_SUCCESS"
    fi

    local reason
    reason="$(echo "$verdict" | jq -r '.reason // "verificationFailed"' 2>/dev/null || echo "verificationFailed")"
    wstatus "{\"status\":\"failed\",\"reason\":\"${reason}\"}"
    log "Verifier rejected: $reason"
    sleep_backoff "$attempt"
  done

  log "Exhausted retries"
  wstatus '{"status":"failed","reason":"maxRetries"}'
  exit "$EXIT_TRANSIENT_FAILURE"
}

main
