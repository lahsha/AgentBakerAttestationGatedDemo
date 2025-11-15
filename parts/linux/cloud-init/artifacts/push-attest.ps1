[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$AksResourceGroup,
  [Parameter(Mandatory=$true)][string]$ClusterName,
  [Parameter(Mandatory=$true)][string]$NodeName,
  [ValidateSet('AUTO','VERIFY','STUB','MOCK')][string]$Mode='AUTO',
  [string]$VerifierUrl='',
  [string]$ChallengeUrl='',
  [switch]$SkipPrereqs,
  [int]$TimeoutStartSec = 120,
  [int]$RestartSec = 20,
  [switch]$EnableGating,
  [switch]$EnableGatingRefreshTimer,
  [string]$TaintKey='attest',
  [string]$TaintValue='failed',
  [string]$TaintEffect='NoSchedule',
  [string]$LabelKey='attestation',
  [string]$LabelPassed='passed',
  [string]$LabelFailed='failed',
  [switch]$RequireStatusFile,
  [string]$ScriptVersion='2025.11.15',
  [string]$ArtifactsDir = "$(Split-Path -Parent $PSCommandPath)"
)

$ErrorActionPreference = 'Stop'

function Resolve-NodeIdentity {
  Write-Host "Resolving nodeResourceGroup..."
  $nodeRG = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv
  if (-not $nodeRG) { throw "Could not resolve nodeResourceGroup" }
  Write-Host "Fetching providerID for $NodeName..."
  $provId = kubectl get node $NodeName -o jsonpath='{.spec.providerID}' 2>$null
  if (-not $provId) { throw "Could not get providerID for $NodeName" }
  $m = [Regex]::Match($provId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)')
  if (-not $m.Success) { throw "Could not parse providerID '$provId'" }
  @{
    NodeResourceGroup = $nodeRG
    Vmss       = $m.Groups[1].Value
    InstanceId = $m.Groups[2].Value
  }
}

function Load-FileOrDie([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Missing required $Name file at path: $Path"
  }
  $content = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::UTF8)
  if (-not $content.Trim()) { throw "$Name file empty: $Path" }
  return $content
}

function Patch-ServiceUnit([string]$Content) {
  # Ensure [Service] section exists
  if ($Content -notmatch '(?m)^\[Service\]') {
    $Content = $Content.TrimEnd() + "`n[Service]`n"
  }

  # TimeoutStartSec
  if ($Content -match '(?m)^TimeoutStartSec=\d+') {
    $Content = [Regex]::Replace($Content,'(?m)^TimeoutStartSec=\d+',"TimeoutStartSec=$TimeoutStartSec")
  } else {
    $Content = $Content -replace '(?m)^\[Service\]',"[Service]`nTimeoutStartSec=$TimeoutStartSec"
  }

  # RestartSec
  if ($Content -match '(?m)^RestartSec=\d+') {
    $Content = [Regex]::Replace($Content,'(?m)^RestartSec=\d+',"RestartSec=$RestartSec")
  } else {
    $Content = $Content -replace '(?m)^\[Service\]',"[Service]`nRestartSec=$RestartSec"
  }

  # ExecStartPost gating (inject if enabled)
  if ($EnableGating) {
    if ($Content -notmatch '(?m)^ExecStartPost=/usr/local/bin/attest-gating\.sh') {
      # Place after existing ExecStart line if present, else append at end of [Service]
      if ($Content -match '(?m)^ExecStart=') {
        $Content = $Content -replace '(?m)^ExecStart=.*$',{
          $_ + "`nExecStartPost=/usr/local/bin/attest-gating.sh"
        }
      } else {
        $Content = $Content -replace '(?m)^\[Service\]',"[Service]`nExecStartPost=/usr/local/bin/attest-gating.sh"
      }
    }
  } else {
    # If gating disabled, strip any lingering ExecStartPost line referencing attest-gating
    $Content = [Regex]::Replace($Content,'(?m)^ExecStartPost=/usr/local/bin/attest-gating\.sh\s*','')
  }

  return $Content
}

$info = Resolve-NodeIdentity
Write-Host "Target => NodeRG=$($info.NodeResourceGroup) VMSS=$($info.Vmss) IID=$($info.InstanceId)"

# Paths (no templates now)
$attestScriptPath  = Join-Path $ArtifactsDir 'attest.sh'
$servicePath       = Join-Path $ArtifactsDir 'attest.service'
$gatingScriptPath  = Join-Path $ArtifactsDir 'attest-gating.sh'
$dropinPath        = Join-Path $ArtifactsDir 'kubelet.attestation.dropin'   # optional plain file

$AttestScriptRaw = Load-FileOrDie $attestScriptPath 'attest.sh'
$ServiceRaw      = Load-FileOrDie $servicePath 'attest.service'

$GatingScriptRaw = $null
if ($EnableGating) {
  if (Test-Path $gatingScriptPath) {
    $GatingScriptRaw = Load-FileOrDie $gatingScriptPath 'attest-gating.sh'
  } else {
    throw "Gating requested but gating script not found at $gatingScriptPath"
  }
}

# Version placeholder in attest.sh
$AttestScript = $AttestScriptRaw -replace '__SCRIPT_VERSION__', $ScriptVersion

# Patch service unit for timeouts and gating ExecStartPost
$ServiceUnit = Patch-ServiceUnit $ServiceRaw

# Drop-in content
if (Test-Path $dropinPath) {
  $DropinUnit = Load-FileOrDie $dropinPath 'kubelet attestation drop-in'
} else {
  $DropinUnit = @"
[Unit]
After=attest.service
"@
}

# Ensure we never keep Requires=attest.service in drop-in
$DropinUnit = [Regex]::Replace($DropinUnit,'(?m)^Requires=attest\.service\s*','')

# Gating script substitution
if ($EnableGating) {
  $GatingScript = $GatingScriptRaw `
    -replace '__TAINT_KEY__', $TaintKey `
    -replace '__TAINT_VALUE__', $TaintValue `
    -replace '__TAINT_EFFECT__', $TaintEffect `
    -replace '__LABEL_KEY__', $LabelKey `
    -replace '__LABEL_PASS__', $LabelPassed `
    -replace '__LABEL_FAIL__', $LabelFailed `
    -replace '__REQUIRE_FILE__', ($RequireStatusFile ? 'true' : 'false')
}

$Remote = @'
#!/usr/bin/env bash
set -euo pipefail

MODE="__MODE__"
VERIFIER_URL="__VERIFIER_URL__"
CHALLENGE_URL="__CHALLENGE_URL__"
SKIP_PREREQS="__SKIP_PREREQS__"
ENABLE_GATING="__ENABLE_GATING__"
ENABLE_TIMER="__ENABLE_TIMER__"

log(){ echo "[deploy-attest] $(date --iso-8601=seconds) $*" >&2; }

if [[ "$SKIP_PREREQS" != "true" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y --no-install-recommends jq curl tpm2-tools flock util-linux || true
fi

install -d -m0755 /opt/azure/containers /etc/systemd/system/kubelet.service.d

cat > /opt/azure/containers/attest.sh <<'ATT'
__ATTEST_SH__
ATT
chmod 0755 /opt/azure/containers/attest.sh

cat > /etc/default/attest <<ENV
MODE=$MODE
VERIFIER_URL=$VERIFIER_URL
CHALLENGE_URL=$CHALLENGE_URL
REQUIRE_TPM=true
REQUIRE_SECURE_BOOT=true
PCRS=0,7,11
ENV

cat > /etc/systemd/system/attest.service <<'UNIT'
__SERVICE_UNIT__
UNIT

DROPIN=/etc/systemd/system/kubelet.service.d/10-attestation.conf
cat > "$DROPIN" <<'DUNIT'
__DROPIN_UNIT__
DUNIT
sed -i '/^Requires=attest.service/d' "$DROPIN"

if [[ "$ENABLE_GATING" == "true" ]]; then
  cat > /usr/local/bin/attest-gating.sh <<'GATE'
__GATING_SCRIPT__
GATE
  chmod 0755 /usr/local/bin/attest-gating.sh

  if [[ "$ENABLE_TIMER" == "true" ]]; then
    cat > /etc/systemd/system/attest-gating.timer <<'TIMER'
[Unit]
Description=Periodic attestation gating refresh
[Timer]
OnBootSec=5m
OnUnitActiveSec=10m
Unit=attest-gating-refresh.service
[Install]
WantedBy=timers.target
TIMER
    cat > /etc/systemd/system/attest-gating-refresh.service <<'REFRESH'
[Unit]
Description=Re-apply attestation gating
[Service]
Type=oneshot
ExecStart=/usr/local/bin/attest-gating.sh
REFRESH
  fi
fi

systemctl daemon-reload
systemctl enable attest.service >/dev/null 2>&1 || true
systemctl reset-failed attest.service || true
systemctl restart attest.service || true
systemctl restart kubelet.service || true
if [[ "$ENABLE_GATING" == "true" && "$ENABLE_TIMER" == "true" ]]; then
  systemctl enable --now attest-gating.timer || true
fi

echo "== attest.service status =="
systemctl show attest.service -p ActiveState -p Result
echo "== kubelet drop-in =="
sed -n '1,25p' "$DROPIN"
echo "== status.json (first 160 chars) =="
[ -f /var/lib/attest/status.json ] && sed -n '1,160p' /var/lib/attest/status.json || echo "(missing)"
'@

# Safe sequential replacements
$Remote = $Remote.Replace('__MODE__', $Mode)
$Remote = $Remote.Replace('__VERIFIER_URL__', $VerifierUrl)
$Remote = $Remote.Replace('__CHALLENGE_URL__', $ChallengeUrl)
$Remote = $Remote.Replace('__SKIP_PREREQS__', ($SkipPrereqs ? 'true' : 'false'))
$Remote = $Remote.Replace('__ENABLE_GATING__', ($EnableGating ? 'true' : 'false'))
$Remote = $Remote.Replace('__ENABLE_TIMER__', ($EnableGatingRefreshTimer ? 'true' : 'false'))
$Remote = $Remote.Replace('__ATTEST_SH__', $AttestScript)
$Remote = $Remote.Replace('__SERVICE_UNIT__', $ServiceUnit)
$Remote = $Remote.Replace('__DROPIN_UNIT__', $DropinUnit)

if ($EnableGating) {
  $Remote = $Remote.Replace('__GATING_SCRIPT__', $GatingScript)
} else {
  $Remote = $Remote.Replace('__GATING_SCRIPT__', '')
}

$Temp = [IO.Path]::GetTempFileName().Replace('.tmp','.sh')
[IO.File]::WriteAllText($Temp, ($Remote -replace "`r`n","`n"), [Text.UTF8Encoding]::UTF8)

try {
  Write-Host "Invoking RunCommand (VMSS=$($info.Vmss) IID=$($info.InstanceId))..."
  $resp = az vmss run-command invoke -g $info.NodeResourceGroup -n $info.Vmss `
    --instance-id $info.InstanceId --command-id RunShellScript --scripts "@$Temp"
  $resp
} finally {
  Remove-Item -Force $Temp
}

Write-Host "Completed attestation push for node: $NodeName"
