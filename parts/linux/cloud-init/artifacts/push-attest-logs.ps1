<#
  Retrieve attestation diagnostics from one or more AKS VMSS instances.

  Features:
    - Parameterized cluster and node selection (exact, prefix, regex, or first Ready)
    - Optional collection from all matches (-AllMatches)
    - Per-node saved attestation block + optional raw RunCommand JSON
    - Stable node ordering (sorted) for deterministic default selection
    - Single temp remote script (UTF8) reused across nodes
    - Regex-based attestation block extraction (no cross-node state)
    - Dry run exit code parsed and summarized
    - Optional tabular summary (-Summary)
    - Experimental parallel mode (-Parallel) for multiple nodes

  Exit codes:
    0 success
    1 invalid arguments
    2 failed resolving node RG
    3 node selection produced zero candidates
    4 RunCommand failure
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string]$AksResourceGroup,
  [Parameter(Mandatory = $true)] [string]$ClusterName,
  [string]$NodeName,
  [string]$NodePrefix,
  [string]$NodeRegex,
  [switch]$AllMatches,
  [string]$OutDir = "./attest-diags",
  [switch]$IncludeRawJson,
  [int]$TimeoutSeconds = 45,
  [switch]$Summary,
  [switch]$Parallel
)

$ErrorActionPreference = "Stop"

function Fail($msg, [int]$code = 1) {
  Write-Error $msg
  exit $code
}

# Argument validation
if (($PSBoundParameters.ContainsKey('NodePrefix') -or $PSBoundParameters.ContainsKey('NodeRegex')) -and $PSBoundParameters.ContainsKey('NodeName')) {
  Fail "Provide only one of -NodeName OR (-NodePrefix | -NodeRegex)" 1
}
if ($PSBoundParameters.ContainsKey('NodePrefix') -and $PSBoundParameters.ContainsKey('NodeRegex')) {
  Fail "Provide only one of -NodePrefix or -NodeRegex" 1
}
if ($TimeoutSeconds -le 0) { Fail "-TimeoutSeconds must be positive" 1 }

function Resolve-NodeResourceGroup {
  Write-Host "Resolving node resource group for cluster '$ClusterName' in RG '$AksResourceGroup'..."
  $rg = az aks show -g $AksResourceGroup -n $ClusterName --query nodeResourceGroup -o tsv 2>$null
  if (-not $rg) { Fail "Could not resolve nodeResourceGroup for $ClusterName (check az login/subscription)" 2 }
  return $rg
}

function Select-Nodes {
  param([string]$Exact,[string]$Prefix,[string]$Regex)
  Write-Host "Listing nodes via kubectl..."
  $nodesJson = kubectl get nodes -o json | ConvertFrom-Json
  $allNodes = $nodesJson.items | ForEach-Object { $_.metadata.name } | Sort-Object
  if (-not $allNodes) { Fail "No nodes returned by kubectl" 3 }

  $candidates = @()
  if ($Exact) {
    if ($allNodes -contains $Exact) { $candidates = @($Exact) } else { Fail "Exact node '$Exact' not found" 3 }
  } elseif ($Prefix) {
    $candidates = $allNodes | Where-Object { $_.StartsWith($Prefix) }
  } elseif ($Regex) {
    $rx = [regex]::new($Regex)
    $candidates = $allNodes | Where-Object { $rx.IsMatch($_) }
  } else {
    $ready = $nodesJson.items | Where-Object {
      $_.status.conditions | Where-Object { $_.type -eq "Ready" -and $_.status -eq "True" }
    } | Select-Object -ExpandProperty metadata | Select-Object -ExpandProperty name
    if ($ready) { $candidates = @($ready | Sort-Object | Select-Object -First 1) }
  }

  if (-not $candidates) { Fail "Node selection yielded zero matches" 3 }
  if (-not $AllMatches -and $candidates.Count -gt 1) {
    Write-Host "Multiple matches found; using first. Add -AllMatches to process all."
    $candidates = @($candidates[0])
  }
  Write-Host "Selected nodes: $($candidates -join ', ')"
  return $candidates
}

function Parse-ProviderId {
  param([string]$Node)
  $provId = kubectl get node $Node -o jsonpath='{.spec.providerID}' 2>$null
  if (-not $provId) { Fail "providerID missing for node $Node" 4 }
  $m = [regex]::Match($provId,'virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)', 'IgnoreCase')
  if (-not $m.Success) { Fail "Unable to parse VMSS/instance from providerID '$provId'" 4 }
  return @{ vmss = $m.Groups[1].Value; iid = $m.Groups[2].Value; providerID = $provId }
}

function Build-RemoteScript {
  param([int]$DryTimeout)
  $tmpl = @'
#!/bin/sh
set -eu
echo "=== START_ATTEST_LOG_BLOCK ==="
echo "--- Basic status ---"
if systemctl list-unit-files | grep -q '^attest.service'; then
  systemctl --no-pager -l status attest.service || true
  systemctl show attest.service \
    -p Id -p Type -p ExecStart -p ActiveState -p SubState -p Result -p ExecMainStatus -p ExecMainCode || true
else
  echo "attest.service not found"
fi
echo "--- attest unit file (systemctl cat) ---"
systemctl cat attest.service 2>/dev/null | sed -n '1,160p' || echo "(unit file missing)"
echo "--- kubelet dependencies ---"
systemctl show kubelet -p Requires -p After 2>/dev/null || echo "(kubelet not found)"
echo "--- kubelet merged unit (first 120 lines) ---"
systemctl cat kubelet 2>/dev/null | sed -n '1,120p' || true
echo "--- /var/lib/attest/status.json (truncated) ---"
[ -f /var/lib/attest/status.json ] && sed -n '1,140p' /var/lib/attest/status.json || echo "(status.json missing)"
echo "--- verdict.jwt (first 2 lines) ---"
[ -f /var/lib/attest/verdict.jwt ] && head -n 2 /var/lib/attest/verdict.jwt || echo "(verdict.jwt missing)"
echo "--- attest.sh head (first 50 lines) + sha256 + perms ---"
if [ -f /opt/azure/containers/attest.sh ]; then
  head -n 50 /opt/azure/containers/attest.sh
  sha256sum /opt/azure/containers/attest.sh 2>/dev/null || echo "(sha256 failed)"
  ls -l /opt/azure/containers/attest.sh
else
  echo "(attest.sh missing)"
fi
echo "--- /etc/default/attest ---"
[ -f /etc/default/attest ] && sed -n '1,80p' /etc/default/attest || echo "(no defaults file)"
echo "--- TPM devices ---"
ls -l /dev/tpm* 2>/dev/null || echo "(no /dev/tpm*)"
echo "--- TPM tools present? ---"
command -v tpm2_quote >/dev/null 2>&1 && echo "tpm2-tools present" || echo "tpm2-tools MISSING"
echo "--- TPM persistent handles ---"
command -v tpm2_getcap >/dev/null 2>&1 && tpm2_getcap handles-persistent 2>/dev/null || echo "(cannot list handles)"
echo "--- Secure Boot state ---"
if command -v mokutil >/dev/null 2>&1; then
  mokutil --sb-state 2>/dev/null || echo "(mokutil failed)"
elif command -v bootctl >/dev/null 2>&1; then
  bootctl status 2>/dev/null | grep -i 'Secure Boot' || echo "(bootctl line not found)"
else
  echo "(no mokutil or bootctl)"
fi
echo "--- attest journal (last 120 lines) ---"
journalctl -u attest -b --no-pager -n 120 2>/dev/null || echo "(no journal lines)"
echo "--- Failed units (attest or kubelet) ---"
systemctl --no-pager --failed 2>/dev/null | grep -E 'attest|kubelet' || echo "(none failed)"
echo "--- Dry run attest.sh (timeout {TIMEOUT}s) ---"
DRY_RC=0
if [ -x /opt/azure/containers/attest.sh ]; then
  if command -v bash >/dev/null 2>&1; then
    timeout {TIMEOUT}s bash -lc '/opt/azure/containers/attest.sh' || DRY_RC=$?
  else
    timeout {TIMEOUT}s /opt/azure/containers/attest.sh || DRY_RC=$?
  fi
  echo "dry_run_exit_code=$DRY_RC"
else
  echo "(attest.sh not executable)"
fi
echo "=== END_ATTEST_LOG_BLOCK ==="
'@
  return $tmpl.Replace('{TIMEOUT}', $DryTimeout.ToString())
}

# Build and cache remote script once
$RemoteScriptCache = Build-RemoteScript -DryTimeout $TimeoutSeconds
$RemoteTemp = [IO.Path]::GetTempFileName().Replace(".tmp",".sh")
Set-Content -Path $RemoteTemp -Value $RemoteScriptCache -Encoding UTF8

$nodeRG   = Resolve-NodeResourceGroup
$selected = Select-Nodes -Exact $NodeName -Prefix $NodePrefix -Regex $NodeRegex

# Concurrent bag for summary
$results = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()

function Invoke-Node {
  param([string]$NodeRG,[string]$NodeName,[hashtable]$Parsed,[string]$OutDir)
  $vmss = $Parsed.vmss; $iid = $Parsed.iid
  Write-Host "Invoking RunCommand for '$NodeName' (VMSS=$vmss IID=$iid)..."
  $raw = az vmss run-command invoke -g $NodeRG -n $vmss --instance-id $iid --command-id RunShellScript --scripts "@$RemoteTemp" 2>$null
  if (-not $raw) { Fail "RunCommand returned no output for node $NodeName" 4 }
  $json = $raw | ConvertFrom-Json
  $entry = $json.value[0]
  $msg = $entry.message
  Write-Host "Status: $($entry.displayStatus)"
  if (-not $msg) { Write-Warning "No message payload for $NodeName"; return }
  $m = [regex]::Match($msg,'(?s)=== START_ATTEST_LOG_BLOCK ===(.*?)=== END_ATTEST_LOG_BLOCK ===')
  $block = if ($m.Success) { $m.Groups[1].Value.Trim() } else { "(no attestation block found)" }
  $dryLine = ($block -split "`n" | Where-Object { $_ -match '^dry_run_exit_code=' }) | Select-Object -First 1
  $dryRC = if ($dryLine) { $dryLine -replace '.*=' } else { '' }

  Write-Host "---- Attestation Block (node $NodeName) ----"
  Write-Host $block

  if ($OutDir) {
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
    $safe = $NodeName -replace '[^a-zA-Z0-9._-]', '_'
    $stamp = (Get-Date -Format "yyyyMMdd-HHmmss")
    $blockPath = Join-Path $OutDir "$safe-$stamp-attest.log"
    $jsonPath  = Join-Path $OutDir "$safe-$stamp-runcommand.json"
    $block | Out-File -FilePath $blockPath -Encoding UTF8
    if ($IncludeRawJson) { $json | ConvertTo-Json -Depth 12 | Out-File -FilePath $jsonPath -Encoding UTF8 }
    Write-Host "Saved attestation block to $blockPath"
    if ($IncludeRawJson) { Write-Host "Saved full RunCommand JSON to $jsonPath" }
  }

  $intDry = 0
  if ([int]::TryParse($dryRC, [ref]$intDry)) { } else { $intDry = -1 }
  $results.Add([pscustomobject]@{
    Node          = $NodeName
    VMSS          = $vmss
    Instance      = $iid
    DryRunExitCode= $intDry
    DisplayStatus = $entry.displayStatus
  }) | Out-Null
}

# Execution (serial or experimental parallel)
if ($Parallel -and $selected.Count -gt 1) {
  Write-Host "Parallel collection enabled..."
  $parsedList = @()
  foreach ($n in $selected) { $parsedList += ,(@{ Node=$n; Parsed=Parse-ProviderId -Node $n }) }
  $parsedList | ForEach-Object -Parallel {
    Invoke-Node -NodeRG $using:nodeRG -NodeName $_.Node -Parsed $_.Parsed -OutDir $using:OutDir
  }
} else {
  foreach ($n in $selected) {
    $parsed = Parse-ProviderId -Node $n
    Invoke-Node -NodeRG $nodeRG -NodeName $n -Parsed $parsed -OutDir $OutDir
  }
}

Remove-Item -Force $RemoteTemp -ErrorAction SilentlyContinue

if ($Summary -and $results.Count -gt 0) {
  Write-Host ""
  Write-Host "Summary:"
  $results | Select-Object Node, VMSS, Instance, DryRunExitCode, DisplayStatus | Format-Table -AutoSize
}

Write-Host "Completed attestation diagnostics for $($selected.Count) node(s)."
exit 0
