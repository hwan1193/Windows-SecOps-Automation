#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Test automation collector using osqueryi on Windows (no blocking/remediation)
  - Runs selected osquery SQLs
  - Saves raw JSON results per query
  - Heuristically flags suspicious items and collects related artifacts
  - Builds final report.json for later alerting

.USAGE
  Run as Administrator:
    powershell -ExecutionPolicy Bypass -File .\osquery_collect_pipeline.ps1

.NOTES
  Dependencies:
    - osqueryi.exe (default: C:\Program Files\osquery\osqueryi.exe)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Config ---
$OsqueryExe = $env:OSQUERYI_BIN
if ([string]::IsNullOrWhiteSpace($OsqueryExe)) {
  $OsqueryExe = 'C:\Program Files\osquery\osqueryi.exe'
}
$OutBase = if ($env:OUT_BASE) { $env:OUT_BASE } else { 'C:\sec\osquery_auto' }
$Timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$OutDir = Join-Path $OutBase $Timestamp
$ArtifactsDir = Join-Path $OutDir 'artifacts'
$SuspDir = Join-Path $OutDir 'suspicious'
$ReportJson = Join-Path $OutDir 'report.json'
$SuspiciousIndexJsonl = Join-Path $SuspDir 'suspicious_index.jsonl'
$ArtifactsIndexJsonl = Join-Path $SuspDir 'artifacts_index.jsonl'

# Ensure dirs
New-Item -ItemType Directory -Force -Path $OutDir, $ArtifactsDir, $SuspDir | Out-Null

# Dependency checks
if (-not (Test-Path $OsqueryExe)) {
  Write-Error "osqueryi.exe not found at '$OsqueryExe'. Set OSQUERYI_BIN env or install osquery."
}

# --- Query Set (Windows) ---
# NOTE: Queries chosen for Windows. Feel free to extend/tune.
$Queries = [ordered]@{
  host_info          = "SELECT hostname, name AS os_name, version, build, platform, install_date FROM os_version;";
  users              = "SELECT username, description, directory, shell FROM users WHERE username NOT IN ('WDAGUtilityAccount','DefaultAccount','Guest');";
  services_custom    = "SELECT name, path, state, start_type FROM services WHERE path NOT LIKE '%\\Windows\\System32\\%' AND path NOT LIKE '%\\Windows\\SysWOW64\\%' AND path NOT NULL;";
  scheduled_tasks    = "SELECT name, action, path, enabled, next_run_time FROM scheduled_tasks;";
  processes_tmp      = "SELECT pid, name, path, cmdline, username, start_time FROM processes WHERE path LIKE 'C:\\Windows\\Temp\\%' OR path LIKE 'C:\\Users\\%\\AppData\\Local\\Temp\\%';";
  listening_ports    = "SELECT pid, name, protocol, address, port FROM listening_ports;";
  external_sockets   = "SELECT pid, name, remote_address, remote_port, family, state FROM process_open_sockets WHERE remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '172.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '127.%';";
  # sensitive hives last modified (SAM/SYSTEM/SECURITY)
  hive_times         = "SELECT path, size, mtime, ctime FROM file WHERE path IN ('C:\\Windows\\System32\\config\\SAM','C:\\Windows\\System32\\config\\SYSTEM','C:\\Windows\\System32\\config\\SECURITY');";
  startup_items      = "SELECT name, path, args, source, username FROM startup_items;";
  # unsigned running binaries (heavier): join processes->authenticode
  unsigned_running   = "SELECT p.pid, p.name, p.path, a.result AS sig_result FROM processes p LEFT JOIN authenticode a ON p.path = a.path WHERE a.result NOT IN ('trusted','valid') OR a.result IS NULL;";
  windows_packages   = "SELECT name, version, publisher, install_location FROM windows_programs WHERE name LIKE '%OpenSSL%' OR name LIKE '%Docker%' OR name LIKE '%NGINX%' OR name LIKE '%Apache%';";
}

# --- Helpers ---
function Invoke-OsqueryJson {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Sql
  )
  $outFile = Join-Path $OutDir "$Name.json"
  Write-Host "[+] Running query: $Name"
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $OsqueryExe
  $psi.Arguments = "--json -S `"$Sql`""
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  if ($p.ExitCode -ne 0) {
    Write-Warning "osqueryi exited with code $($p.ExitCode) for $Name. stderr: $stderr"
  }
  # Some osquery builds may emit empty array for no rows -> ensure [] at least.
  if ([string]::IsNullOrWhiteSpace($stdout)) { $stdout = '[]' }
  $stdout | Out-File -Encoding UTF8 -FilePath $outFile
  return $outFile
}

function Write-Ndjson {
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Path
  )
  $json = $Object | ConvertTo-Json -Depth 6 -Compress
  Add-Content -LiteralPath $Path -Value $json
}

function Save-Artifact {
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [int64]$MaxBytes = 50MB
  )
  $rec = [ordered]@{ path = $FilePath }
  if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
    $rec.reason = 'missing'
    Write-Ndjson -Object $rec -Path $ArtifactsIndexJsonl
    return
  }
  try {
    $info = Get-Item -LiteralPath $FilePath -ErrorAction Stop
    if ($info.Length -gt $MaxBytes) {
      $rec.reason = "skipped_size_$($info.Length)"
      Write-Ndjson -Object $rec -Path $ArtifactsIndexJsonl
      return
    }
    $dest = Join-Path $ArtifactsDir $info.Name
    Copy-Item -LiteralPath $FilePath -Destination $dest -Force
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash
    $rec.collected = $dest
    $rec.sha256 = $hash
    Write-Ndjson -Object $rec -Path $ArtifactsIndexJsonl
  } catch {
    $rec.reason = "copy_error:$($_.Exception.Message)"
    Write-Ndjson -Object $rec -Path $ArtifactsIndexJsonl
  }
}

# --- Run queries ---
$report = [ordered]@{
  timestamp = $Timestamp
  results   = @{}
}

foreach ($kv in $Queries.GetEnumerator()) {
  $name = $kv.Key
  $sql  = $kv.Value
  $jsonPath = Invoke-OsqueryJson -Name $name -Sql $sql
  try {
    $data = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
  } catch {
    $data = @()
  }
  $report.results[$name] = $data
}

# --- Heuristics (no destructive action) ---
# Suspicious bucket
$suspicious = New-Object System.Collections.Generic.List[object]

# 1) Non-standard services -> collect their binaries if path looks like a file
foreach ($svc in $report.results.services_custom) {
  if ($null -ne $svc.path -and $svc.path -is [string] -and $svc.path.Trim() -ne '') {
    $s = [ordered]@{
      type  = 'service_custom_path'
      name  = $svc.name
      path  = $svc.path
      state = $svc.state
      start = $svc.start_type
    }
    $suspicious.Add([pscustomobject]$s)
    # Extract possible binary path from quoted path like: "C:\dir\app.exe" -arg1
    $bin = $svc.path
    if ($bin.StartsWith('"')) {
      $bin = $bin.Trim('"').Split('"')[0]
    } else {
      $bin = $bin.Split(' ')[0]
    }
    if ($bin -and $bin.EndsWith('.exe')) {
      Save-Artifact -FilePath $bin
    }
  }
}

# 2) Scheduled tasks -> record & try to save action binaries
foreach ($t in $report.results.scheduled_tasks) {
  $s = [ordered]@{
    type    = 'scheduled_task'
    name    = $t.name
    action  = $t.action
    path    = $t.path
    enabled = $t.enabled
  }
  $suspicious.Add([pscustomobject]$s)
  if ($t.action) {
    # Action string often like: C:\Windows\System32\cmd.exe /c "C:\path\run.bat"
    $first = $t.action.Trim().Trim('"').Split(' ')[0]
    if ($first -and (Test-Path $first)) { Save-Artifact -FilePath $first }
  }
}

# 3) Processes from temp dirs -> collect binaries
foreach ($p in $report.results.processes_tmp) {
  $s = [ordered]@{
    type     = 'temp_exec'
    pid      = $p.pid
    name     = $p.name
    path     = $p.path
    cmdline  = $p.cmdline
    user     = $p.username
    started  = $p.start_time
  }
  $suspicious.Add([pscustomobject]$s)
  if ($p.path) { Save-Artifact -FilePath $p.path }
}

# 4) External sockets -> record remote endpoints
foreach ($n in $report.results.external_sockets) {
  $s = [ordered]@{
    type   = 'external_socket'
    pid    = $n.pid
    name   = $n.name
    remote = "{0}:{1}" -f $n.remote_address, $n.remote_port
    state  = $n.state
  }
  $suspicious.Add([pscustomobject]$s)
}

# 5) Sensitive hives recent change (24h)
$now = Get-Date
foreach ($f in $report.results.hive_times) {
  if ($null -ne $f.mtime) {
    # osquery returns seconds since epoch or ISO. Handle both.
    $mtime = $null
    if ($f.mtime -is [double] -or $f.mtime -is [int]) {
      $mtime = [DateTimeOffset]::FromUnixTimeSeconds([int64]$f.mtime).LocalDateTime
    } else {
      [DateTime]::TryParse($f.mtime, [ref]$mtime) | Out-Null
    }
    if ($mtime -and ($now - $mtime).TotalHours -lt 24) {
      $s = [ordered]@{
        type  = 'hive_recent_change'
        path  = $f.path
        mtime = $mtime
      }
      $suspicious.Add([pscustomobject]$s)
      Save-Artifact -FilePath $f.path
    }
  }
}

# 6) Startup items
foreach ($si in $report.results.startup_items) {
  $s = [ordered]@{
    type  = 'startup_item'
    name  = $si.name
    path  = $si.path
    args  = $si.args
    src   = $si.source
    user  = $si.username
  }
  $suspicious.Add([pscustomobject]$s)
  if ($si.path -and (Test-Path $si.path)) { Save-Artifact -FilePath $si.path }
}

# 7) Unsigned (or unknown) running binaries
foreach ($u in $report.results.unsigned_running) {
  $s = [ordered]@{
    type       = 'unsigned_running'
    pid        = $u.pid
    name       = $u.name
    path       = $u.path
    sig_result = $u.sig_result
  }
  $suspicious.Add([pscustomobject]$s)
  if ($u.path) { Save-Artifact -FilePath $u.path }
}

# --- Final report assembly ---
# Persist suspicious ndjson + artifacts ndjson
Remove-Item -Force -ErrorAction SilentlyContinue $SuspiciousIndexJsonl, $ArtifactsIndexJsonl | Out-Null
foreach ($row in $suspicious) { Write-Ndjson -Object $row -Path $SuspiciousIndexJsonl }

# Build final JSON object
$final = [ordered]@{
  timestamp  = $Timestamp
  base       = $report
  suspicious = $suspicious
}

$final | ConvertTo-Json -Depth 8 | Out-File -Encoding UTF8 -FilePath $ReportJson

Write-Host "Result saved to: $OutDir"
Write-Host "Report: $ReportJson"
Write-Host "Suspicious: $SuspiciousIndexJsonl"
Write-Host "Artifacts index: $ArtifactsIndexJsonl"
Write-Host "[*] Done."