# Intune_Defender_MonthlyFullScan_v5.ps1
# Create monthly scheduled task: FIRST Saturday 02:00
# Task runs CMD wrapper -> Defender Full Scan
# Compatible /TR quoting (wrapper file)

$ErrorActionPreference = "Stop"

$TaskName = "Defender-Monthly-FullScan-FirstSat-0200"
$TaskTN   = "\$TaskName"

$BaseDir   = Join-Path $env:ProgramData "DefenderScan"
$RunnerCMD = Join-Path $BaseDir "run_fullscan.cmd"
$LogFile   = Join-Path $BaseDir "deploy_task_v5.log"

function Ensure-Dir { if (-not (Test-Path $BaseDir)) { New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null } }
function Log([string]$m) {
  Ensure-Dir
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  Add-Content -Path $LogFile -Value "[$ts] $m"
}

try {
  Ensure-Dir

  # 1) CMD wrapper (Defender Full Scan)
  # MpCmdRun.exe 우선, 없으면 PowerShell Start-MpScan fallback
  $cmd = @"
@echo off
setlocal
set MPCMD=%ProgramFiles%\Windows Defender\MpCmdRun.exe
if exist "%MPCMD%" (
  "%MPCMD%" -Scan -ScanType 2
  exit /b %ERRORLEVEL%
)
set MPCMD=%ProgramFiles%\Microsoft Defender\MpCmdRun.exe
if exist "%MPCMD%" (
  "%MPCMD%" -Scan -ScanType 2
  exit /b %ERRORLEVEL%
)
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-MpScan -ScanType FullScan"
exit /b %ERRORLEVEL%
"@

  Set-Content -Path $RunnerCMD -Value $cmd -Encoding ASCII -Force
  Log "RunnerCMD deployed => $RunnerCMD"

  # 2) Create task (월 1회: 첫째 토요일 02:00)
  # /F로 있으면 덮어쓰기, 없으면 생성
  $tr = "`"$RunnerCMD`""
  Log "Creating task => $TaskTN"
  $out = & schtasks.exe /Create /TN $TaskTN /SC MONTHLY /MO FIRST /D SAT /ST 02:00 /RU SYSTEM /RL HIGHEST /TR $tr /F 2>&1
  Log "Create output: $out"

  if ($LASTEXITCODE -ne 0) { throw "schtasks create failed (exit=$LASTEXITCODE): $out" }

  $verify = & schtasks.exe /Query /TN $TaskTN /V /FO LIST 2>&1
  Log "Verify output: $verify"

  Write-Output "OK: Task created => $TaskTN"
  exit 0
}
catch {
  Log "ERROR: $($_.Exception.Message)"
  Write-Output "ERROR: $($_.Exception.Message)"
  exit 1
}