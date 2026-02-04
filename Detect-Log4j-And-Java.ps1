<#
.SYNOPSIS
  Log4j 탐지(파일 목록) + JndiLookup 검사 + Java/Oracle JRE 버전 수집 스크립트

.DESCRIPTION
  - 모든 파일시스템 드라이브(고정 드라이브)에서 *.jar, *.war, *.ear 파일을 탐색하여 목록 생성
  - 7z(7-Zip)가 있으면 JAR 내부에서 JndiLookup.class 존재 여부를 검사하여 취약 후보 표시
  - 로컬/원격에서 Java/Oracle JRE 설치 버전 수집
  - 결과를 C:\secure_backup\<host>_scan_<ts>\ 아래 CSV 및 텍스트로 저장

.PARAMETER ComputerList
  원격 대상 서버 목록(호스트명 또는 IP)을 포함한 파일 경로(한 줄에 하나), 또는 배열로 직접 전달 가능.
  예: -ComputerList @("server1","server2") 또는 -ComputerList "C:\hosts.txt"

.EXAMPLE
  # 로컬 스캔
  .\Detect-Log4j-And-Java.ps1

  # 원격 여러대 스캔(PSRemoting 필요)
  .\Detect-Log4j-And-Java.ps1 -ComputerList @("vm-prod-01","vm-prod-02")

  # 파일에서 읽기
  .\Detect-Log4j-And-Java.ps1 -ComputerList "C:\temp\targets.txt"
#>

param(
  [Parameter(Mandatory=$false)]
  [string[]] $ComputerList
)

function Ensure-BackupFolder {
  param($HostName)
  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $base = "C:\secure_backup"
  if (-not (Test-Path $base)) { New-Item -Path $base -ItemType Directory -Force | Out-Null }
  $folder = Join-Path $base ("{0}_scan_{1}" -f $HostName, $ts)
  New-Item -Path $folder -ItemType Directory -Force | Out-Null
  return $folder
}

function Test-7z {
  $candidates = @(
    "C:\Program Files\7-Zip\7z.exe",
    "C:\Program Files (x86)\7-Zip\7z.exe"
  )
  foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
  # PATH에 있는지
  $which = (Get-Command 7z.exe -ErrorAction SilentlyContinue).Path
  if ($which) { return $which }
  return $null
}

function Scan-Local {
  param(
    [string] $HostName
  )
  $outdir = Ensure-BackupFolder -HostName $HostName
  $logFile = Join-Path $outdir "scan_log.txt"
  $jarReport = Join-Path $outdir "log4j_candidates.csv"
  $javaReport = Join-Path $outdir "java_versions.csv"

  "`n==== Scan started: $(Get-Date) ====" | Out-File $logFile -Append
  "Host: $HostName" | Out-File $logFile -Append

  $seven = Test-7z
  if ($seven) {
    "7z found: $seven" | Out-File $logFile -Append
  } else {
    "7z NOT found. JAR internal scan will be skipped. Install 7-Zip for deeper checking." | Out-File $logFile -Append
  }

  # 1) Drive list: 고정 드라이브만
  $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null -and $_.DisplayRoot -ne $null } 
  "Searching drives: $($drives.Name -join ', ')" | Out-File $logFile -Append

  $candidates = @()
  foreach ($d in $drives) {
    # 재귀 검색 (예외 무시)
    try {
      $items = Get-ChildItem -Path $d.Root -Recurse -ErrorAction SilentlyContinue -Force -Include *.jar,*.war,*.ear
      foreach ($it in $items) {
        $candidates += [PSCustomObject]@{
          FullName = $it.FullName
          DirectoryName = $it.DirectoryName
          Length = $it.Length
          LastWriteTime = $it.LastWriteTime
          ContainsJndiLookup = $false
        }
      }
    } catch {
      "Error scanning drive $($d.Root): $_" | Out-File $logFile -Append
    }
  }

  # Save preliminary list
  $candidates | Select FullName, DirectoryName, Length, LastWriteTime | Export-Csv -Path $jarReport -NoTypeInformation -Encoding UTF8

  # 2) If 7z available, inspect each jar for JndiLookup.class
  if ($seven -and $candidates.Count -gt 0) {
    Write-Output "Inspecting $($candidates.Count) archives for JndiLookup.class..."
    $idx = 0
    foreach ($row in $candidates) {
      $idx++
      if ($idx % 50 -eq 0) { "`nProcessed $idx / $($candidates.Count) files..." | Out-File $logFile -Append }
      $jar = $row.FullName
      if (Test-Path $jar) {
        try {
          # 7z l returns listing; search for JndiLookup.class
          $out = & $seven l -ba "$jar" 2>$null
          if ($out -match "JndiLookup.class") {
            $row.ContainsJndiLookup = $true
            "VULN CANDIDATE: $jar" | Out-File $logFile -Append
          }
        } catch {
          "Error inspecting $jar : $_" | Out-File $logFile -Append
        }
      }
    }
    # overwrite csv with ContainsJndiLookup
    $candidates | Select FullName, DirectoryName, Length, LastWriteTime, ContainsJndiLookup | Export-Csv -Path $jarReport -NoTypeInformation -Encoding UTF8
  } else {
    "Skipping internal jar inspection (7z not available or no candidates)" | Out-File $logFile -Append
  }

  # 3) Java / Oracle JRE detection
  $javaResults = @()

  # a) java.exe in PATH
  $javaCmd = (Get-Command java.exe -ErrorAction SilentlyContinue).Path
  if ($javaCmd) {
    try {
      $v = & java -version 2>&1
      $javaResults += [PSCustomObject]@{
        Source = "PATH"
        Executable = $javaCmd
        VersionRaw = ($v -join "`n")
      }
    } catch {
      $javaResults += [PSCustomObject]@{
        Source = "PATH"
        Executable = $javaCmd
        VersionRaw = "Error reading version: $_"
      }
    }
  }

  # b) 레지스트리: JavaSoft (64/32)
  $regPaths = @(
    'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
  )
  foreach ($rp in $regPaths) {
    try {
      $keys = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
      if ($keys -ne $null) {
        $current = $keys.CurrentVersion
        if ($current) {
          $verPath = Join-Path $rp $current
          $info = Get-ItemProperty -Path $verPath -ErrorAction SilentlyContinue
          $javaResults += [PSCustomObject]@{
            Source = $rp
            Executable = $info.JavaHome
            VersionRaw = $info.JavaVersion
          }
        } else {
          # enumerate subkeys
          Get-ChildItem -Path $rp -ErrorAction SilentlyContinue | ForEach-Object {
            $info = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            $javaResults += [PSCustomObject]@{
              Source = $rp
              Executable = $info.JavaHome
              VersionRaw = $info.JavaVersion
            }
          }
        }
      }
    } catch {
      # ignore
    }
  }

  # c) Uninstall registry identifiers for Oracle Java
  $uninstPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach ($up in $uninstPaths) {
    try {
      Get-ItemProperty -Path $up -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Java|JRE|JDK|Oracle" } |
        ForEach-Object {
          $javaResults += [PSCustomObject]@{
            Source = "UninstallReg"
            Executable = $_.InstallLocation
            VersionRaw = $_.DisplayVersion
          }
        }
    } catch { }
  }

  if ($javaResults.Count -eq 0) {
    $javaResults += [PSCustomObject]@{
      Source = "NoneDetected"
      Executable = ""
      VersionRaw = ""
    }
  }

  $javaResults | Export-Csv -Path $javaReport -NoTypeInformation -Encoding UTF8

  # Summary
  $summary = [PSCustomObject]@{
    Host = $HostName
    Time = (Get-Date).ToString()
    CandidateCount = $candidates.Count
    JndiCount = ($candidates | Where-Object { $_.ContainsJndiLookup } | Measure-Object).Count
    JavaEntries = $javaResults.Count
    OutputFolder = $outdir
  }
  $summary | ConvertTo-Json | Out-File (Join-Path $outdir "summary.json")

  "`n==== Scan finished: $(Get-Date) ====" | Out-File $logFile -Append
  return $outdir
}

# Main driver
$targets = @()
if ($ComputerList) {
  foreach ($c in $ComputerList) {
    if (Test-Path $c) {
      # 파일로 주어진 경우: 읽어서 추가
      $targets += Get-Content -Path $c | Where-Object { $_ -and $_.Trim().Length -gt 0 }
    } else {
      $targets += $c
    }
  }
}

if ($targets.Count -eq 0) {
  # 로컬 실행
  Write-Host "No ComputerList provided — running locally on $(hostname)" -ForegroundColor Cyan
  $out = Scan-Local -HostName (hostname)
  Write-Host "Results saved to: $out" -ForegroundColor Green
} else {
  # 원격 실행: PSRemoting 필요
  foreach ($t in $targets) {
    Write-Host "Scanning remote target: $t" -ForegroundColor Cyan
    try {
      $scriptBlock = {
        param($host)
        # Serialize the Scan-Local function body to remote session by copying the function definition
        $function:ScanLocal = (Get-Command -Name 'Scan-Local' -CommandType Function -ErrorAction SilentlyContinue)
        # Cannot easily transfer function: call the block that runs the same logic locally on remote
        # Instead, use an approach: write the script to a temp file on remote then execute it
        $script = ${function:Scan-Local}.ScriptBlock.ToString()
        # Fallback: run a small wrapper that writes invocation details to remote temp and runs local detection commands.
        # For simplicity, invoke a small inline script that calls Get-ChildItem and java checks (lighter)
        # NOTE: For full functionality, prefer running the script file remotely via Copy-Item then Invoke-Command -FilePath
      }
      # Simpler and more reliable: copy this script file to remote and run it (requires Admin rights & file share/PSRemoting)
      $localScriptPath = $MyInvocation.MyCommand.Path
      $remoteTemp = "\\$t\c$\temp\Detect-Log4j-Remote.ps1"
      Copy-Item -Path $localScriptPath -Destination $remoteTemp -Force -ErrorAction Stop
      Invoke-Command -ComputerName $t -ScriptBlock {
        param($p)
        Write-Host "Executing remote scan script: $p"
        & powershell.exe -ExecutionPolicy Bypass -File $p
      } -ArgumentList $remoteTemp -ErrorAction Stop
      Write-Host "Remote scan invoked on $t" -ForegroundColor Green
    } catch {
      Write-Host "Failed to scan $t : $_" -ForegroundColor Red
    }
  }
}