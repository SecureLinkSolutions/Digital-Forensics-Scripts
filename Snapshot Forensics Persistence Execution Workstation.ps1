<#
.SYNOPSIS
    Incident response snapshot: persistence mechanisms and execution
    evidence on a Windows workstation.

.DESCRIPTION
    Persistence:
    1. Registry Run / RunOnce keys (HKLM + HKCU, 32 and 64-bit views).
    2. Scheduled tasks that are enabled.
    3. Services configured to auto-start.
    4. Startup folder items (per-user and all-users).

    Execution evidence:
    5. Prefetch file listing (name, last run time, run count where parseable).
    6. Amcache.hve staged (copied out) for offline parsing with a dedicated
       tool (e.g. Eric Zimmerman's AmcacheParser) - this script does not
       parse the ESE/registry structure itself.
    7. AppCompatCache (ShimCache) registry value exported raw for offline
       parsing (e.g. AppCompatCacheParser) - binary format, not parsed here.
    8. PowerShell Script Block Logging events (Event ID 4104), if enabled.
    9. PSReadLine console history file, copied out if present.

    All findings are exported as timestamped CSVs (or copied raw files)
    into -OutputDir, with a console summary at the end.

.PARAMETER OutputDir
    Folder to write output files to. Defaults to current directory.

.PARAMETER MaxScriptBlockEvents
    Max number of PowerShell 4104 events to pull. Default 200.

.EXAMPLE
    .\"Snapshot Forensics Persistence Execution Workstation.ps1"
#>

param(
    [string]$OutputDir = ".",
    [int]$MaxScriptBlockEvents = 200
)

$ErrorActionPreference = "Continue"   # many of these checks are best-effort; don't abort the whole run on one failure

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp       = Get-Date -Format "yyyyMMdd_HHmmss"
$evidenceDir     = Join-Path $OutputDir "evidence_$timestamp"
New-Item -ItemType Directory -Path $evidenceDir | Out-Null

$runKeysCsv      = Join-Path $evidenceDir "persistence_run_keys.csv"
$tasksCsv        = Join-Path $evidenceDir "persistence_scheduled_tasks.csv"
$servicesCsv     = Join-Path $evidenceDir "persistence_autostart_services.csv"
$startupCsv      = Join-Path $evidenceDir "persistence_startup_folder_items.csv"
$prefetchCsv     = Join-Path $evidenceDir "execution_prefetch_listing.csv"
$scriptBlockCsv  = Join-Path $evidenceDir "execution_powershell_4104_events.csv"
$consoleHistOut  = Join-Path $evidenceDir "execution_console_history.txt"
$amcacheOut      = Join-Path $evidenceDir "Amcache.hve"
$shimcacheOut    = Join-Path $evidenceDir "AppCompatCache_raw.reg"

Write-Host "[*] Output folder for this snapshot: $evidenceDir" -ForegroundColor Cyan

# =========================================================================
# 1. Registry Run / RunOnce keys
# =========================================================================
Write-Host "[*] Collecting Run / RunOnce registry keys ..." -ForegroundColor Cyan

$runKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$runEntries = foreach ($path in $runKeyPaths) {
    if (Test-Path $path) {
        $key = Get-Item -Path $path
        foreach ($valueName in $key.GetValueNames()) {
            if ($valueName -ne "") {
                [PSCustomObject]@{
                    RegistryKey = $path
                    ValueName   = $valueName
                    Command     = $key.GetValue($valueName)
                }
            }
        }
    }
}
$runEntries | Export-Csv -Path $runKeysCsv -NoTypeInformation -Encoding UTF8
Write-Host "    $($runEntries.Count) Run/RunOnce entries -> $runKeysCsv" -ForegroundColor DarkGray

# =========================================================================
# 2. Scheduled tasks (enabled only)
# =========================================================================
Write-Host "[*] Collecting enabled scheduled tasks ..." -ForegroundColor Cyan

try {
    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            TaskName    = $_.TaskName
            TaskPath    = $_.TaskPath
            State       = $_.State
            Actions     = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | "
            Triggers    = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "
            LastRunTime = $info.LastRunTime
            NextRunTime = $info.NextRunTime
            Author      = $_.Author
        }
    }
    $tasks | Export-Csv -Path $tasksCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($tasks.Count) enabled scheduled tasks -> $tasksCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Failed to enumerate scheduled tasks: $($_.Exception.Message)" -ForegroundColor Red
}

# =========================================================================
# 3. Services set to auto-start
# =========================================================================
Write-Host "[*] Collecting auto-start services ..." -ForegroundColor Cyan

try {
    $services = Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | Select-Object Name, DisplayName, State, PathName, StartName, ProcessId
    $services | Export-Csv -Path $servicesCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($services.Count) auto-start services -> $servicesCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Failed to enumerate services: $($_.Exception.Message)" -ForegroundColor Red
}

# =========================================================================
# 4. Startup folder items (per-user + all-users)
# =========================================================================
Write-Host "[*] Collecting startup folder items ..." -ForegroundColor Cyan

$startupFolders = @(
    [Environment]::GetFolderPath("Startup"),
    [Environment]::GetFolderPath("CommonStartup")
)

$startupItems = @(foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Folder       = $folder
                FileName     = $_.Name
                FullPath     = $_.FullName
                LastWriteTime= $_.LastWriteTime
            }
        }
    }
})
$startupItems | Export-Csv -Path $startupCsv -NoTypeInformation -Encoding UTF8
Write-Host "    $($startupItems.Count) startup folder items -> $startupCsv" -ForegroundColor DarkGray

# =========================================================================
# 5. Prefetch listing
# =========================================================================
Write-Host "[*] Collecting Prefetch file listing ..." -ForegroundColor Cyan

$prefetchDir = "$env:SystemRoot\Prefetch"
$prefetchItems = @()
if (Test-Path $prefetchDir) {
    try {
        $prefetchItems = Get-ChildItem -Path $prefetchDir -Filter "*.pf" -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                FileName      = $_.Name
                CreatedTime   = $_.CreationTime
                LastWriteTime = $_.LastWriteTime
                SizeBytes     = $_.Length
            }
        }
        $prefetchItems | Export-Csv -Path $prefetchCsv -NoTypeInformation -Encoding UTF8
        Write-Host "    $($prefetchItems.Count) Prefetch files -> $prefetchCsv" -ForegroundColor DarkGray
        Write-Host "    (Filenames only - for run counts and embedded timestamps, parse .pf files with PECmd)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Could not list Prefetch (may require admin rights): $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [!] Prefetch directory not found or Prefetch is disabled on this system" -ForegroundColor Yellow
}

# =========================================================================
# 6. Amcache.hve staging (raw copy for offline parsing)
# =========================================================================
Write-Host "[*] Staging Amcache.hve for offline parsing ..." -ForegroundColor Cyan

$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $amcachePath) {
    try {
        Copy-Item -Path $amcachePath -Destination $amcacheOut -ErrorAction Stop
        Write-Host "    Amcache.hve copied -> $amcacheOut" -ForegroundColor DarkGray
        Write-Host "    (Parse offline with AmcacheParser or similar - not parsed by this script)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Could not copy Amcache.hve directly (file is likely locked): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    [*] Attempting copy via Volume Shadow Copy ..." -ForegroundColor Cyan
        try {
            $shadow = (Get-CimInstance -ClassName Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1)
            if ($shadow) {
                $shadowPath = $shadow.DeviceObject + "\Windows\AppCompat\Programs\Amcache.hve"
                # DeviceObject paths need the trailing backslash handled carefully
                $shadowPath = $shadow.DeviceObject.TrimEnd('\') + "\Windows\AppCompat\Programs\Amcache.hve"
                Copy-Item -Path $shadowPath -Destination $amcacheOut -ErrorAction Stop
                Write-Host "    Amcache.hve copied via existing shadow copy -> $amcacheOut" -ForegroundColor DarkGray
            } else {
                Write-Host "    [!] No existing Volume Shadow Copy found. Skipping Amcache staging." -ForegroundColor Yellow
                Write-Host "    [*] To capture it, create a shadow copy first (e.g. 'vssadmin create shadow /for=C:') and re-run." -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "    [!] Shadow copy fallback also failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    [!] Amcache.hve not found at expected path" -ForegroundColor Yellow
}

# =========================================================================
# 7. AppCompatCache (ShimCache) raw export
# =========================================================================
Write-Host "[*] Exporting AppCompatCache (ShimCache) registry key ..." -ForegroundColor Cyan

$shimcacheKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
try {
    # reg.exe needs the key path (which contains spaces) as a single quoted token.
    # Using cmd.exe /c with an explicitly quoted string avoids the argument-splitting
    # issue that Start-Process -ArgumentList runs into with embedded spaces.
    $regCommand = "reg.exe export `"$shimcacheKey`" `"$shimcacheOut`" /y"
    $output = cmd.exe /c $regCommand 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $shimcacheOut)) {
        Write-Host "    ShimCache key exported -> $shimcacheOut" -ForegroundColor DarkGray
        Write-Host "    (Binary AppCompatCache value inside - parse offline with AppCompatCacheParser)" -ForegroundColor DarkGray
    } else {
        Write-Host "    [!] reg export failed (exit code $LASTEXITCODE): $output" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not export ShimCache key: $($_.Exception.Message)" -ForegroundColor Red
}

# =========================================================================
# 8. PowerShell Script Block Logging (Event ID 4104)
# =========================================================================
Write-Host "[*] Collecting PowerShell Script Block Logging events (4104) ..." -ForegroundColor Cyan

try {
    $sbEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[EventID=4104]]" -MaxEvents $MaxScriptBlockEvents -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{N="ScriptBlockText";E={$_.Properties[2].Value}}, @{N="ScriptPath";E={$_.Properties[3].Value}}

    $sbEvents | Export-Csv -Path $scriptBlockCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($sbEvents.Count) script block events -> $scriptBlockCsv" -ForegroundColor DarkGray
    if ($sbEvents.Count -eq 0) {
        Write-Host "    (No events found - Script Block Logging may not be enabled on this host)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not read PowerShell Operational log (may not be enabled): $($_.Exception.Message)" -ForegroundColor Yellow
}

# =========================================================================
# 9. PSReadLine console history
# =========================================================================
Write-Host "[*] Copying PSReadLine console history ..." -ForegroundColor Cyan

$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    try {
        Copy-Item -Path $historyPath -Destination $consoleHistOut -ErrorAction Stop
        $lineCount = (Get-Content $consoleHistOut | Measure-Object -Line).Lines
        Write-Host "    Console history copied ($lineCount lines) -> $consoleHistOut" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Could not copy console history: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "    [!] No PSReadLine history file found for current user" -ForegroundColor Yellow
}

# =========================================================================
# Summary
# =========================================================================
Write-Host ""
Write-Host "=== Persistence + Execution Evidence Summary ===" -ForegroundColor Green
Write-Host "Run/RunOnce entries       : $($runEntries.Count)"
Write-Host "Enabled scheduled tasks   : $($tasks.Count)"
Write-Host "Auto-start services       : $($services.Count)"
Write-Host "Startup folder items      : $($startupItems.Count)"
Write-Host "Prefetch files            : $($prefetchItems.Count)"
Write-Host "PowerShell 4104 events    : $($sbEvents.Count)"
Write-Host ""
Write-Host "All evidence written to: $evidenceDir" -ForegroundColor Cyan
Write-Host "[*] Done." -ForegroundColor Green
