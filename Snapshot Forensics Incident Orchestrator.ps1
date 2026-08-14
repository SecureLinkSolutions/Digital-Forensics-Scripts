<#
.SYNOPSIS
    Runs all four Snapshot Forensics bundles (Network/Process, Persistence/
    Execution, Identity/Access, DNS/Hosts) into one shared, timestamped
    incident folder.

.DESCRIPTION
    Calls each standalone bundle script in turn, pointing its -OutputDir at
    a dedicated subfolder under one IncidentSnapshot_<timestamp> root:

        IncidentSnapshot_<timestamp>\
            01_NetworkProcess\
            02_PersistenceExecution\
            03_IdentityAccess\
            04_DnsHosts\

    Each bundle script is unchanged and can still be run standalone. This
    script just sequences them and gives you one folder to zip up and hand
    off. API keys for Bundle 1 (AbuseIPDB, VirusTotal) stay set inside that
    script itself, same as running it directly - nothing to pass in here.

    Any bundle can be skipped with its switch if you only need part of the
    picture, or if a script isn't present alongside this one.

.PARAMETER OutputDir
    Root folder the IncidentSnapshot_<timestamp> folder is created inside.
    Defaults to current directory.

.PARAMETER SkipNetworkProcess
    Skip Bundle 1 (netstat, process enrichment, AbuseIPDB, VirusTotal, DNS
    cache, hosts file).

.PARAMETER SkipPersistenceExecution
    Skip Bundle 2 (Run keys, scheduled tasks, services, startup folders,
    Prefetch, Amcache, ShimCache, PowerShell 4104, console history).

.PARAMETER SkipIdentityAccess
    Skip Bundle 3 (4624/4625/4672 logon events, local admin group, local
    user accounts).

.PARAMETER SkipDnsHosts
    Skip Bundle 4 (standalone DNS cache + hosts file - note this data is
    already captured inside Bundle 1, so skipping it here by default avoids
    duplication unless you want the fast standalone copy too).

.PARAMETER SkipVirusTotal
    Passed through to Bundle 1 - skip VirusTotal hash checks.

.PARAMETER DaysBack
    Passed through to Bundle 3 - how many days of logon events to pull.
    Default 7.

.PARAMETER MaxEvents
    Passed through to Bundle 3 - max events per event ID. Default 500.

.PARAMETER MaxScriptBlockEvents
    Passed through to Bundle 2 - max PowerShell 4104 events. Default 200.

.EXAMPLE
    .\"Snapshot Forensics Incident Orchestrator.ps1"

.EXAMPLE
    .\"Snapshot Forensics Incident Orchestrator.ps1" -SkipDnsHosts -SkipVirusTotal
#>

param(
    [string]$OutputDir = ".",
    [switch]$SkipNetworkProcess,
    [switch]$SkipPersistenceExecution,
    [switch]$SkipIdentityAccess,
    [switch]$SkipDnsHosts = $true,   # on by default: this data already lives inside Bundle 1
    [switch]$SkipVirusTotal,
    [int]$DaysBack = 7,
    [int]$MaxEvents = 500,
    [int]$MaxScriptBlockEvents = 200
)

$ErrorActionPreference = "Continue"

# --- Admin check (informational only - individual scripts degrade gracefully without it) ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Not running as Administrator. Bundle 2 (Prefetch/Amcache/ShimCache) and parts of" -ForegroundColor Yellow
    Write-Host "    Bundle 3 (event log / local group reads) work best elevated. Continuing anyway -" -ForegroundColor Yellow
    Write-Host "    affected sections will note failures individually rather than aborting." -ForegroundColor Yellow
    Write-Host ""
}

# --- Locate sibling bundle scripts next to this one ---
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$bundleScripts = @{
    NetworkProcess         = Join-Path $scriptDir "Snapshot Forensics Network Process Workstation.ps1"
    PersistenceExecution   = Join-Path $scriptDir "Snapshot Forensics Persistence Execution Workstation.ps1"
    IdentityAccess         = Join-Path $scriptDir "Snapshot Forensics Identity Access Workstation.ps1"
    DnsHosts               = Join-Path $scriptDir "Snapshot Forensics DNS Hosts Workstation.ps1"
}

# --- Create incident root folder ---
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$incidentDir = Join-Path $OutputDir "IncidentSnapshot_$timestamp"
New-Item -ItemType Directory -Path $incidentDir | Out-Null

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " Snapshot Forensics - Incident Orchestrator" -ForegroundColor Cyan
Write-Host " Incident folder: $incidentDir" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

$runLog = @()

function Invoke-Bundle {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [string]$SubfolderName,
        [hashtable]$ExtraParams = @{}
    )

    Write-Host "---------------------------------------------------------" -ForegroundColor Magenta
    Write-Host " Running: $Name" -ForegroundColor Magenta
    Write-Host "---------------------------------------------------------" -ForegroundColor Magenta

    if (-not (Test-Path $ScriptPath)) {
        Write-Host "[!] Script not found: $ScriptPath - skipping." -ForegroundColor Red
        $script:runLog += [PSCustomObject]@{ Bundle = $Name; Status = "SKIPPED - script not found"; Path = $ScriptPath }
        return
    }

    $subDir = Join-Path $incidentDir $SubfolderName
    New-Item -ItemType Directory -Path $subDir | Out-Null

    # Hashtable splatting (@paramHash) is required for named parameter binding.
    # Array splatting binds positionally and will NOT parse "-ParamName" tokens,
    # which is what caused values to land in the wrong parameter previously.
    $paramHash = @{ OutputDir = $subDir }
    foreach ($key in $ExtraParams.Keys) { $paramHash[$key] = $ExtraParams[$key] }

    try {
        & $ScriptPath @paramHash
        $script:runLog += [PSCustomObject]@{ Bundle = $Name; Status = "Completed"; Path = $subDir }
    } catch {
        Write-Host "[!] $Name failed: $($_.Exception.Message)" -ForegroundColor Red
        $script:runLog += [PSCustomObject]@{ Bundle = $Name; Status = "FAILED - $($_.Exception.Message)"; Path = $subDir }
    }
    Write-Host ""
}

# =========================================================================
# Bundle 1: Network + Process
# =========================================================================
if (-not $SkipNetworkProcess) {
    $extra = @{}
    if ($SkipVirusTotal) { $extra['SkipVirusTotal'] = $true }
    Invoke-Bundle -Name "Bundle 1: Network + Process" -ScriptPath $bundleScripts.NetworkProcess -SubfolderName "01_NetworkProcess" -ExtraParams $extra
} else {
    Write-Host "[*] Skipping Bundle 1: Network + Process (-SkipNetworkProcess)" -ForegroundColor DarkGray
    $runLog += [PSCustomObject]@{ Bundle = "Bundle 1: Network + Process"; Status = "SKIPPED - by parameter"; Path = "" }
}

# =========================================================================
# Bundle 2: Persistence + Execution
# =========================================================================
if (-not $SkipPersistenceExecution) {
    Invoke-Bundle -Name "Bundle 2: Persistence + Execution" -ScriptPath $bundleScripts.PersistenceExecution -SubfolderName "02_PersistenceExecution" -ExtraParams @{ MaxScriptBlockEvents = $MaxScriptBlockEvents }
} else {
    Write-Host "[*] Skipping Bundle 2: Persistence + Execution (-SkipPersistenceExecution)" -ForegroundColor DarkGray
    $runLog += [PSCustomObject]@{ Bundle = "Bundle 2: Persistence + Execution"; Status = "SKIPPED - by parameter"; Path = "" }
}

# =========================================================================
# Bundle 3: Identity + Access
# =========================================================================
if (-not $SkipIdentityAccess) {
    Invoke-Bundle -Name "Bundle 3: Identity + Access" -ScriptPath $bundleScripts.IdentityAccess -SubfolderName "03_IdentityAccess" -ExtraParams @{ DaysBack = $DaysBack; MaxEvents = $MaxEvents }
} else {
    Write-Host "[*] Skipping Bundle 3: Identity + Access (-SkipIdentityAccess)" -ForegroundColor DarkGray
    $runLog += [PSCustomObject]@{ Bundle = "Bundle 3: Identity + Access"; Status = "SKIPPED - by parameter"; Path = "" }
}

# =========================================================================
# Bundle 4: DNS + Hosts (standalone copy - off by default, duplicates Bundle 1)
# =========================================================================
if (-not $SkipDnsHosts) {
    Invoke-Bundle -Name "Bundle 4: DNS + Hosts (standalone)" -ScriptPath $bundleScripts.DnsHosts -SubfolderName "04_DnsHosts"
} else {
    Write-Host "[*] Skipping Bundle 4: DNS + Hosts (default - already captured in Bundle 1; use -SkipDnsHosts:`$false to include anyway)" -ForegroundColor DarkGray
    $runLog += [PSCustomObject]@{ Bundle = "Bundle 4: DNS + Hosts (standalone)"; Status = "SKIPPED - default (duplicates Bundle 1)"; Path = "" }
}

# =========================================================================
# Run log + summary
# =========================================================================
$runLogCsv = Join-Path $incidentDir "_orchestrator_run_log.csv"
$runLog | Export-Csv -Path $runLogCsv -NoTypeInformation -Encoding UTF8

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " Orchestrator Summary" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
$runLog | Format-Table -AutoSize
Write-Host ""
Write-Host "Full incident folder: $incidentDir" -ForegroundColor Green
Write-Host "Run log: $runLogCsv" -ForegroundColor Green
Write-Host "[*] Done." -ForegroundColor Green
