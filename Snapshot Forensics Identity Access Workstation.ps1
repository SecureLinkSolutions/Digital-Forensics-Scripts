<#
.SYNOPSIS
    Incident response snapshot: identity and access activity on a Windows
    workstation.

.DESCRIPTION
    1. Pulls Security log logon events (4624), failed logons (4625), and
       special privilege assignments (4672), with logon type decoded to a
       human-readable label.
    2. Lists current local Administrators group membership.
    3. Lists local user accounts with enabled/disabled state, last logon,
       and password age, for spotting new or unexpected accounts.

    Exports timestamped CSVs into -OutputDir plus a console summary
    highlighting failed logons, remote/network logon types, and privileged
    logons - the signals most relevant to lateral movement or unauthorized
    access.

.PARAMETER OutputDir
    Folder to write output files to. Defaults to current directory.

.PARAMETER MaxEvents
    Max number of events to pull per event ID. Default 500.

.PARAMETER DaysBack
    Only pull events newer than this many days. Default 7.

.EXAMPLE
    .\"Snapshot Forensics Identity Access Workstation.ps1"
#>

param(
    [string]$OutputDir = ".",
    [int]$MaxEvents = 500,
    [int]$DaysBack = 7
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$evidenceDir   = Join-Path $OutputDir "evidence_identity_$timestamp"
New-Item -ItemType Directory -Path $evidenceDir | Out-Null

$logonCsv      = Join-Path $evidenceDir "logon_events_4624.csv"
$failedCsv     = Join-Path $evidenceDir "failed_logon_events_4625.csv"
$privCsv       = Join-Path $evidenceDir "special_privilege_events_4672.csv"
$adminCsv      = Join-Path $evidenceDir "local_administrators_group.csv"
$usersCsv      = Join-Path $evidenceDir "local_user_accounts.csv"

Write-Host "[*] Output folder for this snapshot: $evidenceDir" -ForegroundColor Cyan

$startTime = (Get-Date).AddDays(-$DaysBack)

# Logon type reference: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
$logonTypeMap = @{
    "2"  = "Interactive"
    "3"  = "Network"
    "4"  = "Batch"
    "5"  = "Service"
    "7"  = "Unlock"
    "8"  = "NetworkCleartext"
    "9"  = "NewCredentials"
    "10" = "RemoteInteractive (RDP)"
    "11" = "CachedInteractive"
}

# =========================================================================
# 1. Successful logons (4624)
# =========================================================================
Write-Host "[*] Collecting successful logon events (4624), last $DaysBack days ..." -ForegroundColor Cyan

try {
    $logonEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4624
        StartTime = $startTime
    } -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        $logonTypeVal = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'

        [PSCustomObject]@{
            TimeCreated     = $_.TimeCreated
            TargetUserName  = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            TargetDomain    = ($data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
            LogonType       = $logonTypeVal
            LogonTypeName   = $logonTypeMap[$logonTypeVal]
            IpAddress       = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            WorkstationName = ($data | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
            AuthPackage     = ($data | Where-Object { $_.Name -eq "AuthenticationPackageName" }).'#text'
            LogonProcess    = ($data | Where-Object { $_.Name -eq "LogonProcessName" }).'#text'
        }
    }
    $logonEvents = @($logonEvents)
    $logonEvents | Export-Csv -Path $logonCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($logonEvents.Count) logon events -> $logonCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read 4624 events: $($_.Exception.Message)" -ForegroundColor Yellow
    $logonEvents = @()
}

# =========================================================================
# 2. Failed logons (4625)
# =========================================================================
Write-Host "[*] Collecting failed logon events (4625), last $DaysBack days ..." -ForegroundColor Cyan

try {
    $failedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = $startTime
    } -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        $logonTypeVal = ($data | Where-Object { $_.Name -eq "LogonType" }).'#text'

        [PSCustomObject]@{
            TimeCreated     = $_.TimeCreated
            TargetUserName  = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            TargetDomain    = ($data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
            LogonType       = $logonTypeVal
            LogonTypeName   = $logonTypeMap[$logonTypeVal]
            IpAddress       = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            WorkstationName = ($data | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
            FailureReason   = ($data | Where-Object { $_.Name -eq "FailureReason" }).'#text'
            Status          = ($data | Where-Object { $_.Name -eq "Status" }).'#text'
            SubStatus       = ($data | Where-Object { $_.Name -eq "SubStatus" }).'#text'
        }
    }
    $failedEvents = @($failedEvents)
    $failedEvents | Export-Csv -Path $failedCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($failedEvents.Count) failed logon events -> $failedCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read 4625 events: $($_.Exception.Message)" -ForegroundColor Yellow
    $failedEvents = @()
}

# =========================================================================
# 3. Special privilege assignments (4672)
# =========================================================================
Write-Host "[*] Collecting special privilege logon events (4672), last $DaysBack days ..." -ForegroundColor Cyan

try {
    $privEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4672
        StartTime = $startTime
    } -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data

        [PSCustomObject]@{
            TimeCreated    = $_.TimeCreated
            SubjectUserName= ($data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
            SubjectDomain  = ($data | Where-Object { $_.Name -eq "SubjectDomainName" }).'#text'
            PrivilegeList  = ($data | Where-Object { $_.Name -eq "PrivilegeList" }).'#text'
        }
    }
    $privEvents = @($privEvents)
    $privEvents | Export-Csv -Path $privCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($privEvents.Count) special privilege events -> $privCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read 4672 events: $($_.Exception.Message)" -ForegroundColor Yellow
    $privEvents = @()
}

# =========================================================================
# 4. Local Administrators group membership
# =========================================================================
Write-Host "[*] Collecting local Administrators group membership ..." -ForegroundColor Cyan

try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Select-Object Name, PrincipalSource, ObjectClass
    $admins = @($admins)
    $admins | Export-Csv -Path $adminCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($admins.Count) members of local Administrators -> $adminCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read local Administrators group: $($_.Exception.Message)" -ForegroundColor Red
    $admins = @()
}

# =========================================================================
# 5. Local user accounts overview
# =========================================================================
Write-Host "[*] Collecting local user account overview ..." -ForegroundColor Cyan

try {
    $localUsers = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, SID
    $localUsers = @($localUsers)
    $localUsers | Export-Csv -Path $usersCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($localUsers.Count) local user accounts -> $usersCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read local user accounts: $($_.Exception.Message)" -ForegroundColor Red
    $localUsers = @()
}

# =========================================================================
# Summary
# =========================================================================
Write-Host ""
Write-Host "=== Identity + Access Summary (last $DaysBack days) ===" -ForegroundColor Green
Write-Host "Successful logons (4624)     : $($logonEvents.Count)"
Write-Host "Failed logons (4625)         : $($failedEvents.Count)"
Write-Host "Special privilege logons     : $($privEvents.Count)"
Write-Host "Local Administrators members : $($admins.Count)"
Write-Host "Local user accounts          : $($localUsers.Count)"

if ($failedEvents.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Failed logons by source IP / workstation (top 15) ===" -ForegroundColor Yellow
    $failedEvents |
        Group-Object -Property IpAddress, WorkstationName |
        Sort-Object Count -Descending |
        Select-Object -First 15 |
        Format-Table -AutoSize @{N="Count";E={$_.Count}}, @{N="IpAddress/Workstation";E={$_.Name}}
}

$remoteLogons = @($logonEvents | Where-Object { $_.LogonType -in @("3","10") -and $_.IpAddress -and $_.IpAddress -ne "-" })
if ($remoteLogons.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Remote/network successful logons (Network or RDP) ===" -ForegroundColor Yellow
    $remoteLogons | Sort-Object TimeCreated -Descending | Format-Table -AutoSize TimeCreated, TargetUserName, LogonTypeName, IpAddress, WorkstationName
}

Write-Host ""
Write-Host "=== Local Administrators group members ===" -ForegroundColor Yellow
$admins | Format-Table -AutoSize

Write-Host ""
Write-Host "All evidence written to: $evidenceDir" -ForegroundColor Cyan
Write-Host "[*] Done." -ForegroundColor Green
