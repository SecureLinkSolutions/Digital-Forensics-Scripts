<#
.SYNOPSIS
    Fast, standalone check of DNS resolver cache and hosts file - the same
    data captured in Bundle 1 (Network Process Workstation), pulled out on
    its own for quick triage runs that don't need process enrichment or API
    lookups.

.DESCRIPTION
    1. Dumps the current DNS client resolver cache.
    2. Reviews the hosts file for active (non-comment) entries and flags
       anything beyond the standard OS defaults (localhost / loopback
       mappings).

    No admin rights or API keys required. Exports CSVs into -OutputDir and
    prints a console summary.

.PARAMETER OutputDir
    Folder to write output files to. Defaults to current directory.

.EXAMPLE
    .\"Snapshot Forensics DNS Hosts Workstation.ps1"
#>

param(
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$dnsCacheCsv = Join-Path $OutputDir "dns_cache_$timestamp.csv"
$hostsCsv    = Join-Path $OutputDir "hosts_file_entries_$timestamp.csv"

# =========================================================================
# 1. DNS resolver cache
# =========================================================================
Write-Host "[*] Dumping DNS resolver cache ..." -ForegroundColor Cyan

$dnsCache = @()
try {
    $dnsCache = @(Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Data, TimeToLive, Type)
    $dnsCache | Export-Csv -Path $dnsCacheCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($dnsCache.Count) DNS cache entries -> $dnsCacheCsv" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read DNS cache: $($_.Exception.Message)" -ForegroundColor Red
}

# =========================================================================
# 2. Hosts file review
# =========================================================================
Write-Host "[*] Reviewing hosts file ..." -ForegroundColor Cyan

# Standard Windows default entries - anything beyond these is worth a second look
$defaultHostsPatterns = @(
    '^127\.0\.0\.1\s+localhost$',
    '^::1\s+localhost$'
)

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsEntries = @()
$nonDefaultEntries = @()

if (Test-Path $hostsPath) {
    $lines = Get-Content $hostsPath
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith("#")) {
            if ($trimmed -match '^(\S+)\s+(\S+)') {
                $entry = [PSCustomObject]@{
                    IPAddress = $matches[1]
                    Hostname  = $matches[2]
                    RawLine   = $trimmed
                }
                $hostsEntries += $entry

                $isDefault = $false
                foreach ($pattern in $defaultHostsPatterns) {
                    if ($trimmed -match $pattern) { $isDefault = $true; break }
                }
                if (-not $isDefault) { $nonDefaultEntries += $entry }
            }
        }
    }
    $hostsEntries = @($hostsEntries)
    $hostsEntries | Export-Csv -Path $hostsCsv -NoTypeInformation -Encoding UTF8
    Write-Host "    $($hostsEntries.Count) active (non-comment) entries -> $hostsCsv" -ForegroundColor DarkGray
} else {
    Write-Host "    [!] Hosts file not found at $hostsPath" -ForegroundColor Red
}

# =========================================================================
# Summary
# =========================================================================
Write-Host ""
Write-Host "=== DNS + Hosts Summary ===" -ForegroundColor Green
Write-Host "DNS cache entries         : $($dnsCache.Count)"
Write-Host "Hosts file active entries : $($hostsEntries.Count)"
Write-Host "Hosts entries beyond OS defaults : $($nonDefaultEntries.Count)"

if ($nonDefaultEntries.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Non-default hosts file entries - review these ===" -ForegroundColor Yellow
    $nonDefaultEntries | Format-Table -AutoSize
} else {
    Write-Host ""
    Write-Host "No non-default hosts file entries found." -ForegroundColor DarkGray
}

if ($dnsCache.Count -gt 0) {
    Write-Host ""
    Write-Host "=== DNS cache (most recent first not guaranteed - OS cache order) ===" -ForegroundColor Yellow
    $dnsCache | Where-Object { $_.Type -eq 1 } | Select-Object Name, Data, TimeToLive | Format-Table -AutoSize
}

Write-Host ""
Write-Host "[*] Done." -ForegroundColor Green
