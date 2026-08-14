<#
.SYNOPSIS
    Incident response snapshot: network connections, owning processes (with
    parent process and file hash), AbuseIPDB checks on public remote IPs,
    VirusTotal checks on process hashes, DNS cache, and hosts file review.

.DESCRIPTION
    1. Runs netstat -ano, saves raw output.
    2. Parses connections into Proto / LocalAddress / LocalPort /
       RemoteAddress / RemotePort / State / PID.
    3. Enriches each PID with process name, path, command line, parent PID,
       parent process name, and SHA-256 hash of the executable.
    4. Checks non-RFC1918 remote IPs against AbuseIPDB.
    5. Checks unique process executable hashes against VirusTotal.
    6. Dumps current DNS resolver cache.
    7. Reviews the hosts file for entries beyond the OS defaults.
    8. Exports timestamped CSVs for each stage plus one combined report,
       and prints a console summary sorted by risk signal.

.PARAMETER OutputDir
    Folder to write output files to. Defaults to current directory.

.PARAMETER AbuseConfidenceMinScore
    Only show connections whose remote IP AbuseIPDB score is >= this value
    in the console summary. Default 0 (show all).

.PARAMETER ApiDelayMs
    Delay between AbuseIPDB calls, in milliseconds. Default 1500.

.PARAMETER VtDelayMs
    Delay between VirusTotal calls, in milliseconds. Default 15000 (safe for
    the free VT API tier, which allows ~4 requests/minute). Lower this if you
    have a paid VT tier.

.PARAMETER SkipVirusTotal
    Skip VirusTotal hash checks entirely (useful if you don't have a key yet
    or want a faster run).

.EXAMPLE
    .\"Snapshot Forensics Network Process Workstation.ps1"
#>

param(
    [string]$OutputDir = ".",
    [int]$AbuseConfidenceMinScore = 0,
    [int]$ApiDelayMs = 1500,
    [int]$VtDelayMs = 15000,
    [switch]$SkipVirusTotal
)

# --- Set your API keys here ---
# AbuseIPDB: https://www.abuseipdb.com/account/api
$AbuseIpdbApiKey = "YOUR_ABUSEIPDB_API_KEY_HERE"
# VirusTotal:  https://www.virustotal.com/gui/my-apikey
$VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY_HERE"

$ErrorActionPreference = "Stop"

if ($AbuseIpdbApiKey -eq "YOUR_ABUSEIPDB_API_KEY_HERE" -or [string]::IsNullOrWhiteSpace($AbuseIpdbApiKey)) {
    Write-Host "[!] Set your AbuseIPDB API key in `$AbuseIpdbApiKey near the top of this script before running." -ForegroundColor Red
    exit 1
}
if (-not $SkipVirusTotal -and ($VirusTotalApiKey -eq "YOUR_VIRUSTOTAL_API_KEY_HERE" -or [string]::IsNullOrWhiteSpace($VirusTotalApiKey))) {
    Write-Host "[!] Set your VirusTotal API key in `$VirusTotalApiKey, or re-run with -SkipVirusTotal." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$rawNetstat     = Join-Path $OutputDir "netstat_raw_$timestamp.txt"
$connCsv        = Join-Path $OutputDir "connections_processes_$timestamp.csv"
$abuseCsv       = Join-Path $OutputDir "abuseipdb_results_$timestamp.csv"
$vtCsv          = Join-Path $OutputDir "virustotal_results_$timestamp.csv"
$dnsCacheCsv    = Join-Path $OutputDir "dns_cache_$timestamp.csv"
$hostsCsv       = Join-Path $OutputDir "hosts_file_entries_$timestamp.csv"
$combinedCsv    = Join-Path $OutputDir "network_process_combined_$timestamp.csv"

# =========================================================================
# Step 1: netstat
# =========================================================================
Write-Host "[*] Running netstat -ano ..." -ForegroundColor Cyan
$rawOutput = netstat -ano
$rawOutput | Out-File -FilePath $rawNetstat -Encoding UTF8

$connections = foreach ($line in $rawOutput) {
    if ($line -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(\d+)\s*$') {
        $proto  = $matches[1]
        $local  = $matches[2]
        $remote = $matches[3]
        $state  = if ($proto -eq "TCP") { $matches[4] } else { "" }
        $procId = $matches[5]

        $localAddr, $localPort   = if ($local  -match '^\[(.+)\]:(\d+)$') { $matches[1], $matches[2] } else { $local  -split ':(?=\d+$)' }
        $remoteAddr, $remotePort = if ($remote -match '^\[(.+)\]:(\d+)$') { $matches[1], $matches[2] } else { $remote -split ':(?=\d+$)' }

        [PSCustomObject]@{
            Proto         = $proto
            LocalAddress  = $localAddr
            LocalPort     = $localPort
            RemoteAddress = $remoteAddr
            RemotePort    = $remotePort
            State         = $state
            PID           = [int]$procId
        }
    }
}
Write-Host "[*] Parsed $($connections.Count) connection entries" -ForegroundColor Cyan

# =========================================================================
# Step 2: process enrichment (name, path, parent, hash)
# =========================================================================
Write-Host "[*] Enriching processes (name, path, parent, SHA-256) ..." -ForegroundColor Cyan

$procInfoCache = @{}
$hashCache     = @{}

function Get-ProcInfo {
    param([int]$TargetPid)

    if ($procInfoCache.ContainsKey($TargetPid)) { return $procInfoCache[$TargetPid] }

    $info = [PSCustomObject]@{
        ProcessName   = "Unknown/Exited"
        ExecutablePath= ""
        CommandLine   = ""
        ParentPID     = $null
        ParentName    = "Unknown"
        SHA256        = ""
    }

    try {
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction Stop
        if ($cim) {
            $info.ProcessName    = $cim.Name
            $info.ExecutablePath = $cim.ExecutablePath
            $info.CommandLine    = $cim.CommandLine
            $info.ParentPID      = $cim.ParentProcessId

            try {
                $parentCim = Get-CimInstance Win32_Process -Filter "ProcessId=$($cim.ParentProcessId)" -ErrorAction Stop
                if ($parentCim) { $info.ParentName = $parentCim.Name }
            } catch {
                $info.ParentName = "Unknown/Exited"
            }

            if ($info.ExecutablePath -and (Test-Path $info.ExecutablePath)) {
                if ($hashCache.ContainsKey($info.ExecutablePath)) {
                    $info.SHA256 = $hashCache[$info.ExecutablePath]
                } else {
                    try {
                        $h = (Get-FileHash -Algorithm SHA256 -Path $info.ExecutablePath -ErrorAction Stop).Hash
                        $info.SHA256 = $h
                        $hashCache[$info.ExecutablePath] = $h
                    } catch {
                        $info.SHA256 = "HashError"
                    }
                }
            }
        }
    } catch {
        # process likely exited already, or access denied (common for protected system procs)
    }

    $procInfoCache[$TargetPid] = $info
    return $info
}

$enriched = $connections | ForEach-Object {
    $info = Get-ProcInfo -TargetPid $_.PID
    $_ | Add-Member -NotePropertyName ProcessName    -NotePropertyValue $info.ProcessName    -PassThru |
         Add-Member -NotePropertyName ExecutablePath -NotePropertyValue $info.ExecutablePath -PassThru |
         Add-Member -NotePropertyName CommandLine    -NotePropertyValue $info.CommandLine    -PassThru |
         Add-Member -NotePropertyName ParentPID      -NotePropertyValue $info.ParentPID      -PassThru |
         Add-Member -NotePropertyName ParentName     -NotePropertyValue $info.ParentName     -PassThru |
         Add-Member -NotePropertyName SHA256         -NotePropertyValue $info.SHA256         -PassThru
}

$enriched | Export-Csv -Path $connCsv -NoTypeInformation -Encoding UTF8
Write-Host "[*] Connection + process table saved to $connCsv" -ForegroundColor DarkGray

# =========================================================================
# Step 3: AbuseIPDB on public remote IPs (IPv4 + IPv6)
# =========================================================================
function Test-IsPublicIp {
    <#
        Returns $true only for globally routable IPv4/IPv6 addresses.
        Excludes RFC1918, loopback, link-local, 0.0.0.0/8, multicast, and
        broadcast for IPv4; excludes loopback, link-local (fe80::/10),
        unique local (fc00::/7), and multicast (ff00::/8) for IPv6.
        Windows IPv6 zone/scope suffixes (e.g. fe80::1%12) are stripped
        before matching.
    #>
    param([string]$IpAddress)

    if ([string]::IsNullOrWhiteSpace($IpAddress) -or $IpAddress -eq '*') { return $false }

    $addr = ($IpAddress -split '%')[0]

    if ($addr -match '^\d{1,3}(\.\d{1,3}){3}$') {
        # IPv4
        if ($addr -match '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|22[4-9]\.|23[0-9]\.|255\.)') {
            return $false
        }
        return $true
    }
    elseif ($addr -match ':' -and $addr -match '^[0-9a-fA-F:]+$') {
        # IPv6
        if ($addr -eq '::' -or $addr -eq '::1') { return $false }     # unspecified / loopback
        if ($addr -match '^fe[89ab][0-9a-fA-F]') { return $false }    # link-local  fe80::/10
        if ($addr -match '^f[cd][0-9a-fA-F]{2}') { return $false }    # unique local fc00::/7
        if ($addr -match '^ff') { return $false }                     # multicast   ff00::/8
        return $true
    }
    else {
        return $false
    }
}

$publicIps = $enriched |
    Where-Object { Test-IsPublicIp $_.RemoteAddress } |
    Select-Object -ExpandProperty RemoteAddress -Unique

Write-Host "[*] Checking $($publicIps.Count) unique public IPs (IPv4 + IPv6) against AbuseIPDB ..." -ForegroundColor Cyan

$abuseResults = @()
$abuseHeaders = @{ "Key" = $AbuseIpdbApiKey; "Accept" = "application/json" }

foreach ($ip in $publicIps) {
    Write-Host "    [AbuseIPDB] $ip" -ForegroundColor Yellow
    try {
        $resp = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" -Headers $abuseHeaders -Method Get
        $abuseResults += [PSCustomObject]@{
            IPAddress            = $resp.data.ipAddress
            AbuseConfidenceScore = $resp.data.abuseConfidenceScore
            CountryCode          = $resp.data.countryCode
            ISP                  = $resp.data.isp
            Domain               = $resp.data.domain
            TotalReports         = $resp.data.totalReports
            LastReportedAt       = $resp.data.lastReportedAt
            IsTor                = $resp.data.isTor
            UsageType            = $resp.data.usageType
        }
    } catch {
        Write-Host "        [!] Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        $abuseResults += [PSCustomObject]@{
            IPAddress = $ip; AbuseConfidenceScore = "ERROR"; CountryCode = ""; ISP = ""
            Domain = ""; TotalReports = ""; LastReportedAt = ""; IsTor = ""; UsageType = $_.Exception.Message
        }
    }
    Start-Sleep -Milliseconds $ApiDelayMs
}
$abuseResults | Export-Csv -Path $abuseCsv -NoTypeInformation -Encoding UTF8
Write-Host "[*] AbuseIPDB results saved to $abuseCsv" -ForegroundColor DarkGray

# =========================================================================
# Step 4: VirusTotal on unique process hashes
# =========================================================================
$vtResults = @()

if (-not $SkipVirusTotal) {
    $uniqueHashes = $enriched | Where-Object { $_.SHA256 -and $_.SHA256 -ne "HashError" } | Select-Object -ExpandProperty SHA256 -Unique
    Write-Host "[*] Checking $($uniqueHashes.Count) unique executable hashes against VirusTotal ..." -ForegroundColor Cyan
    Write-Host "    (free VT tier is rate-limited, this may take a while - use -SkipVirusTotal to skip)" -ForegroundColor DarkGray

    $vtHeaders = @{ "x-apikey" = $VirusTotalApiKey }

    foreach ($hash in $uniqueHashes) {
        Write-Host "    [VirusTotal] $hash" -ForegroundColor Yellow
        try {
            $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers $vtHeaders -Method Get
            $stats = $resp.data.attributes.last_analysis_stats
            $vtResults += [PSCustomObject]@{
                SHA256        = $hash
                MeaningfulName= $resp.data.attributes.meaningful_name
                Malicious     = $stats.malicious
                Suspicious    = $stats.suspicious
                Undetected    = $stats.undetected
                Harmless      = $stats.harmless
                FirstSubmission = if ($resp.data.attributes.first_submission_date) {
                    (Get-Date "1970-01-01").AddSeconds($resp.data.attributes.first_submission_date)
                } else { "" }
                Reputation    = $resp.data.attributes.reputation
            }
        } catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 404) {
                $vtResults += [PSCustomObject]@{
                    SHA256 = $hash; MeaningfulName = ""; Malicious = ""; Suspicious = ""
                    Undetected = ""; Harmless = ""; FirstSubmission = ""; Reputation = "NOT FOUND IN VT"
                }
            } else {
                Write-Host "        [!] Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
                $vtResults += [PSCustomObject]@{
                    SHA256 = $hash; MeaningfulName = ""; Malicious = ""; Suspicious = ""
                    Undetected = ""; Harmless = ""; FirstSubmission = ""; Reputation = "ERROR: $($_.Exception.Message)"
                }
            }
        }
        Start-Sleep -Milliseconds $VtDelayMs
    }
    $vtResults | Export-Csv -Path $vtCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[*] VirusTotal results saved to $vtCsv" -ForegroundColor DarkGray
} else {
    Write-Host "[*] Skipping VirusTotal checks (-SkipVirusTotal)" -ForegroundColor DarkGray
}

# =========================================================================
# Step 5: DNS resolver cache
# =========================================================================
Write-Host "[*] Dumping DNS resolver cache ..." -ForegroundColor Cyan
try {
    $dnsCache = Get-DnsClientCache | Select-Object Entry, Name, Data, TimeToLive, Type
    $dnsCache | Export-Csv -Path $dnsCacheCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[*] DNS cache saved to $dnsCacheCsv ($($dnsCache.Count) entries)" -ForegroundColor DarkGray
} catch {
    Write-Host "    [!] Could not read DNS cache: $($_.Exception.Message)" -ForegroundColor Red
}

# =========================================================================
# Step 6: hosts file review
# =========================================================================
Write-Host "[*] Reviewing hosts file ..." -ForegroundColor Cyan
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsEntries = @()
if (Test-Path $hostsPath) {
    $lines = Get-Content $hostsPath
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -and -not $trimmed.StartsWith("#")) {
            if ($trimmed -match '^(\S+)\s+(\S+)') {
                $hostsEntries += [PSCustomObject]@{
                    IPAddress = $matches[1]
                    Hostname  = $matches[2]
                    RawLine   = $trimmed
                }
            }
        }
    }
    $hostsEntries | Export-Csv -Path $hostsCsv -NoTypeInformation -Encoding UTF8
    Write-Host "[*] Hosts file has $($hostsEntries.Count) active (non-comment) entries - saved to $hostsCsv" -ForegroundColor DarkGray
    if ($hostsEntries.Count -gt 0) {
        Write-Host "    [!] Non-default hosts entries found - review these:" -ForegroundColor Yellow
        $hostsEntries | Format-Table -AutoSize
    }
} else {
    Write-Host "    [!] Hosts file not found at $hostsPath" -ForegroundColor Red
}

# =========================================================================
# Step 7: combined report + console summary
# =========================================================================
$finalReport = foreach ($conn in $enriched) {
    $abuse = $abuseResults | Where-Object { $_.IPAddress -eq $conn.RemoteAddress }
    $vt    = $vtResults    | Where-Object { $_.SHA256 -eq $conn.SHA256 }

    $conn | Add-Member -NotePropertyName AbuseConfidenceScore -NotePropertyValue $(if ($abuse) { $abuse.AbuseConfidenceScore } else { "" }) -PassThru |
            Add-Member -NotePropertyName AbuseCountry          -NotePropertyValue $(if ($abuse) { $abuse.CountryCode } else { "" }) -PassThru |
            Add-Member -NotePropertyName AbuseISP              -NotePropertyValue $(if ($abuse) { $abuse.ISP } else { "" }) -PassThru |
            Add-Member -NotePropertyName VTMalicious            -NotePropertyValue $(if ($vt) { $vt.Malicious } else { "" }) -PassThru |
            Add-Member -NotePropertyName VTSuspicious           -NotePropertyValue $(if ($vt) { $vt.Suspicious } else { "" }) -PassThru |
            Add-Member -NotePropertyName VTReputation           -NotePropertyValue $(if ($vt) { $vt.Reputation } else { "" }) -PassThru
}
$finalReport | Export-Csv -Path $combinedCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "=== Summary: connections with public IPs (AbuseIPDB score >= $AbuseConfidenceMinScore) ===" -ForegroundColor Green
$finalReport |
    Where-Object { $_.AbuseConfidenceScore -ne "" -and $_.AbuseConfidenceScore -ge $AbuseConfidenceMinScore } |
    Sort-Object -Property AbuseConfidenceScore -Descending |
    Format-Table -AutoSize PID, ProcessName, ParentName, RemoteAddress, RemotePort, AbuseConfidenceScore, AbuseCountry, VTMalicious, VTReputation

if (-not $SkipVirusTotal) {
    Write-Host ""
    Write-Host "=== Summary: processes flagged by VirusTotal (malicious > 0) ===" -ForegroundColor Green
    $finalReport |
        Where-Object { $_.VTMalicious -ne "" -and $_.VTMalicious -gt 0 } |
        Sort-Object -Property VTMalicious -Descending -Unique |
        Format-Table -AutoSize PID, ProcessName, ExecutablePath, SHA256, VTMalicious, VTReputation
}

Write-Host ""
Write-Host "[*] Combined report: $combinedCsv" -ForegroundColor Cyan
Write-Host "[*] Done." -ForegroundColor Green
