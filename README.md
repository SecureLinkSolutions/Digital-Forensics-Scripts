# Snapshot Forensics

A small set of PowerShell scripts for fast, first-response triage on a Windows workstation during an incident. Each script is standalone and can be run on its own, or chained together with the orchestrator into a single timestamped incident folder.

Built for practitioner-level use: quick to run, CSV output for further analysis, no framework or install required beyond PowerShell itself.

## Scripts

| Script | Purpose | Admin required? | External API |
|---|---|---|---|
| `Snapshot Forensics Network Process Workstation.ps1` | Active network connections, owning processes (with parent process and SHA-256 hash), AbuseIPDB checks on public remote IPs, VirusTotal checks on process hashes, DNS cache, hosts file review | No | AbuseIPDB, VirusTotal (optional) |
| `Snapshot Forensics Persistence Execution Workstation.ps1` | Run/RunOnce keys, enabled scheduled tasks, auto-start services, startup folder items, Prefetch listing, Amcache.hve staging, ShimCache raw export, PowerShell Script Block Logging (4104), console history | Recommended | None |
| `Snapshot Forensics Identity Access Workstation.ps1` | Logon events (4624), failed logons (4625), special privilege logons (4672), local Administrators group membership, local user account overview | Recommended | None |
| `Snapshot Forensics DNS Hosts Workstation.ps1` | Standalone, fast DNS resolver cache + hosts file check (same data already captured inside the Network/Process script — kept separate for quick no-admin, no-API-wait checks) | No | None |
| `Snapshot Forensics Incident Orchestrator.ps1` | Runs the above scripts in sequence into one shared `IncidentSnapshot_<timestamp>` folder | Recommended | Uses whatever the Network/Process script has configured |

## Requirements

- Windows 10/11 or Windows Server, PowerShell 5.1 or later
- Run as Administrator for full results from the Persistence/Execution and Identity/Access scripts — they'll still run without it, but some sections (Prefetch, Amcache, ShimCache, some event log/service queries) will report failures instead of data
- Free API keys if you want the enrichment steps in the Network/Process script:
  - [AbuseIPDB](https://www.abuseipdb.com/account/api) — required for that script to run at all
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey) — optional, skip with `-SkipVirusTotal` if you don't have one

## Setup

1. Clone or download this repo into one folder — the orchestrator locates the other scripts by filename next to itself, so keep them together.
2. Open `Snapshot Forensics Network Process Workstation.ps1` and set your own keys near the top:

   ```powershell
   $AbuseIpdbApiKey = "your_key_here"
   $VirusTotalApiKey = "your_key_here"
   ```

   **Do not commit real API keys to a public repo.** If you fork or publish this, replace your keys with the placeholder text before pushing, or keep your populated copy in a private repo / out of version control (e.g. via `.gitignore`).

3. Scripts are unsigned by default. Either run with a relaxed execution policy for the session:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

   or self-sign them with your own code-signing certificate for repeated use. See [about_Execution_Policies](https://go.microsoft.com/fwlink/?LinkID=135170) for background.

## Usage

Run any script standalone:

```powershell
.\"Snapshot Forensics Network Process Workstation.ps1"
.\"Snapshot Forensics Persistence Execution Workstation.ps1"
.\"Snapshot Forensics Identity Access Workstation.ps1"
.\"Snapshot Forensics DNS Hosts Workstation.ps1"
```

Or run everything at once:

```powershell
.\"Snapshot Forensics Incident Orchestrator.ps1"
```

Useful orchestrator flags:

```powershell
# Fast pass, skip VirusTotal rate-limit waits
.\"Snapshot Forensics Incident Orchestrator.ps1" -SkipVirusTotal

# Only run persistence and identity checks
.\"Snapshot Forensics Incident Orchestrator.ps1" -SkipNetworkProcess

# Pull 30 days of logon history instead of the default 7
.\"Snapshot Forensics Incident Orchestrator.ps1" -DaysBack 30
```

Run `Get-Help .\"<script name>.ps1" -Full` on any individual script for its complete parameter list.

## Output

Each script writes timestamped CSVs (and a couple of raw artifact copies) to `-OutputDir` (defaults to the current directory). The orchestrator collects everything into one folder:

```
IncidentSnapshot_<timestamp>\
    01_NetworkProcess\
    02_PersistenceExecution\
    03_IdentityAccess\
    _orchestrator_run_log.csv
```

Note: `Amcache.hve` and the raw ShimCache registry export produced by the Persistence/Execution script are **staged, not parsed** — use a dedicated tool such as Eric Zimmerman's [AmcacheParser](https://ericzimmerman.github.io/) / [AppCompatCacheParser](https://ericzimmerman.github.io/) for full analysis of those artifacts.

## Scope and limitations

- These scripts collect evidence; they don't interpret it. Treat flagged items (AbuseIPDB score, VirusTotal detections, non-default hosts entries, failed logon spikes) as leads to investigate, not conclusions.
- Event log sections (4624/4625/4672/4104) return empty results if the relevant audit policy or Script Block Logging isn't enabled on the target host — that's expected, not a bug.
- Intended for use on systems you're authorized to investigate.

## License

Add a license of your choice before publishing (e.g. MIT) if you want others to reuse or modify these scripts.
