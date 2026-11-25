# netprobe

Network discovery from a Windows host where you have no admin rights and can't install
anything: a single PowerShell script that runs on the stock Windows PowerShell 5.1 and .NET
Framework. It's written for internal network penetration tests run from a client-provided
desktop (for example Azure Virtual Desktop), where nmap isn't an option.

It does:

- **ICMP echo sweep**
- **TCP connect scan**, with a banner grab on open ports, `HEAD /` on HTTP ports, and the TLS
  protocol and certificate (subject, issuer, expiry) on TLS ports
- **UDP probes** that elicit a reply: DNS `version.bind`, TFTP read of a missing file, NTP
  client request, NetBIOS node status, SNMP v2c `sysDescr.0` (community `public` by default),
  IPMI channel authentication capabilities, and the SQL Server Browser instance list

Every scan refuses to send anything unless all its targets fall inside the scope file you
load. Scans are rate-limited (connection attempts started per second) and bounded in
concurrency.

It's a connect scanner, not nmap: no SYN scan, no OS or version fingerprinting beyond what
banners show. It uses no exploits and does no credential guessing.

## Requirements

- Windows PowerShell 5.1 in FullLanguage mode (`$ExecutionContext.SessionState.LanguageMode`)
- .NET Framework 4.5 or later; `Add-Type` compiles the embedded C# on first load

## Getting it onto the host

Pin the URL to a commit so you run exactly what you reviewed. Type this in PowerShell on the
host (Windows PowerShell 5.1 needs TLS 1.2 turned on for GitHub):

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
iwr https://raw.githubusercontent.com/billm/netprobe/<commit>/netprobe.ps1 -OutFile np.ps1 -UseBasicParsing
(Get-FileHash np.ps1).Hash   # compare with: shasum -a 256 netprobe.ps1
. .\np.ps1
```

If the execution policy blocks loading a script file, start the session with
`powershell -ExecutionPolicy Bypass` (a per-process user setting).

## Use

Write two files on the host (Notepad is fine), one entry per line, with `#` comments allowed:

- `scope.txt`: the CIDRs/IPs you're authorized to test. Prefixes from /8 to /32.
- `targets.txt`: what to scan, as IPs or CIDRs. CIDRs larger than /31 skip their network and
  broadcast addresses.

```powershell
. .\np.ps1
Start-NpSession                          # optional: transcript of the session
Set-NpScope -Path .\scope.txt
$t = Get-NpTarget -Path .\targets.txt    # fails if any target is outside scope

Invoke-NpPing     -Targets $t
Invoke-NpTcpScan  -Targets $t            # 75 common ports
Invoke-NpUdpProbe -Targets $t

# All TCP ports on hosts that had something open
$csv = Get-ChildItem $HOME\Documents\netpen\*-tcp.csv | Select-Object -Last 1
$live = Import-Csv $csv.FullName | Select-Object -ExpandProperty Host -Unique
Invoke-NpTcpScan -Targets $live -Ports '1-65535'
```

| Command | Defaults | Main options |
|---|---|---|
| `Invoke-NpPing` | 20/s, 16 at a time, 1000 ms timeout | `-Rate -Concurrency -TimeoutMs` |
| `Invoke-NpTcpScan` | 50/s, 32 at a time, 1500 ms timeout, `$NpDefaultPorts` | `-Ports 22,80,'8000-8100'` or `'1-65535'`, `-NoGrab` |
| `Invoke-NpUdpProbe` | 20/s, 16 at a time, 2000 ms timeout, all probes | `-Probes snmp,ipmi`, `-Community` |

A full TCP sweep is slow on purpose: 65,535 ports on one host at 50/s is about 22 minutes.

## Output

Each scan writes to `$HOME\Documents\netpen\`:

- `<UTC stamp>-<scan>.csv`, written as results arrive, so a scan stopped with Ctrl+C keeps
  what it found. The TCP CSV holds open ports only; ping and UDP CSVs hold every probe.
- `<UTC stamp>-<scan>.txt`: the settings, and when the scan finishes, the state counts, the
  number of hosts that responded, and a per-host summary (also printed on screen).

UDP states: `open` (a reply), `closed` (ICMP port unreachable), `open|filtered` (no reply).
TCP states: `open`, `closed` (refused), `filtered` (timeout or other error).

## Testing

`test/check.sh` runs every check (needs Docker and the .NET SDK):

1. compiles the embedded C# as C# 5 against .NET Framework 4.5 reference assemblies, as
   `Add-Type` does on Windows PowerShell 5.1
2. PSScriptAnalyzer with Windows PowerShell 5.1 syntax compatibility
   (`PSScriptAnalyzerSettings.psd1`)
3. ruff on the lab's Python
4. `test/run-tests.ps1` in PowerShell 7 against a Docker lab: one host with SSH, nginx (HTTP
   and TLS), Redis, an FTP greeting, dnsmasq, tftp-hpa, chrony, net-snmp and canned
   NetBIOS/IPMI/SQL Browser responders; and one host with nothing listening

The lab runs on Linux, where unconnected UDP sockets don't see ICMP port unreachable, so the
`closed` UDP state is only exercised on Windows.
