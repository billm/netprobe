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

Show-NpSummary                           # every open service so far, grouped by check
$smb = Get-NpHost -Port 139, 445         # hosts for the next phase's checks
```

`Show-NpSummary` merges every scan's CSVs (partial runs included, each service listed once)
and groups open services by the checks they feed: SMB, LDAP, SSH, SNMP, databases, web, and
so on. It also lists each traced run with its start time, duration, probes finished, and
whether it completed or was killed. It saves the same text as `<UTC stamp>-summary.txt`.

| Command | Defaults | Main options |
|---|---|---|
| `Invoke-NpPing` | 20/s, 16 at a time, 1000 ms timeout | `-Rate -Concurrency -TimeoutMs` |
| `Invoke-NpTcpScan` | 50/s, 32 at a time, 1500 ms timeout, `$NpDefaultPorts` | `-Ports 22,80,'8000-8100'` or `'1-65535'`, `-NoGrab`, `-Resume` |
| `Invoke-NpUdpProbe` | 20/s, 16 at a time, 2000 ms timeout, all probes | `-Probes snmp,ipmi`, `-Community` |

A full TCP sweep is slow on purpose: 65,535 ports on one host at 50/s is about 22 minutes.

## Service checks

Per-host checks for the services discovery found. Each writes `<UTC stamp>-<check>.csv` one
row per host as it goes (a killed run keeps its rows) and a `.txt` summary, and takes
`-Resume` to skip hosts an earlier run of the same check recorded.

```powershell
Invoke-NpSmbCheck    -Targets (Get-NpHost -Port 445)
Invoke-NpLdapCheck   -Targets (Get-NpHost -Port 389)
Invoke-NpSmtpCheck   -Targets (Get-NpHost -Port 25)
Invoke-NpTelnetCheck -Targets (Get-NpHost -Port 23)
```

| Check | What it does |
|---|---|
| `Invoke-NpSmbCheck` | SMB2 NEGOTIATE (dialect; signing enabled or required) and SMB1 NEGOTIATE (supported, and its signing), no credentials. On Windows also `net use \\host\IPC$` with an empty user, then as `guest`, both with an empty password, listing shares through each connection that succeeds and removing it afterwards. `-NoLogon` skips the `net use` part |
| `Invoke-NpLdapCheck` | Anonymous bind; RootDSE (host name, naming context, domain and forest functional levels); an anonymous one-level search of the naming context (5 entries at most); one unsigned simple bind as a made-up `cn=netprobe-invalid-...` user: `strongerAuthRequired` (8) means the server requires signing, `invalidCredentials` (49) means it checked the credentials without requiring it. Channel binding needs valid credentials and isn't tested |
| `Invoke-NpSmtpCheck` | Greeting; EHLO (STARTTLS, AUTH); `VRFY root` against a random unknown user (different answers suggest user enumeration); `EXPN root`; `MAIL FROM:<netprobe@example.com>` and `RCPT TO:<netprobe@example.net>` (accepted means an open-relay candidate). Ends with RSET and QUIT before DATA, so no mail is sent |
| `Invoke-NpTelnetCheck` | Refuses every Telnet option the server offers and records the greeting and login prompt. Sends no credentials |

## Output

Each scan writes to `$HOME\Documents\netpen\`:

- `<UTC stamp>-<scan>.csv`, written as results arrive, so a scan stopped with Ctrl+C keeps
  what it found. The TCP CSV holds open ports only; ping and UDP CSVs hold every probe.
- `<UTC stamp>-<scan>.txt`: the settings, and when the scan finishes, the state counts, the
  number of hosts that responded, and a per-host summary (also printed on screen).

UDP states: `open` (a reply), `closed` (ICMP port unreachable), `open|filtered` (no reply).
TCP states: `open`, `closed` (refused), `filtered` (timeout or other error).

## When a scan dies

- `netprobe-crash.log` in the output folder records any exception that escapes netprobe's
  worker threads, the only way its own code can end the process. If PowerShell exits and this
  file doesn't exist, something outside netprobe ended it (EDR, for example).
- `-Trace` on any scan writes `<UTC stamp>-<scan>-trace.log`: a timestamped line as each probe
  starts and ends, flushed as written. After a kill, the `start` lines without a matching `end`
  are the probes in flight. Expect about 100 bytes per probe.
- `Invoke-NpTcpScan -Resume` skips every host:port probe that an earlier traced run finished,
  so a killed scan carries on where it stopped. It implies `-Trace`, so each resumed run can be
  resumed in turn.

```powershell
$log = Get-ChildItem $HOME\Documents\netpen\*-trace.log | Select-Object -Last 1
Get-Content $log.FullName -Tail 40
```

## Testing

`test/check.sh` runs every check (needs Docker and the .NET SDK):

1. compiles the embedded C# as C# 5 against .NET Framework 4.5 reference assemblies, as
   `Add-Type` does on Windows PowerShell 5.1
2. PSScriptAnalyzer with Windows PowerShell 5.1 syntax compatibility
   (`PSScriptAnalyzerSettings.psd1`)
3. ruff on the lab's Python
4. `test/run-tests.ps1` in PowerShell 7 against a Docker lab: one host with SSH, nginx (HTTP
   and TLS), Redis, FTP and SMTP (587) greetings, dnsmasq, tftp-hpa, chrony, net-snmp, Samba
   (signing mandatory, SMB1 off), OpenLDAP (anonymous read), busybox telnetd, an SMTP server
   on 25 that leaks users through VRFY and relays, and canned NetBIOS/IPMI/SQL Browser
   responders; and one host with nothing listening

The lab runs on Linux, so some paths are only exercised on Windows: the `closed` UDP state
(unconnected sockets there don't see ICMP port unreachable) and the `net use` null and guest
session checks.
