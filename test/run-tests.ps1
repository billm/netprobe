# Runs netprobe.ps1 against the Docker lab (test/compose.yaml) and checks what it reports.
# Exits non-zero on the first failed check.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lab = '172.30.99.10'
$empty = '172.30.99.11'
$tmp = Join-Path ([IO.Path]::GetTempPath()) 'netprobe-test'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$script:failures = 0

function Check {
  param([string]$Name, [scriptblock]$Test)
  try {
    $ok = & $Test
    if ($ok) { Write-Host "PASS  $Name" } else { Write-Host "FAIL  $Name"; $script:failures++ }
  } catch {
    Write-Host "FAIL  $Name : $($_.Exception.Message)"
    $script:failures++
  }
}

function Throws {
  param([scriptblock]$Block, [string]$Like)
  try { & $Block | Out-Null } catch { return $_.Exception.Message -like $Like }
  return $false
}

function Write-List {
  param([string]$Name, [string[]]$Lines)
  $path = Join-Path $tmp $Name
  Set-Content -LiteralPath $path -Value $Lines
  return $path
}

function Get-LatestOutput {
  param([string]$Pattern)
  return Get-ChildItem -Path $NpOutDir -Filter $Pattern | Sort-Object Name | Select-Object -Last 1
}

. /work/netprobe.ps1

Check 'scans refuse to run before a scope is loaded' {
  Throws { Invoke-NpPing -Targets @($lab) } '*No scope loaded*'
}

Set-NpScope -Path (Write-List 'scope.txt' @('# lab', '172.30.99.8/29', '172.30.99.10'))

Check 'scope rejects prefixes shorter than /8' {
  Throws { Set-NpScope -Path (Write-List 'bad-scope.txt' @('10.0.0.0/7')) } '*Refusing prefix /7*'
}
Check 'out-of-scope target in a targets file stops before any traffic' {
  $file = Write-List 'oos.txt' @($lab, '172.30.99.5')
  Throws { Get-NpTarget -Path $file } '*1 target(s) outside scope*172.30.99.5*'
}
Check 'out-of-scope target passed straight to a scan is refused' {
  Throws { Invoke-NpTcpScan -Targets @('8.8.8.8') -Ports 53 } '*outside scope*8.8.8.8*'
}
Check 'CIDR expands without network/broadcast and de-duplicates' {
  $file = Write-List 'cidr.txt' @('172.30.99.8/30', '172.30.99.10  # dup', '', '172.30.99.12/32')
  $t = Get-NpTarget -Path $file
  ($t -join ',') -eq '172.30.99.9,172.30.99.10,172.30.99.12'
}
Check 'port lists accept ranges and drop duplicates' {
  ((ConvertTo-NpPortList @('1-3', 2, '80,443')) -join ',') -eq '1,2,3,80,443'
}
Check 'invalid ports are rejected' {
  $bad = @(0, '70000', '9-3', 'ssh', '')
  @($bad | Where-Object { -not (Throws { ConvertTo-NpPortList $_ } '*port*') }).Count -eq 0
}

$targets = @($lab, $empty)

Invoke-NpPing -Targets $targets -Rate 100
$ping = Import-Csv (Get-LatestOutput '*-ping.csv').FullName
Check 'ping finds both lab hosts' { @($ping | Where-Object Status -eq 'Success').Count -eq 2 }

Invoke-NpTcpScan -Targets $targets -Ports @(21, 22, 80, 443, 6379, 1, 8080) -Rate 200
$tcpCsv = Get-LatestOutput '*-tcp.csv'
$tcp = @(Import-Csv $tcpCsv.FullName)
$byPort = @{}
foreach ($r in $tcp) { if ($r.Host -eq $lab) { $byPort[[int]$r.Port] = $r } }
Check 'TCP CSV holds only open ports, all on the lab host' {
  ($tcp.Count -eq 5) -and (@($tcp | Where-Object Host -ne $lab).Count -eq 0)
}
Check 'FTP greeting grabbed' { $byPort[21].Banner -like '220 netprobe-lab FTP*' }
Check 'SSH banner grabbed' { $byPort[22].Banner -like 'SSH-2.0-OpenSSH*' }
Check 'HTTP HEAD returns the nginx status line' {
  $byPort[80].Banner -like 'HTTP/1.1 200*Server: nginx*'
}
Check 'TLS certificate and protocol on 443' {
  ($byPort[443].TlsSubject -eq 'CN=lab.netprobe.test') -and
  ($byPort[443].TlsProtocol -like 'Tls1*') -and
  ($byPort[443].Banner -like 'HTTP/1.1 200*')
}
Check 'silent service (redis) is open with an empty banner' {
  ($byPort[6379].State -eq 'open') -and (-not $byPort[6379].Banner)
}
Check 'TCP summary counts closed ports and both responding hosts' {
  $txt = Get-Content ($tcpCsv.FullName -replace '\.csv$', '.txt') -Raw
  ($txt -match 'closed 9') -and ($txt -match 'open 5') -and ($txt -match 'hosts that responded: 2')
}

Invoke-NpUdpProbe -Targets $targets -Rate 100 -TimeoutMs 1500
$udp = @(Import-Csv (Get-LatestOutput '*-udp.csv').FullName)
$probe = @{}
foreach ($r in $udp) { if ($r.Host -eq $lab) { $probe[$r.Probe] = $r } }
Check 'UDP CSV has one row per host and probe' { $udp.Count -eq 14 }
Check 'DNS version.bind answered' { $probe['dns'].Detail -like 'rcode 0, answers 1, dnsmasq-*' }
Check 'TFTP error for a missing file' { $probe['tftp'].Detail -like 'error 1:*' }
Check 'NTP server answered' { $probe['ntp'].Detail -like 'version 3, stratum *' }
Check 'NetBIOS names and MAC parsed' {
  $probe['nbns'].Detail -eq 'LABHOST<00>U WORKGROUP<00>G LABHOST<20>U mac 02-42-0A-1E-63-0A'
}
Check 'SNMP sysDescr with community public' {
  $probe['snmp'].Detail -eq 'sysDescr: netprobe-lab snmpd'
}
Check 'IPMI auth capabilities parsed' {
  $expected = 'completion 00, IPMI 2.0, auth none/MD2/MD5/password, anonymous login enabled'
  $probe['ipmi'].Detail -eq $expected
}
Check 'SQL Server Browser instance list' {
  $probe['mssql'].Detail -like 'ServerName;LABSQL;*tcp;1433;;'
}
Check 'no reply from the empty host is open|filtered or closed, never open' {
  @($udp | Where-Object { $_.Host -eq $empty -and $_.State -eq 'open' }).Count -eq 0
}

Check 'a cancelled job stops promptly and keeps its CSV' {
  $o = New-NpScanOption -TypeName 'NetProbe.TcpOptions' -TimeoutMs 1500 -Concurrency 4 -Rate 5
  $csv = Join-Path $tmp 'cancel.csv'
  $job = [NetProbe.Scans]::Tcp([string[]]$targets, [int[]](1..1000), $o, $csv)
  Start-Sleep -Milliseconds 1500
  $job.Cancel()
  $stopped = $job.Wait(5000)
  $rows = @(Get-Content $csv)
  $stopped -and ($job.Done -lt $job.Total) -and ($rows[0] -like '"Host","Port",*')
}
Check 'rate limit holds: 40 connects at 20/s take about 2 s' {
  $o = New-NpScanOption -TypeName 'NetProbe.TcpOptions' -TimeoutMs 1500 -Concurrency 8 -Rate 20
  $o.Grab = $false
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $csv = Join-Path $tmp 'rate.csv'
  $job = [NetProbe.Scans]::Tcp([string[]]@($empty), [int[]](2000..2039), $o, $csv)
  [void]$job.Wait(30000)
  $s = $sw.Elapsed.TotalSeconds
  Write-Host ("      40 connects took {0:N2} s" -f $s)
  ($s -ge 1.8) -and ($s -lt 4)
}

Invoke-NpTcpScan -Targets $targets -Ports @(21, 587, 1) -Rate 200 -Trace
$traceCsv = Get-LatestOutput '*-tcp.csv'
$trace = @(Get-Content ($traceCsv.FullName -replace '\.csv$', '-trace.log'))
Check 'trace logs a start and an end for every probe, between job start and end' {
  $starts = @($trace | Where-Object { $_ -match ' start tcp ' })
  $ends = @($trace | Where-Object { $_ -match ' end tcp ' })
  ($trace[0] -match 'job start, 6 probes$') -and ($trace[-1] -match 'job end, 6 probes done$') -and
  ($starts.Count -eq 6) -and ($ends.Count -eq 6) -and
  (@($trace | Where-Object { $_ -match "end tcp ${lab}:587 open$" }).Count -eq 1)
}
Check 'SMTP submission greeting grabbed on 587' {
  $smtp = Import-Csv $traceCsv.FullName | Where-Object Port -eq '587'
  $smtp.Banner -like '220 netprobe-lab ESMTP*'
}

Check 'stress: 8,000 probes with grabs finish, with no crash log' {
  Invoke-NpTcpScan -Targets $targets -Ports '1-4000' -Rate 1000 -Concurrency 32 -Trace
  $csv = Get-LatestOutput '*-tcp.csv'
  $txt = Get-Content ($csv.FullName -replace '\.csv$', '.txt') -Raw
  $ends = @(Get-Content ($csv.FullName -replace '\.csv$', '-trace.log') |
      Where-Object { $_ -match ' end tcp ' })
  ($txt -match 'closed 7989, open 11') -and ($ends.Count -eq 8000) -and
  -not (Test-Path (Join-Path $NpOutDir 'netprobe-crash.log'))
}

Check 'an exception escaping a worker thread is written to the crash log' {
  $log = Join-Path $tmp 'child-crash.log'
  $child = Join-Path $tmp 'crash-child.ps1'
  Set-Content -LiteralPath $child -Value @'
. /work/netprobe.ps1
[NetProbe.CrashLog]::Install($args[0])
Add-Type -TypeDefinition @"
public static class Boom {
    public static void Go() {
        var t = new System.Threading.Thread(delegate() {
            throw new System.InvalidOperationException("netprobe crash test");
        });
        t.Start();
        t.Join();
    }
}
"@
[Boom]::Go()
'@
  & pwsh -NoProfile -File $child $log 2>&1 | Out-Null
  $logged = (Get-Content $log -Raw) -match 'InvalidOperationException: netprobe crash test'
  ($LASTEXITCODE -ne 0) -and $logged
}

function Get-TraceStart {
  $trace = Get-LatestOutput '*-tcp-trace.log'
  return (Get-Content -LiteralPath $trace.FullName -TotalCount 1)
}

Invoke-NpTcpScan -Targets $targets -Ports '30001-30010' -Trace -NoGrab -Rate 200
Invoke-NpTcpScan -Targets $targets -Ports '30001-30015' -Resume -NoGrab -Rate 200
Check 'resume skips probes an earlier traced run finished' {
  (Get-TraceStart) -match 'job start, 10 probes$'
}
Invoke-NpTcpScan -Targets $targets -Ports '30001-30015' -Resume -NoGrab -Rate 200
Check 'resume with nothing left finishes at once' { (Get-TraceStart) -match 'job start, 0 probes$' }

# A run killed mid-write: one probe finished, the next end line cut off.
Set-Content -LiteralPath (Join-Path $NpOutDir '20000101T000000000Z-tcp-trace.log') -Value @(
  '2000-01-01T00:00:00.000Z t1 job start, 3 probes',
  "2000-01-01T00:00:00.100Z t5 start tcp ${lab}:30100",
  "2000-01-01T00:00:00.200Z t5 end tcp ${lab}:30100 closed",
  "2000-01-01T00:01:15.500Z t6 start tcp ${lab}:30101",
  '2000-01-01T00:01:15.600Z t6 end tcp 172.30.9'
)
Invoke-NpTcpScan -Targets @($lab) -Ports '30100-30102' -Resume -NoGrab -Rate 200
Check 'resume ignores a truncated last line from a killed run' {
  $trace = Get-LatestOutput '*-tcp-trace.log'
  $lines = Get-Content -LiteralPath $trace.FullName
  $ends = ($lines | Where-Object { $_ -match ' end tcp ' }) -join ' '
  ((Get-TraceStart) -match 'job start, 2 probes$') -and ($ends -match ':30101 closed') -and
  ($ends -notmatch ':30100 ')
}

Check 'Get-NpHost lists hosts with a port open, across scans and protocols' {
  (((Get-NpHost -Port 22) -join ',') -eq $lab) -and
  (((Get-NpHost -Port 22, 587, 6379) -join ',') -eq $lab) -and
  (((Get-NpHost -Port 161 -Protocol udp) -join ',') -eq $lab) -and
  (@(Get-NpHost -Port 9).Count -eq 0)
}

Show-NpSummary
$summary = @(Get-Content -LiteralPath (Get-LatestOutput '*-summary.txt').FullName)
$text = $summary -join "`n"
Check 'summary reports a killed run with its duration and probe count' {
  $line = $summary | Where-Object { $_ -like '*20000101T000000000Z-tcp-trace.log*' }
  $line -match 'tcp 00:00:00-00:01:15Z\s+76 s\s+1 of 3\s+killed \(no end line\)'
}
Check 'summary reports completed traced runs' { $text -match '8000 of 8000\s+complete' }
Check 'summary groups services by check, merging TCP and UDP' {
  $ssh = "== SSH: versions, algorithms, auth methods: 1 host\(s\)\n\s+$lab\s+22/tcp SSH-2\.0"
  ($text -match $ssh) -and
  ($text -match "== DNS: 1 host\(s\)\n\s+$lab\s+53/tcp[^\n]*\n\s+$lab\s+53/udp rcode 0") -and
  ($text -match "== SNMP: 1 host\(s\)\n\s+$lab\s+161/udp sysDescr: netprobe-lab snmpd") -and
  ($text -match "== Web [^\n]*: 1 host\(s\)\n\s+$lab\s+80/tcp HTTP/1\.1 200") -and
  ($text -match "== MSSQL: 1 host\(s\)\n\s+$lab\s+1434/udp ServerName;LABSQL")
}
Check 'summary lists each open service once despite repeat scans' {
  @($summary | Where-Object { $_ -match "^\s+$lab\s+22/tcp " }).Count -eq 1
}

Invoke-NpSmbCheck -Targets $targets
$smb = @(Import-Csv (Get-LatestOutput '*-smb.csv').FullName)
$smbLab = $smb | Where-Object Host -eq $lab
$smbEmpty = $smb | Where-Object Host -eq $empty
Check 'SMB negotiate reads the dialect and mandatory signing (Samba)' {
  ($smbLab.Smb2Dialect -eq '3.0.2') -and ($smbLab.Smb2Signing -eq 'required') -and
  (-not $smbLab.Error)
}
Check 'SMB1 refused by a server with SMB1 off' { $smbLab.Smb1 -like 'no (*' }
Check 'null and guest checks are skipped off Windows, and say so' {
  ($smbLab.NullSession -eq 'not run (needs Windows)') -and
  ($smbLab.GuestSession -eq 'not run (needs Windows)')
}
Check 'SMB on a host with nothing listening records the error' {
  ($smbEmpty.Smb2Dialect -eq '') -and ($smbEmpty.Error -like 'smb2:*')
}
Invoke-NpSmbCheck -Targets $targets -Resume
Check 'SMB -Resume skips hosts already checked' {
  (Get-Content (Get-LatestOutput '*-smb.txt').FullName) -contains '# targets = 0'
}

Invoke-NpLdapCheck -Targets @($lab)
$ldap = Import-Csv (Get-LatestOutput '*-ldap.csv').FullName
Check 'LDAP anonymous bind and RootDSE naming context' {
  ($ldap.AnonymousBind -eq 'allowed') -and ($ldap.NamingContext -eq 'dc=netprobe,dc=test')
}
Check 'LDAP anonymous search of the naming context is reported' {
  $ldap.AnonymousSearch -eq 'allowed: 1 entries returned (limit 5)'
}
Check 'LDAP unsigned simple bind with made-up credentials gets invalidCredentials' {
  $ldap.UnsignedSimpleBind -like 'signing not required (invalid credentials checked): code 49*'
}

Invoke-NpSmtpCheck -Targets @($lab)
$smtp = Import-Csv (Get-LatestOutput '*-smtp.csv').FullName
Check 'SMTP greeting, EHLO and STARTTLS' {
  ($smtp.Banner -eq '220 netprobe-lab ESMTP fake') -and ($smtp.StartTls -eq 'True') -and
  ($smtp.Ehlo -like '250-netprobe-lab | *250 SIZE 10240000')
}
Check 'SMTP VRFY user enumeration and relay candidate detected' {
  ($smtp.UserEnum -eq 'likely: VRFY root 252, unknown user 550') -and
  ($smtp.Relay -eq 'candidate: external RCPT accepted') -and (-not $smtp.Error)
}

Invoke-NpTelnetCheck -Targets @($lab)
$telnet = Import-Csv (Get-LatestOutput '*-telnet.csv').FullName
Check 'Telnet greeting read after option negotiation' {
  ($telnet.Banner -match 'netprobe-lab telnet') -and ($telnet.Banner -match 'login:') -and
  (-not $telnet.Error)
}

if ($script:failures -gt 0) { Write-Host "$script:failures check(s) failed"; exit 1 }
Write-Host 'All checks passed'
