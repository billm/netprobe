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

if ($script:failures -gt 0) { Write-Host "$script:failures check(s) failed"; exit 1 }
Write-Host 'All checks passed'
