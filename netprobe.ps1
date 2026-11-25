<#
.SYNOPSIS
  netprobe: network discovery for Windows hosts without admin rights or installed tools.

.DESCRIPTION
  Dot-source this file in Windows PowerShell 5.1 (FullLanguage mode). It uses only the .NET
  Framework already on the host: ICMP echo, TCP connect scans with banner and TLS certificate
  grabs, and UDP protocol probes (DNS, TFTP, NTP, NetBIOS, SNMP, IPMI, SQL Server Browser).
  Every command refuses targets outside the CIDRs in the scope file.

  . .\netprobe.ps1
  Set-NpScope -Path .\scope.txt              # allowed CIDRs/IPs, one per line
  $t = Get-NpTarget -Path .\targets.txt      # IPs or CIDRs, expanded and checked against scope
  Invoke-NpPing     -Targets $t
  Invoke-NpTcpScan  -Targets $t               # common ports; -Ports '1-65535' for all
  Invoke-NpUdpProbe -Targets $t

  Output: $HOME\Documents\netpen\<UTC stamp>-<scan>.csv (written as results arrive) and .txt
  (settings, then a summary when the scan finishes).
#>

$NpOutDir = Join-Path $HOME 'Documents\netpen'
$script:NpScope = $null

$NpDefaultPorts = @(
  21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 512, 513,
  514, 515, 548, 587, 623, 631, 636, 873, 902, 993, 995, 1080, 1099, 1433, 1521, 1723, 2049,
  2121, 2375, 2376, 3000, 3128, 3268, 3269, 3306, 3389, 4786, 5000, 5432, 5601, 5800, 5900,
  5901, 5985, 5986, 6000, 6379, 6443, 7001, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000,
  9090, 9100, 9200, 9443, 10000, 11211, 27017, 50000
)
$NpTlsPorts = @(443, 465, 636, 993, 995, 3269, 5986, 6443, 8443, 9443)
$NpHttpPorts = @(80, 81, 443, 3000, 5000, 5601, 5985, 5986, 6443, 8000, 8008, 8080, 8081, 8443,
  8888, 9000, 9090, 9200, 9443, 10000)

# Service groups for Show-NpSummary, named for the methodology checks each one feeds.
$NpServiceGroups = @(
  @{ Name = 'FTP: anonymous login, versions'; Tcp = @(21, 2121); Udp = @() },
  @{ Name = 'SSH: versions, algorithms, auth methods'; Tcp = @(22); Udp = @() },
  @{ Name = 'Telnet and r-services (legacy, unencrypted)'; Tcp = @(23, 512, 513, 514); Udp = @() },
  @{ Name = 'SMTP: versions, encryption, user enum, relay'; Tcp = @(25, 465, 587); Udp = @() },
  @{ Name = 'DNS'; Tcp = @(53); Udp = @(53) },
  @{ Name = 'TFTP'; Tcp = @(); Udp = @(69) },
  @{ Name = 'Kerberos (likely domain controllers)'; Tcp = @(88); Udp = @() },
  @{ Name = 'POP3'; Tcp = @(110, 995); Udp = @() },
  @{ Name = 'IMAP'; Tcp = @(143, 993); Udp = @() },
  @{ Name = 'NFS and RPC'; Tcp = @(111, 2049); Udp = @() },
  @{ Name = 'NTP'; Tcp = @(); Udp = @(123) },
  @{ Name = 'SMB, MSRPC, NetBIOS: signing, null sessions, shares'; Tcp = @(135, 139, 445)
    Udp = @(137) },
  @{ Name = 'SNMP'; Tcp = @(); Udp = @(161) },
  @{ Name = 'LDAP: signing, channel binding, anonymous bind'; Tcp = @(389, 636, 3268, 3269)
    Udp = @() },
  @{ Name = 'IPMI'; Tcp = @(623); Udp = @(623) },
  @{ Name = 'Printers'; Tcp = @(515, 631, 9100); Udp = @() },
  @{ Name = 'MSSQL'; Tcp = @(1433); Udp = @(1434) },
  @{ Name = 'Oracle'; Tcp = @(1521); Udp = @() },
  @{ Name = 'MySQL'; Tcp = @(3306); Udp = @() },
  @{ Name = 'PostgreSQL'; Tcp = @(5432); Udp = @() },
  @{ Name = 'Redis'; Tcp = @(6379); Udp = @() },
  @{ Name = 'Other databases and caches'; Tcp = @(9200, 11211, 27017); Udp = @() },
  @{ Name = 'RDP'; Tcp = @(3389); Udp = @() },
  @{ Name = 'VNC'; Tcp = @(5800, 5900, 5901); Udp = @() },
  @{ Name = 'X11'; Tcp = @(6000); Udp = @() },
  @{ Name = 'WinRM'; Tcp = @(5985, 5986); Udp = @() },
  @{ Name = 'Docker and Kubernetes APIs'; Tcp = @(2375, 2376, 6443); Udp = @() },
  @{ Name = 'Web (apps, Tomcat, Jenkins, Webmin, phpMyAdmin)'; Udp = @()
    Tcp = @(80, 81, 443, 3000, 5000, 5601, 7001, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000,
      9090, 9443, 10000) }
)

$NpSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace NetProbe
{
    public interface ICsvRow { string[] Fields(); }

    public class ScanOptions
    {
        public int TimeoutMs = 1500;
        public int Concurrency = 32;
        public double Rate = 50;
        // When set, every probe's start and end is appended here as it happens.
        public string TracePath;
    }

    public class TcpOptions : ScanOptions
    {
        public bool Grab = true;
        public int[] TlsPorts = new int[0];
        public int[] HttpPorts = new int[0];
        // "host:port" probes finished in earlier runs; a resumed scan skips them.
        public HashSet<string> Skip;
    }

    public class UdpOptions : ScanOptions
    {
        public string Community = "public";
    }

    public class TcpResult : ICsvRow
    {
        public static readonly string[] Header = { "Host", "Port", "State", "Millis", "Banner",
            "TlsProtocol", "TlsSubject", "TlsIssuer", "TlsNotAfter", "Error" };
        public string Host; public int Port; public string State; public int Millis;
        public string Banner; public string TlsProtocol; public string TlsSubject;
        public string TlsIssuer; public string TlsNotAfter; public string Error;
        public string[] Fields()
        {
            return new[] { Host, Port.ToString(), State, Millis.ToString(), Banner, TlsProtocol,
                TlsSubject, TlsIssuer, TlsNotAfter, Error };
        }
    }

    public class UdpResult : ICsvRow
    {
        public static readonly string[] Header =
            { "Host", "Port", "Probe", "State", "Detail", "Error" };
        public string Host; public int Port; public string Probe; public string State;
        public string Detail; public string Error;
        public string[] Fields()
        {
            return new[] { Host, Port.ToString(), Probe, State, Detail, Error };
        }
    }

    public class PingResult : ICsvRow
    {
        public static readonly string[] Header = { "Host", "Status", "Millis", "Ttl" };
        public string Host; public string Status; public long Millis; public int Ttl;
        public string[] Fields()
        {
            return new[] { Host, Status, Millis.ToString(), Ttl.ToString() };
        }
    }

    // Runs probes on a fixed pool of worker threads, starting at most Rate per second, and
    // appends each kept result to a CSV file as it arrives.
    public class Job
    {
        public readonly int Total;
        public readonly ConcurrentDictionary<string, int> StateCounts =
            new ConcurrentDictionary<string, int>();
        public readonly ConcurrentDictionary<string, int> RespondingHosts =
            new ConcurrentDictionary<string, int>();
        public string LastError;

        readonly List<object> results = new List<object>();
        readonly object gate = new object();
        readonly ScanOptions options;
        readonly StreamWriter csv;
        readonly StreamWriter trace;
        readonly BlockingCollection<Func<object>> queue = new BlockingCollection<Func<object>>(1);
        IEnumerable<Func<object>> work;
        Thread feeder;
        Thread[] workers;
        volatile bool cancelled;
        bool closed;
        int done;

        public Job(int total, ScanOptions options, string csvPath, string[] header)
        {
            Total = total;
            this.options = options;
            csv = new StreamWriter(csvPath, false, new UTF8Encoding(false));
            csv.AutoFlush = true;
            csv.WriteLine(Csv.Line(header));
            if (options.TracePath != null)
            {
                trace = new StreamWriter(options.TracePath, false, new UTF8Encoding(false));
                trace.AutoFlush = true;
                Trace("job start, " + total + " probes");
            }
        }

        public int Done { get { return Volatile.Read(ref done); } }
        public bool IsComplete { get { return Wait(0); } }

        public object[] Results { get { lock (gate) { return results.ToArray(); } } }

        public void Count(string state, string host, bool responded)
        {
            StateCounts.AddOrUpdate(state, 1, delegate(string k, int v) { return v + 1; });
            if (responded) RespondingHosts.TryAdd(host, 1);
        }

        public void Trace(string what)
        {
            if (trace == null) return;
            string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                + " t" + Thread.CurrentThread.ManagedThreadId + " " + what;
            lock (trace) { if (!closed) trace.WriteLine(line); }
        }

        public void Start(IEnumerable<Func<object>> items)
        {
            work = items;
            feeder = new Thread(Feed);
            feeder.IsBackground = true;
            workers = new Thread[Math.Max(1, options.Concurrency)];
            for (int i = 0; i < workers.Length; i++)
            {
                workers[i] = new Thread(Consume);
                workers[i].IsBackground = true;
                workers[i].Start();
            }
            feeder.Start();
        }

        public void Cancel() { cancelled = true; }

        // Waits up to timeoutMs for every thread to finish; true when the job is complete.
        public bool Wait(int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            if (!feeder.Join(timeoutMs)) return false;
            foreach (var t in workers)
            {
                int left = Math.Max(0, timeoutMs - (int)sw.ElapsedMilliseconds);
                if (!t.Join(left)) return false;
            }
            lock (gate)
            {
                if (!closed)
                {
                    Trace("job end, " + Done + " probes done");
                    csv.Close();
                    if (trace != null) lock (trace) { trace.Close(); }
                    closed = true;
                }
            }
            return true;
        }

        void Feed()
        {
            double interval = options.Rate > 0 ? 1000.0 / options.Rate : 0;
            var sw = Stopwatch.StartNew();
            double next = 0;
            try
            {
                foreach (var item in work)
                {
                    if (cancelled) break;
                    while (sw.ElapsedMilliseconds < next) Thread.Sleep(1);
                    queue.Add(item);
                    next += interval;
                    // Don't burst to catch up after the workers were all busy.
                    if (sw.ElapsedMilliseconds > next + 1000) next = sw.ElapsedMilliseconds;
                }
            }
            finally { queue.CompleteAdding(); }
        }

        void Consume()
        {
            foreach (var item in queue.GetConsumingEnumerable())
            {
                if (!cancelled)
                {
                    try { Record(item()); }
                    catch (Exception e) { Count("error", "", false); LastError = e.ToString(); }
                }
                Interlocked.Increment(ref done);
            }
        }

        void Record(object r)
        {
            if (r == null) return;
            lock (gate)
            {
                results.Add(r);
                if (!closed) csv.WriteLine(Csv.Line(((ICsvRow)r).Fields()));
            }
        }
    }

    public static class Scans
    {
        public static Job Ping(string[] hosts, ScanOptions o, string csvPath)
        {
            var job = new Job(hosts.Length, o, csvPath, PingResult.Header);
            job.Start(PingWork(job, hosts, o));
            return job;
        }

        public static Job Tcp(string[] hosts, int[] ports, TcpOptions o, string csvPath)
        {
            int total = 0;
            foreach (var p in ports)
                foreach (var h in hosts)
                    if (!Skipped(o, h, p)) total++;
            var job = new Job(total, o, csvPath, TcpResult.Header);
            job.Start(TcpWork(job, hosts, ports, o));
            return job;
        }

        public static Job Udp(string[] hosts, string[] probes, UdpOptions o, string csvPath)
        {
            foreach (var p in probes) UdpProbe.PortFor(p);
            var job = new Job(hosts.Length * probes.Length, o, csvPath, UdpResult.Header);
            job.Start(UdpWork(job, hosts, probes, o));
            return job;
        }

        static bool Skipped(TcpOptions o, string host, int port)
        {
            return o.Skip != null && o.Skip.Contains(host + ":" + port);
        }

        static IEnumerable<Func<object>> PingWork(Job job, string[] hosts, ScanOptions o)
        {
            foreach (var h in hosts)
            {
                string host = h;
                yield return delegate
                {
                    job.Trace("start icmp " + host);
                    var r = IcmpProbe.Probe(host, o.TimeoutMs);
                    job.Trace("end icmp " + host + " " + r.Status);
                    job.Count(r.Status, host, r.Status == "Success");
                    return r;
                };
            }
        }

        // Ports in the outer loop spread each port's connects across hosts.
        static IEnumerable<Func<object>> TcpWork(Job job, string[] hosts, int[] ports, TcpOptions o)
        {
            foreach (var p in ports)
            {
                bool tls = Array.IndexOf(o.TlsPorts, p) >= 0;
                bool http = Array.IndexOf(o.HttpPorts, p) >= 0;
                foreach (var h in hosts)
                {
                    if (Skipped(o, h, p)) continue;
                    string host = h; int port = p;
                    yield return delegate
                    {
                        job.Trace("start tcp " + host + ":" + port);
                        var r = TcpProbe.Probe(host, port, o.TimeoutMs, o.Grab, tls, http);
                        job.Trace("end tcp " + host + ":" + port + " " + r.State);
                        bool responded = r.State == "open" || r.State == "closed";
                        job.Count(r.State, host, responded);
                        return r.State == "open" ? r : null;
                    };
                }
            }
        }

        static IEnumerable<Func<object>> UdpWork(
            Job job, string[] hosts, string[] probes, UdpOptions o)
        {
            foreach (var p in probes)
            {
                foreach (var h in hosts)
                {
                    string host = h; string probe = p;
                    yield return delegate
                    {
                        job.Trace("start udp " + host + " " + probe);
                        var r = UdpProbe.Probe(host, probe, o.TimeoutMs, o.Community);
                        job.Trace("end udp " + host + " " + probe + " " + r.State);
                        job.Count(r.State, host, r.State == "open" || r.State == "closed");
                        return r;
                    };
                }
            }
        }
    }

    public class SmbResult
    {
        public string Host; public string Smb2Dialect; public string Smb2Signing;
        public string Smb1; public string Smb1Signing; public string Error;
    }

    // SMB2 and SMB1 NEGOTIATE on 445: dialect, signing (enabled/required) and SMBv1 support.
    // Negotiation only: no session setup, no credentials.
    public static class SmbProbe
    {
        public static SmbResult Probe(string host, int timeoutMs)
        {
            var r = new SmbResult();
            r.Host = host;
            try { ParseSmb2(Exchange(host, timeoutMs, Smb2Negotiate()), r); }
            catch (Exception e) { r.Error = "smb2: " + e.Message; }
            try { ParseSmb1(Exchange(host, timeoutMs, Smb1Negotiate()), r); }
            catch (Exception e) { r.Smb1 = "no (" + e.Message + ")"; }
            return r;
        }

        static void ParseSmb2(byte[] b, SmbResult r)
        {
            if (b.Length > 4 && b[0] == 0xff && b[1] == (byte)'S')
            {
                r.Smb2Dialect = "none (server answered with SMB1)";
                return;
            }
            if (b.Length < 70 || b[0] != 0xfe || b[1] != (byte)'S')
                throw new InvalidDataException("not an SMB2 reply: " + Text.Hex(b, b.Length, 16));
            uint status = BitConverter.ToUInt32(b, 8);
            if (status != 0)
            {
                r.Smb2Dialect = "error 0x" + status.ToString("x8");
                return;
            }
            int mode = BitConverter.ToUInt16(b, 66);
            int dialect = BitConverter.ToUInt16(b, 68);
            r.Smb2Dialect = DialectName(dialect);
            r.Smb2Signing = Signing((mode & 0x02) != 0, (mode & 0x01) != 0);
        }

        static void ParseSmb1(byte[] b, SmbResult r)
        {
            if (b.Length > 4 && b[0] == 0xfe && b[1] == (byte)'S')
            {
                r.Smb1 = "no (server answered with SMB2)";
                return;
            }
            if (b.Length < 36 || b[0] != 0xff || b[1] != (byte)'S' || b[4] != 0x72)
                throw new InvalidDataException("not an SMB1 reply: " + Text.Hex(b, b.Length, 16));
            uint status = BitConverter.ToUInt32(b, 5);
            int index = BitConverter.ToUInt16(b, 33);
            if (status != 0 || b[32] != 17 || index == 0xffff)
            {
                r.Smb1 = "no (NT LM 0.12 refused, status 0x" + status.ToString("x8") + ")";
                return;
            }
            r.Smb1 = "yes (NT LM 0.12)";
            r.Smb1Signing = Signing((b[35] & 0x08) != 0, (b[35] & 0x04) != 0);
        }

        static string Signing(bool required, bool enabled)
        {
            if (required) return "required";
            return enabled ? "enabled, not required" : "disabled";
        }

        static string DialectName(int d)
        {
            switch (d)
            {
                case 0x0202: return "2.0.2";
                case 0x0210: return "2.1";
                case 0x0300: return "3.0";
                case 0x0302: return "3.0.2";
                case 0x0311: return "3.1.1";
                case 0x02ff: return "2.??";
            }
            return "0x" + d.ToString("x4");
        }

        static byte[] Smb2Negotiate()
        {
            var header = new byte[64];
            header[0] = 0xfe; header[1] = (byte)'S'; header[2] = (byte)'M'; header[3] = (byte)'B';
            header[4] = 64;   // StructureSize
            header[14] = 1;   // CreditRequest
            ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302 };
            var body = new MemoryStream();
            // StructureSize 36, dialect count, SecurityMode signing enabled, reserved, capabilities
            var fixedPart = new byte[] { 36, 0, (byte)dialects.Length, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
            body.Write(fixedPart, 0, fixedPart.Length);
            body.Write(Guid.NewGuid().ToByteArray(), 0, 16);
            body.Write(new byte[8], 0, 8);
            foreach (var d in dialects) body.Write(BitConverter.GetBytes(d), 0, 2);
            return NetBios(header, body.ToArray());
        }

        static byte[] Smb1Negotiate()
        {
            var header = new byte[32];
            header[0] = 0xff; header[1] = (byte)'S'; header[2] = (byte)'M'; header[3] = (byte)'B';
            header[4] = 0x72;                    // SMB_COM_NEGOTIATE
            header[9] = 0x18;                    // Flags: case-insensitive, canonical paths
            header[10] = 0x01; header[11] = 0xc8; // Flags2: long names, NT status, Unicode
            byte[] dialect = Encoding.ASCII.GetBytes("\u0002NT LM 0.12\u0000");
            var body = new MemoryStream();
            body.WriteByte(0); // WordCount
            body.Write(BitConverter.GetBytes((ushort)dialect.Length), 0, 2);
            body.Write(dialect, 0, dialect.Length);
            return NetBios(header, body.ToArray());
        }

        static byte[] NetBios(byte[] header, byte[] body)
        {
            int len = header.Length + body.Length;
            var packet = new byte[4 + len];
            packet[1] = (byte)(len >> 16); packet[2] = (byte)(len >> 8); packet[3] = (byte)len;
            Array.Copy(header, 0, packet, 4, header.Length);
            Array.Copy(body, 0, packet, 4 + header.Length, body.Length);
            return packet;
        }

        static byte[] Exchange(string host, int timeoutMs, byte[] request)
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                IAsyncResult ar = client.BeginConnect(IPAddress.Parse(host), 445, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    throw new TimeoutException("connect timeout");
                client.EndConnect(ar);
                client.ReceiveTimeout = timeoutMs;
                client.SendTimeout = timeoutMs;
                Stream s = client.GetStream();
                s.Write(request, 0, request.Length);
                byte[] nb = ReadExact(s, 4);
                int len = (nb[1] << 16) | (nb[2] << 8) | nb[3];
                if (len > 65536) throw new InvalidDataException("reply length " + len);
                return ReadExact(s, len);
            }
        }

        static byte[] ReadExact(Stream s, int n)
        {
            var b = new byte[n];
            int off = 0;
            while (off < n)
            {
                int k = s.Read(b, off, n - off);
                if (k <= 0) throw new IOException("connection closed");
                off += k;
            }
            return b;
        }
    }

    // Reads a Telnet server's greeting, refusing every option it offers (DO -> WONT,
    // WILL -> DONT), until a login prompt appears, the server goes quiet, or the timeout ends.
    public static class TelnetProbe
    {
        public static string Banner(string host, int port, int timeoutMs)
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                IAsyncResult ar = client.BeginConnect(IPAddress.Parse(host), port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    throw new TimeoutException("connect timeout");
                client.EndConnect(ar);
                NetworkStream s = client.GetStream();
                var text = new List<byte>();
                var buf = new byte[1024];
                var total = Stopwatch.StartNew();
                var idle = Stopwatch.StartNew();
                while (total.ElapsedMilliseconds < timeoutMs && text.Count < 600)
                {
                    if (!s.DataAvailable)
                    {
                        if (text.Count > 0 && idle.ElapsedMilliseconds > 1500) break;
                        Thread.Sleep(50);
                        continue;
                    }
                    int n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    idle.Restart();
                    byte[] reply = Negotiate(buf, n, text);
                    if (reply.Length > 0) s.Write(reply, 0, reply.Length);
                    string seen = Encoding.ASCII.GetString(text.ToArray());
                    if (seen.Contains("ogin:") || seen.Contains("assword:")) break;
                }
                byte[] all = text.ToArray();
                return Text.Clean(all, 0, all.Length, 600);
            }
        }

        static byte[] Negotiate(byte[] buf, int n, List<byte> text)
        {
            var reply = new MemoryStream();
            for (int i = 0; i < n; i++)
            {
                if (buf[i] != 0xff) { text.Add(buf[i]); continue; }
                if (i + 1 >= n) break;
                byte cmd = buf[++i];
                if (cmd >= 251 && cmd <= 254 && i + 1 < n)
                {
                    byte opt = buf[++i];
                    // Refuse everything: DO gets WONT, WILL gets DONT.
                    if (cmd == 253) reply.Write(new byte[] { 0xff, 252, opt }, 0, 3);
                    else if (cmd == 251) reply.Write(new byte[] { 0xff, 254, opt }, 0, 3);
                }
                else if (cmd == 250)
                {
                    // Subnegotiation: skip to IAC SE.
                    while (i + 1 < n && !(buf[i] == 0xff && buf[i + 1] == 240)) i++;
                    i++;
                }
            }
            return reply.ToArray();
        }
    }

    public class TraceRun
    {
        public string File; public string Kind; public DateTime Started; public DateTime Last;
        public int Total; public int Ended; public bool EndLine;
        public double Seconds { get { return (Last - Started).TotalSeconds; } }
        public string Outcome
        {
            get
            {
                if (!EndLine) return "killed (no end line)";
                return Ended >= Total ? "complete" : "stopped";
            }
        }
    }

    // Reads -Trace logs: one TraceRun per file, and every finished TCP probe ("host:port").
    // A process killed mid-write can leave a truncated last line; it is not counted.
    public static class TraceLog
    {
        public static List<TraceRun> Read(string[] paths, HashSet<string> doneTcp)
        {
            var runs = new List<TraceRun>();
            foreach (var path in paths)
            {
                var run = new TraceRun();
                run.File = Path.GetFileName(path);
                var share = FileShare.ReadWrite | FileShare.Delete;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, share))
                using (var reader = new StreamReader(fs))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null) Parse(line, run, doneTcp);
                }
                runs.Add(run);
            }
            return runs;
        }

        // <UTC time> t<thread> <event>, e.g. "... t7 end tcp 10.1.0.5:445 closed"
        static void Parse(string line, TraceRun run, HashSet<string> doneTcp)
        {
            string[] f = line.Split(' ');
            if (f.Length < 4) return;
            DateTime when;
            var styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
            if (!DateTime.TryParseExact(f[0], "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                CultureInfo.InvariantCulture, styles, out when)) return;
            if (run.Started == DateTime.MinValue) run.Started = when;
            run.Last = when;
            int n;
            if (f[2] == "job" && f[3] == "start," && f.Length > 4 && int.TryParse(f[4], out n))
                run.Total = n;
            else if (f[2] == "job" && f[3] == "end,")
                run.EndLine = true;
            else if (f[2] == "start" && run.Kind == null)
                run.Kind = f[3];
            else if (f[2] == "end" && f.Length >= 6)
            {
                run.Ended++;
                if (f[3] == "tcp" && doneTcp != null) doneTcp.Add(f[4]);
            }
        }
    }

    // Records any exception that escapes a worker thread. Such an exception ends the
    // process, so if the process dies with this log empty, something outside killed it.
    public static class CrashLog
    {
        static string logPath;

        public static void Install(string path)
        {
            if (logPath == null) AppDomain.CurrentDomain.UnhandledException += OnUnhandled;
            logPath = path;
        }

        static void OnUnhandled(object sender, UnhandledExceptionEventArgs e)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logPath));
            File.AppendAllText(logPath, DateTime.UtcNow.ToString("u")
                + " unhandled exception, process terminating: " + e.IsTerminating
                + Environment.NewLine + e.ExceptionObject + Environment.NewLine);
        }
    }

    public static class Csv
    {
        public static string Line(string[] fields)
        {
            var quoted = new string[fields.Length];
            for (int i = 0; i < fields.Length; i++)
                quoted[i] = "\"" + (fields[i] ?? "").Replace("\"", "\"\"") + "\"";
            return string.Join(",", quoted);
        }
    }

    public static class Text
    {
        public static string Clean(byte[] buf, int offset, int len, int max)
        {
            var sb = new StringBuilder();
            for (int i = offset; i < offset + len && i < buf.Length && sb.Length < max; i++)
            {
                byte b = buf[i];
                if (b == 13) sb.Append("\\r");
                else if (b == 10) sb.Append("\\n");
                else if (b == 9) sb.Append("\\t");
                else if (b >= 32 && b < 127) sb.Append((char)b);
                else sb.Append('.');
            }
            return sb.ToString();
        }

        public static string Hex(byte[] buf, int len, int max)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < len && i < max; i++) sb.Append(buf[i].ToString("x2"));
            return sb.ToString();
        }
    }

    public static class TcpProbe
    {
        public static TcpResult Probe(
            string host, int port, int timeoutMs, bool grab, bool tls, bool http)
        {
            var r = new TcpResult();
            r.Host = host; r.Port = port;
            var sw = Stopwatch.StartNew();
            var client = new TcpClient(AddressFamily.InterNetwork);
            try
            {
                IAsyncResult ar = client.BeginConnect(IPAddress.Parse(host), port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                {
                    r.State = "filtered"; r.Error = "timeout";
                    return r;
                }
                client.EndConnect(ar);
                r.State = "open"; r.Millis = (int)sw.ElapsedMilliseconds;
                if (grab) Grab(client, r, host, tls, http);
            }
            catch (SocketException e)
            {
                r.Millis = (int)sw.ElapsedMilliseconds;
                bool refused = e.SocketErrorCode == SocketError.ConnectionRefused;
                r.State = refused ? "closed" : "filtered";
                r.Error = e.SocketErrorCode.ToString();
            }
            catch (Exception e)
            {
                if (r.State == null) r.State = "error";
                r.Error = e.GetType().Name + ": " + e.Message;
            }
            finally { client.Close(); }
            return r;
        }

        static void Grab(TcpClient client, TcpResult r, string host, bool tls, bool http)
        {
            client.ReceiveTimeout = 3000;
            client.SendTimeout = 3000;
            Stream s = client.GetStream();
            if (tls)
            {
                try
                {
                    var ssl = new SslStream(s, false, delegate { return true; });
                    // TLS 1.0 | 1.1 | 1.2 as numbers: legacy hosts still need 1.0/1.1, and
                    // newer .NET marks those enum names obsolete.
                    ssl.AuthenticateAsClient(host, null, (SslProtocols)(192 | 768 | 3072), false);
                    r.TlsProtocol = ssl.SslProtocol.ToString();
                    if (ssl.RemoteCertificate != null)
                    {
                        var cert = new X509Certificate2(ssl.RemoteCertificate);
                        r.TlsSubject = cert.Subject;
                        r.TlsIssuer = cert.Issuer;
                        r.TlsNotAfter = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd");
                    }
                    s = ssl;
                }
                catch (Exception e)
                {
                    r.Error = "tls: " + e.Message;
                    return;
                }
            }
            if (http)
            {
                string head = "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n";
                byte[] req = Encoding.ASCII.GetBytes(head);
                try { s.Write(req, 0, req.Length); }
                catch (Exception e) { r.Error = "http: " + e.Message; return; }
            }
            r.Banner = ReadSome(s);
        }

        static string ReadSome(Stream s)
        {
            var buf = new byte[1024];
            try
            {
                int n = s.Read(buf, 0, buf.Length);
                return Text.Clean(buf, 0, n, 400);
            }
            catch (IOException) { return ""; }
            catch (ObjectDisposedException) { return ""; }
        }
    }

    public static class IcmpProbe
    {
        public static PingResult Probe(string host, int timeoutMs)
        {
            var r = new PingResult();
            r.Host = host;
            try
            {
                using (var p = new Ping())
                {
                    PingReply reply = p.Send(IPAddress.Parse(host), timeoutMs);
                    r.Status = reply.Status.ToString();
                    r.Millis = reply.RoundtripTime;
                    if (reply.Status == IPStatus.Success && reply.Options != null)
                        r.Ttl = reply.Options.Ttl;
                }
            }
            catch (Exception e) { r.Status = "error: " + e.Message; }
            return r;
        }
    }

    public static class UdpProbe
    {
        public static int PortFor(string probe)
        {
            switch (probe)
            {
                case "dns": return 53;
                case "tftp": return 69;
                case "ntp": return 123;
                case "nbns": return 137;
                case "snmp": return 161;
                case "ipmi": return 623;
                case "mssql": return 1434;
            }
            throw new ArgumentException("unknown UDP probe '" + probe + "'");
        }

        public static UdpResult Probe(string host, string probe, int timeoutMs, string community)
        {
            var r = new UdpResult();
            r.Host = host; r.Probe = probe; r.Port = PortFor(probe);
            var target = new IPEndPoint(IPAddress.Parse(host), r.Port);
            var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                sock.ReceiveTimeout = timeoutMs;
                sock.Bind(new IPEndPoint(IPAddress.Any, 0));
                sock.SendTo(Payload(probe, community), target);
                var buf = new byte[4096];
                var sw = Stopwatch.StartNew();
                while (sw.ElapsedMilliseconds < timeoutMs)
                {
                    EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                    int n = sock.ReceiveFrom(buf, ref from);
                    // TFTP answers from a new port, so match on the address only.
                    if (((IPEndPoint)from).Address.Equals(target.Address))
                    {
                        r.State = "open";
                        r.Detail = Parse(probe, buf, n);
                        return r;
                    }
                }
                r.State = "open|filtered";
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.TimedOut) r.State = "open|filtered";
                else if (e.SocketErrorCode == SocketError.ConnectionReset
                      || e.SocketErrorCode == SocketError.ConnectionRefused) r.State = "closed";
                else { r.State = "error"; r.Error = e.SocketErrorCode.ToString(); }
            }
            catch (Exception e)
            {
                r.State = "error";
                r.Error = e.GetType().Name + ": " + e.Message;
            }
            finally { sock.Close(); }
            return r;
        }

        static byte[] Payload(string probe, string community)
        {
            switch (probe)
            {
                case "dns":
                    // version.bind TXT CHAOS
                    return Concat(new byte[] { 0x4e, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 },
                        Label("version"), Label("bind"), new byte[] { 0, 0, 0x10, 0, 3 });
                case "tftp":
                    // read request for a file that should not exist
                    return Concat(new byte[] { 0, 1 },
                        Encoding.ASCII.GetBytes("netprobe-nonexistent.txt"), new byte[] { 0 },
                        Encoding.ASCII.GetBytes("octet"), new byte[] { 0 });
                case "ntp":
                    var ntp = new byte[48];
                    ntp[0] = 0x1b; // version 3, mode 3 (client)
                    return ntp;
                case "nbns":
                    // node status request for the wildcard name "*"
                    var name = new byte[34];
                    name[0] = 0x20; name[1] = (byte)'C'; name[2] = (byte)'K';
                    for (int i = 3; i < 33; i++) name[i] = (byte)'A';
                    return Concat(new byte[] { 0x4e, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 },
                        name, new byte[] { 0, 0x21, 0, 1 });
                case "snmp":
                    return SnmpGetSysDescr(community);
                case "ipmi":
                    // RMCP + IPMI 1.5 Get Channel Authentication Capabilities
                    return new byte[] {
                        0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5 };
                case "mssql":
                    return new byte[] { 0x02 }; // CLNT_BCAST_EX: list instances
            }
            throw new ArgumentException("unknown UDP probe '" + probe + "'");
        }

        static string Parse(string probe, byte[] b, int n)
        {
            try
            {
                switch (probe)
                {
                    case "mssql":
                        return n > 3 ? Text.Clean(b, 3, n - 3, 600) : Text.Hex(b, n, 64);
                    case "tftp":
                        if (n >= 4 && b[1] == 5)
                            return "error " + b[3] + ": " + Text.Clean(b, 4, n - 4, 100);
                        if (n >= 2 && b[1] == 3) return "DATA returned for a nonexistent file name";
                        return Text.Hex(b, n, 64);
                    case "ntp":
                        if (n < 48) return Text.Hex(b, n, 64);
                        string refid = b[1] <= 1 ? Encoding.ASCII.GetString(b, 12, 4).TrimEnd('\0')
                            : b[12] + "." + b[13] + "." + b[14] + "." + b[15];
                        return "version " + ((b[0] >> 3) & 7) + ", stratum " + b[1]
                            + ", refid " + refid;
                    case "nbns":
                        return ParseNodeStatus(b, n);
                    case "snmp":
                        return "sysDescr: " + ParseSnmpSysDescr(b, n);
                    case "dns":
                        return ParseVersionBind(b, n);
                    case "ipmi":
                        return ParseIpmi(b, n);
                }
            }
            catch (Exception e) { return "parse error (" + e.Message + "): " + Text.Hex(b, n, 64); }
            return Text.Hex(b, n, 64);
        }

        static string ParseVersionBind(byte[] b, int n)
        {
            int rcode = b[3] & 0x0f;
            int answers = (b[6] << 8) | b[7];
            string s = "rcode " + rcode + ", answers " + answers;
            // header 12 + question 18 + answer name pointer, type, class, ttl, rdlength 12:
            // the TXT length byte is at 42.
            if (answers > 0 && n > 43) s += ", " + Text.Clean(b, 43, Math.Min(b[42], n - 43), 200);
            return s;
        }

        static string ParseIpmi(byte[] b, int n)
        {
            // RMCP 4 + session 10 + message header 6, then completion code, channel, auth bytes.
            if (n < 25) return "IPMI response " + Text.Hex(b, n, 64);
            int cc = b[20], auth = b[22], ext = b[23];
            var types = new List<string>();
            if ((auth & 0x01) != 0) types.Add("none");
            if ((auth & 0x02) != 0) types.Add("MD2");
            if ((auth & 0x04) != 0) types.Add("MD5");
            if ((auth & 0x10) != 0) types.Add("password");
            if ((auth & 0x20) != 0) types.Add("OEM");
            return "completion " + cc.ToString("x2")
                + ", IPMI " + ((auth & 0x80) != 0 ? "2.0" : "1.5")
                + ", auth " + string.Join("/", types.ToArray())
                + ((ext & 0x01) != 0 ? ", anonymous login enabled" : "")
                + ((ext & 0x02) != 0 ? ", null user names enabled" : "");
        }

        static string ParseNodeStatus(byte[] b, int n)
        {
            int qd = (b[4] << 8) | b[5];
            int an = (b[6] << 8) | b[7];
            if (an == 0) return "no answer";
            int off = 12;
            for (int q = 0; q < qd; q++) off = SkipName(b, off) + 4;
            off = SkipName(b, off) + 10; // type, class, ttl, rdlength
            int count = b[off]; off++;
            var names = new List<string>();
            for (int i = 0; i < count && off + 18 <= n; i++)
            {
                string nm = Encoding.ASCII.GetString(b, off, 15).TrimEnd(' ', '\0');
                bool group = (b[off + 16] & 0x80) != 0;
                names.Add(nm + "<" + b[off + 15].ToString("x2") + ">" + (group ? "G" : "U"));
                off += 18;
            }
            string mac = off + 6 <= n ? " mac " + BitConverter.ToString(b, off, 6) : "";
            return string.Join(" ", names.ToArray()) + mac;
        }

        static int SkipName(byte[] b, int off)
        {
            while (true)
            {
                int len = b[off];
                if (len == 0) return off + 1;
                if ((len & 0xc0) == 0xc0) return off + 2;
                off += len + 1;
            }
        }

        static byte[] SnmpGetSysDescr(string community)
        {
            byte[] oid = { 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 }; // 1.3.6.1.2.1.1.1.0
            byte[] varbind = Tlv(0x30, Concat(Tlv(0x06, oid), new byte[] { 0x05, 0x00 }));
            byte[] pdu = Tlv(0xa0, Concat(Tlv(0x02, new byte[] { 0x4e, 0x50 }),
                Tlv(0x02, new byte[] { 0 }), Tlv(0x02, new byte[] { 0 }), Tlv(0x30, varbind)));
            return Tlv(0x30, Concat(Tlv(0x02, new byte[] { 1 }), // version 1 = SNMPv2c
                Tlv(0x04, Encoding.ASCII.GetBytes(community)), pdu));
        }

        static string ParseSnmpSysDescr(byte[] b, int n)
        {
            byte[] marker = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
            for (int i = 0; i + marker.Length + 2 <= n; i++)
            {
                bool hit = true;
                for (int j = 0; j < marker.Length && hit; j++) hit = b[i + j] == marker[j];
                if (!hit) continue;
                int off = i + marker.Length;
                if (b[off] != 0x04) return "value tag " + b[off].ToString("x2");
                int len = b[off + 1]; off += 2;
                if ((len & 0x80) != 0)
                {
                    int lenBytes = len & 0x7f; len = 0;
                    for (int k = 0; k < lenBytes; k++) len = (len << 8) | b[off + k];
                    off += lenBytes;
                }
                return Text.Clean(b, off, Math.Min(len, n - off), 300);
            }
            return "response without sysDescr: " + Text.Hex(b, n, 64);
        }

        static byte[] Tlv(byte tag, byte[] value)
        {
            byte[] len;
            if (value.Length < 128) len = new byte[] { (byte)value.Length };
            else if (value.Length < 256) len = new byte[] { 0x81, (byte)value.Length };
            else len = new byte[] { 0x82, (byte)(value.Length >> 8), (byte)value.Length };
            return Concat(new byte[] { tag }, len, value);
        }

        static byte[] Label(string s)
        {
            return Concat(new byte[] { (byte)s.Length }, Encoding.ASCII.GetBytes(s));
        }

        static byte[] Concat(params byte[][] parts)
        {
            var ms = new MemoryStream();
            foreach (var p in parts) ms.Write(p, 0, p.Length);
            return ms.ToArray();
        }
    }
}
'@

if (-not ('NetProbe.Job' -as [type])) {
  Add-Type -TypeDefinition $NpSource -Language CSharp
}
[NetProbe.CrashLog]::Install((Join-Path $NpOutDir 'netprobe-crash.log'))

function ConvertTo-NpUInt32 {
  param([Parameter(Mandatory = $true)][string]$Ip)
  $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
  if ($bytes.Length -ne 4) { throw "Not an IPv4 address: $Ip" }
  [Array]::Reverse($bytes)
  return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-NpUInt32 {
  param([Parameter(Mandatory = $true)][uint32]$Value)
  $bytes = [BitConverter]::GetBytes($Value)
  [Array]::Reverse($bytes)
  return (New-Object System.Net.IPAddress (, $bytes)).ToString()
}

function ConvertTo-NpRange {
  # "a.b.c.d" or "a.b.c.d/nn" -> @{ First; Last } as numbers.
  param([Parameter(Mandatory = $true)][string]$Entry)
  $parts = $Entry.Trim() -split '/'
  if ($parts.Count -gt 2) { throw "Not an IP or CIDR: '$Entry'" }
  $base = [uint64](ConvertTo-NpUInt32 $parts[0])
  $bits = 32
  if ($parts.Count -eq 2) { $bits = [int]$parts[1] }
  if ($bits -lt 8 -or $bits -gt 32) {
    throw "Refusing prefix /$bits in '$Entry' (allowed /8 to /32)"
  }
  $size = [uint64]1 -shl (32 - $bits)
  $first = $base - ($base % $size)
  return @{ First = $first; Last = $first + $size - 1 }
}

function Read-NpListFile {
  # Non-empty lines with '#' comments removed.
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  return @(Get-Content -LiteralPath $Path | ForEach-Object { ($_ -split '#')[0].Trim() } |
      Where-Object { $_ -ne '' })
}

function Set-NpScope {
  <#
  .SYNOPSIS
    Loads the in-scope CIDRs/IPs (one per line). Every scan checks its targets against them.
  #>
  param([Parameter(Mandatory = $true)][string]$Path)
  $ranges = @(Read-NpListFile $Path | ForEach-Object { ConvertTo-NpRange $_ })
  if ($ranges.Count -eq 0) { throw "Scope file $Path has no entries" }
  $script:NpScope = $ranges
  Write-Host ("Scope: {0} entries from {1}" -f $ranges.Count, $Path)
}

function Test-NpInScope {
  param([Parameter(Mandatory = $true)][string]$Ip)
  if ($null -eq $script:NpScope) { throw 'No scope loaded. Run Set-NpScope -Path <file> first.' }
  $n = [uint64](ConvertTo-NpUInt32 $Ip)
  foreach ($r in $script:NpScope) {
    if ($n -ge $r.First -and $n -le $r.Last) { return $true }
  }
  return $false
}

function Assert-NpInScope {
  param([Parameter(Mandatory = $true)][string[]]$Targets)
  $out = @($Targets | Where-Object { -not (Test-NpInScope $_) })
  if ($out.Count -gt 0) {
    $sample = ($out | Select-Object -First 10) -join ', '
    throw ("{0} target(s) outside scope, nothing sent: {1}" -f $out.Count, $sample)
  }
}

function Get-NpTarget {
  <#
  .SYNOPSIS
    Expands a file of IPs/CIDRs into a de-duplicated list of IPs, all checked against scope.
    CIDRs larger than /31 skip their network and broadcast addresses.
  #>
  param([Parameter(Mandatory = $true)][string]$Path)
  $ips = New-Object System.Collections.Generic.List[string]
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($entry in (Read-NpListFile $Path)) {
    $r = ConvertTo-NpRange $entry
    $first = $r.First
    $last = $r.Last
    if ($entry -match '/' -and ($last - $first) -ge 3) { $first++; $last-- }
    for ($n = $first; $n -le $last; $n++) {
      $ip = ConvertFrom-NpUInt32 ([uint32]$n)
      if ($seen.Add($ip)) { $ips.Add($ip) }
    }
  }
  Assert-NpInScope $ips.ToArray()
  Write-Host ("Targets: {0} addresses from {1}, all in scope" -f $ips.Count, $Path)
  return $ips.ToArray()
}

function ConvertTo-NpPortList {
  # Accepts numbers, comma lists and ranges: 22,80,'8000-8100' or '1-65535'.
  param([Parameter(Mandatory = $true)]$Ports)
  $seen = New-Object 'System.Collections.Generic.HashSet[int]'
  $list = New-Object System.Collections.Generic.List[int]
  foreach ($p in @($Ports)) {
    foreach ($part in ([string]$p -split ',')) {
      $part = $part.Trim()
      if ($part -eq '') { continue }
      if ($part -notmatch '^(\d+)(?:-(\d+))?$') { throw "Invalid port or range: '$part'" }
      $lo = [int]$Matches[1]
      $hi = $lo
      if ($Matches[2]) { $hi = [int]$Matches[2] }
      if ($lo -lt 1 -or $hi -gt 65535 -or $lo -gt $hi) { throw "Invalid port or range: '$part'" }
      for ($i = $lo; $i -le $hi; $i++) { if ($seen.Add($i)) { $list.Add($i) } }
    }
  }
  if ($list.Count -eq 0) { throw 'No ports given' }
  return $list.ToArray()
}

function New-NpOutputBase {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Test-Path -LiteralPath $NpOutDir)) {
    New-Item -ItemType Directory -Path $NpOutDir | Out-Null
  }
  # Millisecond stamps sort in start order; wait out a clash rather than overwrite a run.
  while ($true) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
    $base = Join-Path $NpOutDir "$stamp-$Name"
    if (-not (Test-Path -LiteralPath "$base.txt")) { return $base }
    Start-Sleep -Milliseconds 5
  }
}

function Write-NpRunHeader {
  param([string]$Base, [string]$Command, [hashtable]$Settings)
  $lines = @(
    "# netprobe $Command",
    "# started $((Get-Date).ToUniversalTime().ToString('u'))",
    "# host $env:COMPUTERNAME, user $env:USERDOMAIN\$env:USERNAME"
  )
  foreach ($k in ($Settings.Keys | Sort-Object)) { $lines += "# $k = $($Settings[$k])" }
  Set-Content -LiteralPath "$Base.txt" -Value $lines -Encoding UTF8
}

function New-NpScanOption {
  param([string]$TypeName, [int]$TimeoutMs, [int]$Concurrency, [double]$Rate,
    [string]$TracePath)
  if ($Concurrency -lt 1 -or $Rate -le 0 -or $TimeoutMs -lt 1) {
    throw 'TimeoutMs, Concurrency and Rate must be positive'
  }
  $o = New-Object $TypeName
  $o.TimeoutMs = $TimeoutMs
  $o.Concurrency = $Concurrency
  $o.Rate = $Rate
  if ($TracePath) { $o.TracePath = $TracePath }
  return $o
}

function Wait-NpJob {
  # Shows progress until the job finishes. Ctrl+C stops the job; the CSV keeps what arrived.
  param([Parameter(Mandatory = $true)]$Job, [Parameter(Mandatory = $true)][string]$Activity)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    while (-not $Job.Wait(1000)) {
      $done = $Job.Done
      $pct = [int](100 * $done / [math]::Max(1, $Job.Total))
      $status = '{0} of {1}' -f $done, $Job.Total
      $secs = -1
      if ($done -gt 0) { $secs = [int]($sw.Elapsed.TotalSeconds * ($Job.Total - $done) / $done) }
      Write-Progress -Activity $Activity -Status $status -PercentComplete $pct `
        -SecondsRemaining $secs
    }
  } finally {
    if (-not $Job.IsComplete) {
      $Job.Cancel()
      [void]$Job.Wait(15000)
      Write-Warning ("{0} stopped at {1} of {2}; the CSV holds the results so far" -f
        $Activity, $Job.Done, $Job.Total)
    }
    Write-Progress -Activity $Activity -Completed
  }
}

function Write-NpSummary {
  param([string]$Base, $Job, [string[]]$Lines)
  $counts = ($Job.StateCounts.GetEnumerator() | Sort-Object Key |
      ForEach-Object { '{0} {1}' -f $_.Key, $_.Value }) -join ', '
  $all = @("# finished $((Get-Date).ToUniversalTime().ToString('u'))", "# results: $counts",
    "# hosts that responded: $($Job.RespondingHosts.Count)") + $Lines
  if ($Job.LastError) { $all += "# last internal error: $($Job.LastError)" }
  Add-Content -LiteralPath "$Base.txt" -Value $all -Encoding UTF8
  $all | Write-Host
  Write-Host "Saved $Base.csv and $Base.txt"
}

function Get-NpTraceFile {
  # Every -Trace log in the output folder, oldest first. The leading comma keeps an empty or
  # one-element array from being unrolled on return.
  $files = @()
  if (Test-Path -LiteralPath $NpOutDir) {
    $files = @(Get-ChildItem -LiteralPath $NpOutDir -Filter '*-trace.log' |
        Sort-Object Name | ForEach-Object { $_.FullName })
  }
  return , [string[]]$files
}

function Get-NpOpenService {
  <#
  .SYNOPSIS
    Every open TCP port and answering UDP service in all scan CSVs so far (partial runs
    included), one row per host, protocol and port.
  #>
  $rows = @{}
  $files = @()
  if (Test-Path -LiteralPath $NpOutDir) {
    $files = @(Get-ChildItem -LiteralPath $NpOutDir -Filter '*.csv')
  }
  foreach ($f in $files) {
    $isTcp = $f.Name -like '*-tcp.csv'
    if (-not $isTcp -and $f.Name -notlike '*-udp.csv') { continue }
    foreach ($r in (Import-Csv -LiteralPath $f.FullName)) {
      if ($isTcp) {
        $detail = $r.Banner
        if ($r.TlsSubject) { $detail = "[$($r.TlsProtocol)] $($r.TlsSubject) $detail" }
        $row = [pscustomobject]@{ Host = $r.Host; Protocol = 'tcp'; Port = [int]$r.Port
          Service = ''; Detail = $detail }
      } elseif ($r.State -eq 'open') {
        $row = [pscustomobject]@{ Host = $r.Host; Protocol = 'udp'; Port = [int]$r.Port
          Service = $r.Probe; Detail = $r.Detail }
      } else { continue }
      $key = '{0}/{1}/{2}' -f $row.Protocol, $row.Host, $row.Port
      if (-not $rows.ContainsKey($key) -or (-not $rows[$key].Detail -and $row.Detail)) {
        $rows[$key] = $row
      }
    }
  }
  return @($rows.Values | Sort-Object { ConvertTo-NpUInt32 $_.Host }, Protocol, Port)
}

function Get-NpHost {
  <#
  .SYNOPSIS
    Hosts with any of the given ports open in any scan so far, e.g. $smb = Get-NpHost -Port 445.
  #>
  param(
    [Parameter(Mandatory = $true)][int[]]$Port,
    [ValidateSet('tcp', 'udp')][string]$Protocol = 'tcp'
  )
  $open = @(Get-NpOpenService |
      Where-Object { $_.Protocol -eq $Protocol -and $Port -contains $_.Port })
  return @($open | ForEach-Object { $_.Host } | Select-Object -Unique)
}

function Format-NpServiceLine {
  param($Service)
  $detail = [string]$Service.Detail
  if ($detail.Length -gt 110) { $detail = $detail.Substring(0, 110) + '...' }
  return '  {0,-15} {1,5}/{2} {3}' -f $Service.Host, $Service.Port, $Service.Protocol, $detail
}

function Show-NpSummary {
  <#
  .SYNOPSIS
    Prints and saves (<UTC stamp>-summary.txt) the traced runs, each with start time,
    duration, probes finished and whether it completed or was killed; then every open
    service found so far, grouped by the checks it feeds.
  #>
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("# netprobe summary $((Get-Date).ToUniversalTime().ToString('u'))")
  $done = New-Object 'System.Collections.Generic.HashSet[string]'
  $runs = [NetProbe.TraceLog]::Read((Get-NpTraceFile), $done)
  $lines.Add('')
  $lines.Add("== Traced runs: $($runs.Count); TCP host:port probes finished: $($done.Count)")
  foreach ($r in $runs) {
    $lines.Add(('  {0}  {1} {2:HH:mm:ss}-{3:HH:mm:ss}Z {4,7:N0} s  {5} of {6}  {7}' -f
        $r.File, $r.Kind, $r.Started, $r.Last, $r.Seconds, $r.Ended, $r.Total, $r.Outcome))
  }
  $services = Get-NpOpenService
  $claimed = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($g in $NpServiceGroups) {
    $hits = @($services | Where-Object {
        ($_.Protocol -eq 'tcp' -and $g.Tcp -contains $_.Port) -or
        ($_.Protocol -eq 'udp' -and $g.Udp -contains $_.Port)
      })
    if ($hits.Count -eq 0) { continue }
    $hostCount = @($hits | ForEach-Object { $_.Host } | Select-Object -Unique).Count
    $lines.Add('')
    $lines.Add("== $($g.Name): $hostCount host(s)")
    foreach ($s in $hits) {
      [void]$claimed.Add(('{0}/{1}/{2}' -f $s.Protocol, $s.Host, $s.Port))
      $lines.Add((Format-NpServiceLine $s))
    }
  }
  $other = @($services | Where-Object {
      -not $claimed.Contains(('{0}/{1}/{2}' -f $_.Protocol, $_.Host, $_.Port))
    })
  if ($other.Count -gt 0) {
    $lines.Add('')
    $hostCount = @($other | ForEach-Object { $_.Host } | Select-Object -Unique).Count
    $lines.Add("== Other open ports: $hostCount host(s)")
    foreach ($s in $other) { $lines.Add((Format-NpServiceLine $s)) }
  }
  $base = New-NpOutputBase 'summary'
  Set-Content -LiteralPath "$base.txt" -Value $lines -Encoding UTF8
  $lines | Write-Host
  Write-Host "Saved $base.txt"
}

function Select-NpPendingHost {
  # With -Resume, drops hosts already recorded in an earlier <stamp>-<Kind>.csv.
  param([string[]]$Targets, [string]$Kind, [bool]$Resume)
  if (-not $Resume -or -not (Test-Path -LiteralPath $NpOutDir)) { return , [string[]]$Targets }
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($f in @(Get-ChildItem -LiteralPath $NpOutDir -Filter "*-$Kind.csv")) {
    foreach ($r in (Import-Csv -LiteralPath $f.FullName)) { [void]$seen.Add($r.Host) }
  }
  $todo = [string[]]@($Targets | Where-Object { -not $seen.Contains($_) })
  $already = $Targets.Count - $todo.Count
  Write-Host ('Resume: {0} of {1} hosts already checked' -f $already, $Targets.Count)
  return , $todo
}

function Start-NpCheck {
  # Output base and run header for a per-host check.
  param([string]$Kind, [string]$Command, [string[]]$Targets, [hashtable]$Settings)
  $base = New-NpOutputBase $Kind
  $Settings['targets'] = $Targets.Count
  Write-NpRunHeader -Base $base -Command $Command -Settings $Settings
  return $base
}

function Add-NpCheckRow {
  # Appends one result row to the check's CSV straight away, so a killed run keeps it.
  param([string]$Base, $Row)
  $Row | Export-Csv -LiteralPath "$Base.csv" -Append -NoTypeInformation -Encoding UTF8
}

function Complete-NpCheck {
  param([string]$Base, [string[]]$Lines)
  $all = @("# finished $((Get-Date).ToUniversalTime().ToString('u'))") + $Lines
  Add-Content -LiteralPath "$Base.txt" -Value $all -Encoding UTF8
  $all | Write-Host
  Write-Host "Saved $Base.csv and $Base.txt"
}

function Invoke-NpNative {
  # Runs a built-in Windows program with an exact argument string. Returns its exit code,
  # its non-empty output lines, and those lines joined on one line.
  param([string]$File, [string]$Arguments, [int]$TimeoutMs = 30000)
  $psi = New-Object System.Diagnostics.ProcessStartInfo($File, $Arguments)
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEndAsync()
  $err = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutMs)) {
    $p.Kill()
    return @{ Code = -1; Output = "timed out after $TimeoutMs ms"; Lines = @() }
  }
  $lines = @(($out.Result + "`n" + $err.Result) -split "`r?`n" | Where-Object { $_.Trim() })
  return @{ Code = $p.ExitCode; Output = ($lines -join ' | '); Lines = $lines }
}

function Test-NpSmbLogon {
  # Connects to \\host\IPC$ as the given user with an empty password, lists shares through
  # that connection, then disconnects. Windows only (net.exe).
  param([string]$Ip, [string]$User)
  $ipc = '\\{0}\IPC$' -f $Ip
  $use = Invoke-NpNative -File 'net.exe' -Arguments ('use {0} "" /user:"{1}"' -f $ipc, $User)
  if ($use.Code -ne 0) { return @{ Result = "refused: $($use.Output)"; Shares = '' } }
  $view = Invoke-NpNative -File 'net.exe' -Arguments ('view \\{0} /all' -f $Ip)
  [void](Invoke-NpNative -File 'net.exe' -Arguments ('use {0} /delete /y' -f $ipc))
  if ($view.Code -ne 0) {
    return @{ Result = 'allowed'; Shares = "listing refused: $($view.Output)" }
  }
  $shares = New-Object System.Collections.Generic.List[string]
  $inTable = $false
  foreach ($line in $view.Lines) {
    if ($line -match '^-{5,}') { $inTable = $true; continue }
    if ($line -match '^The command completed') { break }
    if ($inTable) { $shares.Add((($line.Trim() -split '\s{2,}')[0])) }
  }
  return @{ Result = 'allowed'; Shares = ($shares -join '; ') }
}

function Invoke-NpSmbCheck {
  <#
  .SYNOPSIS
    SMB on 445: SMB2 dialect and signing (enabled/required), SMBv1 support and its signing,
    and on Windows, null-session and guest access to IPC$ with share listing.
  .DESCRIPTION
    The negotiate checks send no credentials. The logon checks run net.exe: "net use
    \\host\IPC$" with an empty user name, then as "guest", both with an empty password. Each
    connection that succeeds is used to list shares, then removed. -NoLogon skips them.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [int]$TimeoutMs = 3000,
    [switch]$NoLogon,
    [switch]$Resume
  )
  Assert-NpInScope $Targets
  $todo = Select-NpPendingHost -Targets $Targets -Kind 'smb' -Resume $Resume
  $onWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
  $logon = $onWindows -and -not $NoLogon
  $base = Start-NpCheck -Kind 'smb' -Command 'Invoke-NpSmbCheck' -Targets $todo -Settings @{
    timeout_ms = $TimeoutMs; logon_checks = $logon
  }
  $skipped = @{ Result = 'not run (-NoLogon)'; Shares = '' }
  if (-not $onWindows) { $skipped = @{ Result = 'not run (needs Windows)'; Shares = '' } }
  $lines = New-Object System.Collections.Generic.List[string]
  $i = 0
  foreach ($ip in $todo) {
    $i++
    Write-Progress -Activity 'SMB checks' -Status $ip -PercentComplete (100 * $i / $todo.Count)
    $r = [NetProbe.SmbProbe]::Probe($ip, $TimeoutMs)
    $anon = $skipped
    $guest = $skipped
    if ($logon) {
      $anon = Test-NpSmbLogon -Ip $ip -User ''
      $guest = Test-NpSmbLogon -Ip $ip -User 'guest'
    }
    Add-NpCheckRow -Base $base -Row ([pscustomobject]@{
        Host = $ip; Smb2Dialect = $r.Smb2Dialect; Smb2Signing = $r.Smb2Signing
        Smb1 = $r.Smb1; Smb1Signing = $r.Smb1Signing
        NullSession = $anon.Result; NullShares = $anon.Shares
        GuestSession = $guest.Result; GuestShares = $guest.Shares; Error = $r.Error
      })
    $lines.Add(('{0,-15} SMB2 {1}, signing {2}; SMB1 {3}' -f $ip, $r.Smb2Dialect, $r.Smb2Signing,
        $r.Smb1))
    if ($r.Error) { $lines.Add("                {0}" -f $r.Error) }
    $lines.Add(('                null: {0} {1}' -f $anon.Result, $anon.Shares))
    $lines.Add(('                guest: {0} {1}' -f $guest.Result, $guest.Shares))
  }
  Write-Progress -Activity 'SMB checks' -Completed
  Complete-NpCheck -Base $base -Lines $lines.ToArray()
}

function Get-NpLdapValue {
  param($Entry, [string]$Name)
  if (-not $Entry.Attributes.Contains($Name)) { return '' }
  return (@($Entry.Attributes[$Name].GetValues([string])) -join ',')
}

function Test-NpLdapHost {
  # Anonymous bind, RootDSE read, an anonymous search of the domain, and an unsigned simple bind
  # with made-up credentials (a server that requires signing answers strongerAuthRequired).
  param([string]$Ip, [int]$TimeoutMs)
  $p = 'System.DirectoryServices.Protocols'
  $row = [ordered]@{ Host = $Ip; AnonymousBind = ''; DnsHostName = ''; NamingContext = ''
    DomainLevel = ''; ForestLevel = ''; AnonymousSearch = ''; UnsignedSimpleBind = ''; Error = '' }
  $id = New-Object "$p.LdapDirectoryIdentifier"($Ip, 389)
  $conn = New-Object "$p.LdapConnection"($id)
  try {
    $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
    $conn.Bind()
    $row.AnonymousBind = 'allowed'
    $attrs = [string[]]@('dnsHostName', 'defaultNamingContext', 'namingContexts',
      'domainFunctionality', 'forestFunctionality')
    $req = New-Object "$p.SearchRequest"('', '(objectClass=*)', 'Base', $attrs)
    $rootDse = $conn.SendRequest($req).Entries[0]
    $row.DnsHostName = Get-NpLdapValue $rootDse 'dnsHostName'
    $row.NamingContext = Get-NpLdapValue $rootDse 'defaultNamingContext'
    if (-not $row.NamingContext -and $rootDse.Attributes.Contains('namingContexts')) {
      # Non-AD servers publish only namingContexts; use the first.
      $row.NamingContext = @($rootDse.Attributes['namingContexts'].GetValues([string]))[0]
    }
    $row.DomainLevel = Get-NpLdapValue $rootDse 'domainFunctionality'
    $row.ForestLevel = Get-NpLdapValue $rootDse 'forestFunctionality'
    if ($row.NamingContext) {
      $search = New-Object "$p.SearchRequest"($row.NamingContext, '(objectClass=*)', 'OneLevel',
        [string[]]@('distinguishedName'))
      $search.SizeLimit = 5
      try {
        $found = $conn.SendRequest($search).Entries.Count
        $row.AnonymousSearch = "allowed: $found entries returned (limit 5)"
      } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $resp = $_.Exception.Response
        $row.AnonymousSearch = "refused: $($resp.ResultCode) $($resp.ErrorMessage)"
      }
    }
  } catch {
    $row.Error = $_.Exception.Message
  } finally {
    $conn.Dispose()
  }
  $row.UnsignedSimpleBind = Test-NpLdapUnsignedBind -Ip $Ip -TimeoutMs $TimeoutMs
  return [pscustomobject]$row
}

function Test-NpLdapUnsignedBind {
  param([string]$Ip, [int]$TimeoutMs)
  $p = 'System.DirectoryServices.Protocols'
  $id = New-Object "$p.LdapDirectoryIdentifier"($Ip, 389)
  # A DN-shaped name, so AD and other servers check it rather than reject its syntax.
  $user = 'cn=netprobe-invalid-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
  $cred = New-Object System.Net.NetworkCredential($user, [guid]::NewGuid().ToString('N'))
  $basic = [System.DirectoryServices.Protocols.AuthType]::Basic
  $conn = New-Object "$p.LdapConnection"($id, $cred, $basic)
  try {
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
    $conn.Bind()
    return 'bind accepted with made-up credentials'
  } catch [System.DirectoryServices.Protocols.LdapException] {
    $e = $_.Exception
    $meaning = 'other'
    if ($e.ErrorCode -eq 49) { $meaning = 'signing not required (invalid credentials checked)' }
    if ($e.ErrorCode -eq 8) { $meaning = 'signing required (strongerAuthRequired)' }
    return ('{0}: code {1} {2}' -f $meaning, $e.ErrorCode, $e.ServerErrorMessage).Trim()
  } catch {
    return "error: $($_.Exception.Message)"
  } finally {
    $conn.Dispose()
  }
}

function Invoke-NpLdapCheck {
  <#
  .SYNOPSIS
    LDAP on 389: anonymous bind and RootDSE (host name, naming context, functional levels),
    whether an anonymous search of the domain returns entries, and whether an unsigned simple
    bind is refused for lack of signing.
  .DESCRIPTION
    The signing check binds once per host as a random non-existent user with a random
    password; the server's answer shows whether it requires signing before checking the
    credentials. Channel binding needs valid domain credentials and is not tested.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [int]$TimeoutMs = 5000,
    [switch]$Resume
  )
  Assert-NpInScope $Targets
  Add-Type -AssemblyName System.DirectoryServices.Protocols
  $todo = Select-NpPendingHost -Targets $Targets -Kind 'ldap' -Resume $Resume
  $base = Start-NpCheck -Kind 'ldap' -Command 'Invoke-NpLdapCheck' -Targets $todo -Settings @{
    timeout_ms = $TimeoutMs
  }
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($ip in $todo) {
    $r = Test-NpLdapHost -Ip $ip -TimeoutMs $TimeoutMs
    Add-NpCheckRow -Base $base -Row $r
    $lines.Add(('{0,-15} {1} ({2}), domain level {3}, forest level {4}' -f $ip, $r.DnsHostName,
        $r.NamingContext, $r.DomainLevel, $r.ForestLevel))
    $lines.Add(('                anonymous bind: {0}; anonymous search: {1}' -f $r.AnonymousBind,
        $r.AnonymousSearch))
    $lines.Add(('                unsigned simple bind: {0}' -f $r.UnsignedSimpleBind))
    if ($r.Error) { $lines.Add("                error: $($r.Error)") }
  }
  Complete-NpCheck -Base $base -Lines $lines.ToArray()
}

function Read-NpSmtpReply {
  # One SMTP reply, which may span several "250-..." lines.
  param([System.IO.StreamReader]$Reader)
  $lines = New-Object System.Collections.Generic.List[string]
  while ($true) {
    $line = $Reader.ReadLine()
    if ($null -eq $line) { break }
    $lines.Add($line)
    if ($line.Length -lt 4 -or $line[3] -ne '-') { break }
  }
  return ($lines -join ' | ')
}

function Test-NpSmtpHost {
  # Greeting, EHLO capabilities, VRFY/EXPN, and whether an external recipient is accepted.
  # Ends with RSET and QUIT before any DATA, so no mail is sent.
  param([string]$Ip, [int]$Port, [int]$TimeoutMs)
  $row = [ordered]@{ Host = $Ip; Port = $Port; Banner = ''; Ehlo = ''; StartTls = ''
    VrfyRoot = ''; VrfyUnknown = ''; ExpnRoot = ''; MailFrom = ''; RcptExternal = ''
    UserEnum = ''; Relay = ''; Error = '' }
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $client.BeginConnect([System.Net.IPAddress]::Parse($Ip), $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw 'connect timeout' }
    $client.EndConnect($ar)
    $client.ReceiveTimeout = $TimeoutMs
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
    $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true
    $send = { param($cmd) $writer.WriteLine($cmd); return Read-NpSmtpReply $reader }
    $row.Banner = Read-NpSmtpReply $reader
    $row.Ehlo = & $send 'EHLO netprobe.invalid'
    $row.StartTls = [string]($row.Ehlo -match 'STARTTLS')
    $row.VrfyRoot = & $send 'VRFY root'
    $row.VrfyUnknown = & $send ('VRFY netprobe' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $row.ExpnRoot = & $send 'EXPN root'
    $row.MailFrom = & $send 'MAIL FROM:<netprobe@example.com>'
    $row.RcptExternal = & $send 'RCPT TO:<netprobe@example.net>'
    [void](& $send 'RSET')
    [void](& $send 'QUIT')
  } catch {
    $row.Error = $_.Exception.Message
  } finally {
    $client.Close()
  }
  $codeRoot = ([string]$row.VrfyRoot).Split(' ')[0]
  $codeUnknown = ([string]$row.VrfyUnknown).Split(' ')[0]
  $row.UserEnum = 'no (VRFY answers do not differ)'
  if ($codeRoot -match '^25[02]$' -and $codeUnknown -match '^55\d$') {
    $row.UserEnum = "likely: VRFY root $codeRoot, unknown user $codeUnknown"
  }
  $row.Relay = 'no'
  if ([string]$row.RcptExternal -match '^25[01]') {
    $row.Relay = 'candidate: external RCPT accepted'
  }
  return [pscustomobject]$row
}

function Invoke-NpSmtpCheck {
  <#
  .SYNOPSIS
    SMTP: greeting, EHLO capabilities (STARTTLS, AUTH), VRFY/EXPN user enumeration, and an
    open-relay check (example.com sender to an example.net recipient). No mail is sent: the
    session ends with RSET and QUIT before DATA.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [int]$Port = 25,
    [int]$TimeoutMs = 10000,
    [switch]$Resume
  )
  Assert-NpInScope $Targets
  $todo = Select-NpPendingHost -Targets $Targets -Kind 'smtp' -Resume $Resume
  $base = Start-NpCheck -Kind 'smtp' -Command 'Invoke-NpSmtpCheck' -Targets $todo -Settings @{
    port = $Port; timeout_ms = $TimeoutMs
  }
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($ip in $todo) {
    $r = Test-NpSmtpHost -Ip $ip -Port $Port -TimeoutMs $TimeoutMs
    Add-NpCheckRow -Base $base -Row $r
    $lines.Add(('{0}:{1}  {2}' -f $ip, $Port, $r.Banner))
    $lines.Add(('  EHLO: {0}' -f $r.Ehlo))
    $lines.Add(('  STARTTLS {0}; user enum {1}; relay {2}' -f $r.StartTls, $r.UserEnum, $r.Relay))
    $lines.Add(('  VRFY root: {0} | unknown: {1} | EXPN root: {2}' -f $r.VrfyRoot,
        $r.VrfyUnknown, $r.ExpnRoot))
    $lines.Add(('  MAIL FROM: {0} | RCPT external: {1}' -f $r.MailFrom, $r.RcptExternal))
    if ($r.Error) { $lines.Add("  error: $($r.Error)") }
  }
  Complete-NpCheck -Base $base -Lines $lines.ToArray()
}

function Invoke-NpTelnetCheck {
  <#
  .SYNOPSIS
    Telnet: the greeting and login prompt, after refusing every option the server offers. No
    credentials are sent.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [int]$Port = 23,
    [int]$TimeoutMs = 8000,
    [switch]$Resume
  )
  Assert-NpInScope $Targets
  $todo = Select-NpPendingHost -Targets $Targets -Kind 'telnet' -Resume $Resume
  $base = Start-NpCheck -Kind 'telnet' -Command 'Invoke-NpTelnetCheck' -Targets $todo -Settings @{
    port = $Port; timeout_ms = $TimeoutMs
  }
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($ip in $todo) {
    $banner = ''
    $err = ''
    try { $banner = [NetProbe.TelnetProbe]::Banner($ip, $Port, $TimeoutMs) }
    catch {
      $e = $_.Exception
      if ($e.InnerException) { $e = $e.InnerException }
      $err = $e.Message
    }
    Add-NpCheckRow -Base $base -Row ([pscustomobject]@{
        Host = $ip; Port = $Port; Banner = $banner; Error = $err })
    $lines.Add(('{0,-15} {1}/tcp {2}{3}' -f $ip, $Port, $banner, $err))
  }
  Complete-NpCheck -Base $base -Lines $lines.ToArray()
}

function Start-NpSession {
  <#
  .SYNOPSIS
    Starts a PowerShell transcript for this testing session in the output folder.
  #>
  $base = New-NpOutputBase 'transcript'
  Start-Transcript -LiteralPath "$base.txt" | Out-Null
  Write-Host "Transcript: $base.txt (Stop-Transcript to end)"
}

function Invoke-NpPing {
  <#
  .SYNOPSIS
    ICMP echo sweep. Hosts that drop ICMP may still have open ports.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [int]$TimeoutMs = 1000,
    [int]$Concurrency = 16,
    [double]$Rate = 20,
    [switch]$Trace
  )
  Assert-NpInScope $Targets
  $base = New-NpOutputBase 'ping'
  $tracePath = $null
  if ($Trace) { $tracePath = "$base-trace.log" }
  $o = New-NpScanOption -TypeName 'NetProbe.ScanOptions' -TimeoutMs $TimeoutMs `
    -Concurrency $Concurrency -Rate $Rate -TracePath $tracePath
  Write-NpRunHeader -Base $base -Command 'Invoke-NpPing' -Settings @{
    targets = $Targets.Count; timeout_ms = $TimeoutMs
    concurrency = $Concurrency; rate_per_s = $Rate; trace = [bool]$Trace
  }
  $job = [NetProbe.Scans]::Ping([string[]]$Targets, $o, "$base.csv")
  Wait-NpJob $job 'ICMP echo sweep'
  $up = @($job.Results | Where-Object { $_.Status -eq 'Success' } |
      Sort-Object { ConvertTo-NpUInt32 $_.Host })
  $lines = @($up | ForEach-Object { '{0,-15} ttl {1,-3} {2} ms' -f $_.Host, $_.Ttl, $_.Millis })
  Write-NpSummary -Base $base -Job $job -Lines $lines
}

function Invoke-NpTcpScan {
  <#
  .SYNOPSIS
    TCP connect scan, with banner, HTTP HEAD and TLS certificate grabs on open ports.
  .PARAMETER Ports
    Numbers, lists and ranges: 22,80,'8000-8100' or '1-65535'. Defaults to $NpDefaultPorts.
  .PARAMETER Rate
    Connection attempts started per second, across all targets.
  .PARAMETER Resume
    Skip host:port probes that earlier traced runs (-Trace or -Resume) finished, so a scan
    that was stopped or killed carries on where it left off. Implies -Trace.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    $Ports = $NpDefaultPorts,
    [int]$TimeoutMs = 1500,
    [int]$Concurrency = 32,
    [double]$Rate = 50,
    [switch]$NoGrab,
    [switch]$Trace,
    [switch]$Resume
  )
  Assert-NpInScope $Targets
  $portList = ConvertTo-NpPortList $Ports
  $done = New-Object 'System.Collections.Generic.HashSet[string]'
  if ($Resume) { [void][NetProbe.TraceLog]::Read((Get-NpTraceFile), $done) }
  $base = New-NpOutputBase 'tcp'
  $tracePath = $null
  if ($Trace -or $Resume) { $tracePath = "$base-trace.log" }
  $o = New-NpScanOption -TypeName 'NetProbe.TcpOptions' -TimeoutMs $TimeoutMs `
    -Concurrency $Concurrency -Rate $Rate -TracePath $tracePath
  $o.Grab = -not $NoGrab
  $o.TlsPorts = [int[]]$NpTlsPorts
  $o.HttpPorts = [int[]]$NpHttpPorts
  if ($Resume) { $o.Skip = $done }
  $all = $Targets.Count * $portList.Count
  Write-NpRunHeader -Base $base -Command 'Invoke-NpTcpScan' -Settings @{
    targets = $Targets.Count; ports = $portList.Count; probes = $all; timeout_ms = $TimeoutMs
    concurrency = $Concurrency; rate_per_s = $Rate; grab = $o.Grab
    trace = [bool]$tracePath; resume = [bool]$Resume
  }
  $job = [NetProbe.Scans]::Tcp([string[]]$Targets, [int[]]$portList, $o, "$base.csv")
  if ($Resume) {
    Write-Host ('Resume: {0} of {1} probes already finished in earlier traced runs' -f
      ($all - $job.Total), $all)
  }
  $minutes = $job.Total / $Rate / 60
  Write-Host ('{0} connects at up to {1}/s: at least {2:N1} minutes' -f $job.Total, $Rate, $minutes)
  Wait-NpJob $job 'TCP connect scan'
  $open = @($job.Results | Sort-Object { ConvertTo-NpUInt32 $_.Host }, Port)
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($g in ($open | Group-Object Host)) {
    $lines.Add('')
    $lines.Add($g.Name)
    foreach ($r in $g.Group) {
      $detail = $r.Banner
      if ($r.TlsSubject) {
        $cert = "$($r.TlsSubject) (issuer $($r.TlsIssuer), until $($r.TlsNotAfter))"
        $detail = "[$($r.TlsProtocol)] $cert $detail"
      }
      if (-not $detail -and $r.Error) { $detail = "($($r.Error))" }
      $lines.Add(('  {0,5}/tcp  {1}' -f $r.Port, $detail))
    }
  }
  Write-NpSummary -Base $base -Job $job -Lines $lines.ToArray()
}

function Invoke-NpUdpProbe {
  <#
  .SYNOPSIS
    Protocol-specific UDP probes. "open|filtered" means no reply, which UDP cannot tell apart.
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    [ValidateSet('dns', 'tftp', 'ntp', 'nbns', 'snmp', 'ipmi', 'mssql')]
    [string[]]$Probes = @('dns', 'tftp', 'ntp', 'nbns', 'snmp', 'ipmi', 'mssql'),
    [string]$Community = 'public',
    [int]$TimeoutMs = 2000,
    [int]$Concurrency = 16,
    [double]$Rate = 20,
    [switch]$Trace
  )
  Assert-NpInScope $Targets
  $base = New-NpOutputBase 'udp'
  $tracePath = $null
  if ($Trace) { $tracePath = "$base-trace.log" }
  $o = New-NpScanOption -TypeName 'NetProbe.UdpOptions' -TimeoutMs $TimeoutMs `
    -Concurrency $Concurrency -Rate $Rate -TracePath $tracePath
  $o.Community = $Community
  Write-NpRunHeader -Base $base -Command 'Invoke-NpUdpProbe' -Settings @{
    targets = $Targets.Count; probes = ($Probes -join ','); community = $Community
    timeout_ms = $TimeoutMs; concurrency = $Concurrency; rate_per_s = $Rate; trace = [bool]$Trace
  }
  $job = [NetProbe.Scans]::Udp([string[]]$Targets, [string[]]$Probes, $o, "$base.csv")
  Wait-NpJob $job 'UDP probes'
  $answered = @($job.Results | Where-Object { $_.State -eq 'open' } |
      Sort-Object { ConvertTo-NpUInt32 $_.Host }, Port)
  $lines = @($answered | ForEach-Object {
      '{0,-15} {1,5}/udp {2,-5} {3}' -f $_.Host, $_.Port, $_.Probe, $_.Detail
    })
  Write-NpSummary -Base $base -Job $job -Lines $lines
}
