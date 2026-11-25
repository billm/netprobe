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

$NpSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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
            var job = new Job(hosts.Length * ports.Length, o, csvPath, TcpResult.Header);
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
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  return Join-Path $NpOutDir "$stamp-$Name"
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
  #>
  param(
    [Parameter(Mandatory = $true)][string[]]$Targets,
    $Ports = $NpDefaultPorts,
    [int]$TimeoutMs = 1500,
    [int]$Concurrency = 32,
    [double]$Rate = 50,
    [switch]$NoGrab,
    [switch]$Trace
  )
  Assert-NpInScope $Targets
  $portList = ConvertTo-NpPortList $Ports
  $base = New-NpOutputBase 'tcp'
  $tracePath = $null
  if ($Trace) { $tracePath = "$base-trace.log" }
  $o = New-NpScanOption -TypeName 'NetProbe.TcpOptions' -TimeoutMs $TimeoutMs `
    -Concurrency $Concurrency -Rate $Rate -TracePath $tracePath
  $o.Grab = -not $NoGrab
  $o.TlsPorts = [int[]]$NpTlsPorts
  $o.HttpPorts = [int[]]$NpHttpPorts
  $total = $Targets.Count * $portList.Count
  Write-NpRunHeader -Base $base -Command 'Invoke-NpTcpScan' -Settings @{
    targets = $Targets.Count; ports = $portList.Count; probes = $total; timeout_ms = $TimeoutMs
    concurrency = $Concurrency; rate_per_s = $Rate; grab = $o.Grab; trace = [bool]$Trace
  }
  $minutes = $total / $Rate / 60
  Write-Host ('{0} connects at up to {1}/s: at least {2:N1} minutes' -f $total, $Rate, $minutes)
  $job = [NetProbe.Scans]::Tcp([string[]]$Targets, [int[]]$portList, $o, "$base.csv")
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
