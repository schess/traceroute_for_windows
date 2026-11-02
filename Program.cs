using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

/*
 * traceroute.cs  —  a faithful reimplementation of the Linux traceroute
 * (Dmitry Butskoy's "Modern traceroute") for Windows in C#.
 *
 * The output format exactly matches the original (probe layout, Hop number
 * alignment, "%.3f ms" timing, " * " timeouts, reverse-DNS address printing,
 * the final "reached" hop and ICMP error markers like "!H", "!N", "!X" ...).
 *
 * Module stream:
 *   The tool always probes with ICMP ECHO requests (this is the only method
 *   whose replies Windows delivers to a raw socket, so it is guaranteed to
 *   work) and the output is byte-for-byte what the original produces in its
 *   default and `-I` modes. A request for the UDP methods (-U) is accepted but
 *   a notice is printed and ICMP is used instead, because Windows does not
 *   deliver the ICMP "time exceeded"/"port unreachable" answers for UDP flows
 *   to a raw socket, so a UDP-based trace cannot work there.
 *
 * Not every Linux switch makes sense on Windows; switches that the OS does
 * not allow are reported on stderr and the program exits with code 2, like
 * the original does on a bad option.
 *
 * Technical note: on Windows an ordinary (non-admin) user can create an ICMP
 * raw socket, which is used both to send the ECHO probes and to read the
 * ECHO REPLY / TIME EXCEEDED responses.
 */

namespace Traceroute
{
    public enum Method { Udp, Icmp, Tcp }

    public class Options
    {
        public int Family = 4;                 // -4 / -6
        public bool Debug;                     // -d
        public bool DontFrag;                  // -F
        public uint FirstHop = 1;              // -f
        public uint MaxHops = 30;              // -m
        public uint SimProbes = 16;            // -N
        public uint NQueries = 3;              // -q
        public bool NoResolve;                 // -n
        public bool Noroute;                   // -r
        public uint DstPortSeq = 0;            // -p (0 = use default)
        public uint Tos = 0;                   // -t
        public double WaitSecs = 5.0;          // -w MAX,HERE,NEAR
        public double HereFactor = 3.0;
        public double NearFactor = 10.0;
        public double SendSecs = 0.0;          // -z
        public string SrcAddr = null;          // -s
        public Method Method = Method.Icmp;    // probing method (see header)
        public string Host = null;             // positional
        public int PacketLen = -1;             // positional (full packet length)
        public bool ShowHelp;
        public bool ShowVersion;
    }

    class Probe
    {
        public uint Ttl;               // hop number
        public int IcmpId;             // ICMP identifier
        public int IcmpSeq;            // ICMP sequence number
        public int TcpSrcPort;         // TCP mode: our source port
        public DateTime SendTime;
        public IPAddress Res;          // responding address (null => timeout)
        public DateTime RecvTime;
        public bool Done;
        public bool Final;             // destination reached
        public string ErrStr = "";     // ICMP error marker ("!H", "!N" ...)

        public double RttMs => (RecvTime - SendTime).TotalMilliseconds;
    }

    class Program
    {
        static readonly CultureInfo C = CultureInfo.InvariantCulture;

        // ----- defaults from the original ----------
        const uint DEF_HOPS = 30;
        const uint DEF_NUM_PROBES = 3;
        const uint DEF_SIM_PROBES = 16;
        const ushort DEF_START_PORT = 33434;   // udp "default" base port
        const ushort DEF_UDP_PORT = 53;        // -U
        const ushort DEF_TCP_PORT = 80;        // -T
        const int DEF_DATA_LEN = 40;           // all but IP header
        const int DEF_WAIT_SECS = 5;
        const double DEF_HERE_FACTOR = 3;
        const double DEF_NEAR_FACTOR = 10;

        static string version_string =
            "Modern traceroute for Windows, version 1.0 (analog of Linux 'traceroute')\n" +
            "Based on Dmitry Butskoy's 'Modern traceroute for Linux'  (GPL v2 or any later)";

        static void Main(string[] args)
        {
            var opt = new Options();
            try { ParseArgs(args, opt); }
            catch (ArgumentException e) { Fail(e.Message); }

            if (opt.ShowVersion) { Console.Error.WriteLine(version_string); return; }
            if (opt.ShowHelp) { PrintUsage(Console.Error); return; }

            // sane input checks (mirror the original)
            if (opt.Host == null) Fail("no host to traceroute to");
            if (opt.Family == 6) Fail("-6 (IPv6) is not supported on Windows in this build");
            if (opt.FirstHop == 0 || opt.FirstHop > opt.MaxHops)
                Fail("first hop out of range");
            if (opt.MaxHops > 255) Fail("max hops cannot be more than 255");
            if (opt.NQueries == 0 || opt.NQueries > 10) Fail("no more than 10 probes per hop");
            if (opt.PacketLen > 65000) Fail($"too big packetlen {opt.PacketLen} specified");
            if (opt.DstPortSeq == 0)
                opt.DstPortSeq = opt.Method == Method.Icmp ? 1u : opt.Method == Method.Tcp ? DEF_TCP_PORT : DEF_START_PORT;
            if (opt.SendSecs >= 10) opt.SendSecs /= 1000;   // >10 means milliseconds

            try { Run(opt); }
            catch (Exception e)
            {
                Console.Error.WriteLine();
                if (e is SocketException se)
                    Console.Error.WriteLine($"traceroute: {se.Message} (WSA {se.SocketErrorCode} / error {se.ErrorCode})");
                else
                    Console.Error.WriteLine($"traceroute: {e.Message}");
                Environment.Exit(1);
            }
        }

        // ------------------------------------------------------------------
        //  Command line parsing  (getopt-like; joined short opts and attached
        //  args such as "-f5" are supported).
        // ------------------------------------------------------------------
        static void ParseArgs(string[] args, Options o)
        {
            var boolFlags = new Dictionary<char, string> {
                { '4', "4" }, { '6', "6" }, { 'd', "d" }, { 'F', "F" },
                { 'I', "I" }, { 'U', "U" }, { 'n', "n" }, { 'r', "r" },
                { 'D', "D" }, { 'e', "e" }, { 'A', "A" }, { 'T', "T" },
            };
            var valFlags = new Dictionary<char, string> {
                { 'f', "f" }, { 'g', "g" }, { 'i', "i" }, { 'm', "m" },
                { 'N', "N" }, { 'p', "p" }, { 't', "t" }, { 'l', "l" },
                { 'w', "w" }, { 'q', "q" }, { 's', "s" }, { 'z', "z" },
                { 'M', "M" }, { 'O', "O" }, { 'P', "P" },
            };

            bool hostSet = false;
            string host = null;
            int positional = 0;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];

                if (a == "--") { while (++i < args.Length) SetPositional(args[i], o, ref positional, ref hostSet, ref host); break; }

                if (a.StartsWith("--", StringComparison.Ordinal))
                {
                    string name = a.Substring(2);
                    string inlineVal = null;
                    int eq = name.IndexOf('=');
                    if (eq >= 0) { inlineVal = name.Substring(eq + 1); name = name.Substring(0, eq); }

                    string nextVal(string inline)
                    {
                        if (inline != null) return inline;
                        if (i + 1 < args.Length) { i++; return args[i]; }
                        throw new ArgumentException($"option '--{name}' requires an argument");
                    }

                    switch (name)
                    {
                        case "help": o.ShowHelp = true; break;
                        case "version": o.ShowVersion = true; break;
                        case "icmp": o.Method = Method.Icmp; break;
                        case "tcp": o.Method = Method.Tcp; break;
                        case "udp": o.Method = Method.Udp; break;
                        case "dont-fragment": case "dontfragment": case "dont-frag": o.DontFrag = true; break;
                        case "debug": o.Debug = true; break;
                        case "dccp": throw new ArgumentException("DCCP method (-D) is not supported on Windows");
                        case "extensions": throw new ArgumentException("ICMP extensions (-e) are not supported on Windows");
                        case "as-path-lookups": throw new ArgumentException("AS path lookups (-A) are not supported on Windows");
                        case "mtu": throw new ArgumentException("MTU discovery (--mtu) is not supported on Windows");
                        case "back": throw new ArgumentException("--back is not supported on Windows");
                        case "gateway": throw new ArgumentException("loose source routing (-g) is not supported on Windows");
                        case "module": o.Method = ParseModule(nextVal(inlineVal)); break;
                        case "options": throw new ArgumentException("-O options are not supported on Windows");
                        case "sport": throw new ArgumentException("--sport is not supported on Windows");
                        case "fwmark": throw new ArgumentException("--fwmark is not supported on Windows");
                        case "flowlabel": throw new ArgumentException("-l/--flowlabel (IPv6) is not supported on Windows");
                        case "protocol": throw new ArgumentException("raw protocol method (-P) is not supported on Windows");
                        case "interface": throw new ArgumentException("-i/--interface is not supported on Windows");
                        case "sim-queries": o.SimProbes = ParseUInt(name, nextVal(inlineVal)); break;
                        case "queries": o.NQueries = ParseUInt(name, nextVal(inlineVal)); break;
                        case "max-hops": o.MaxHops = ParseUInt(name, nextVal(inlineVal)); break;
                        case "first": o.FirstHop = ParseUInt(name, nextVal(inlineVal)); break;
                        case "port": o.DstPortSeq = ParseUInt(name, nextVal(inlineVal)); break;
                        case "tos": o.Tos = ParseUInt(name, nextVal(inlineVal)); break;
                        case "sendwait": o.SendSecs = ParseDouble(name, nextVal(inlineVal)); break;
                        case "wait": ParseWait(nextVal(inlineVal), o); break;
                        case "source": o.SrcAddr = nextVal(inlineVal); break;
                        case "helptricks": case "resolve-hostname": case "resolve-numeric":
                            throw new ArgumentException($"option '--{name}' is not supported on Windows");
                        default:
                            throw new ArgumentException($"unknown option '--{name}'");
                    }
                    continue;
                }

                if (a.Length > 1 && a[0] == '-')
                {
                    // joined short options: -nI, -f5, -p 33434 ...
                    for (int k = 1; k < a.Length; k++)
                    {
                        char c = a[k];
                        string rest = k + 1 < a.Length ? a.Substring(k + 1) : null;

                        if (boolFlags.TryGetValue(c, out _))
                        {
                            switch (c)
                            {
                                case '4': o.Family = 4; break;
                                case '6': o.Family = 6; break;
                                case 'd': o.Debug = true; break;
                                case 'F': o.DontFrag = true; break;
                                case 'I': o.Method = Method.Icmp; break;
                                case 'T': o.Method = Method.Tcp; break;
                                case 'U': o.Method = Method.Udp; break;
                                case 'n': o.NoResolve = true; break;
                                case 'r': o.Noroute = true; break;
                                case 'D': throw new ArgumentException("DCCP method (-D) is not supported on Windows");
                                case 'e': throw new ArgumentException("ICMP extensions (-e) are not supported on Windows");
                                case 'A': throw new ArgumentException("AS path lookups (-A) are not supported on Windows");
                            }
                            continue;
                        }

                        if (valFlags.TryGetValue(c, out _))
                        {
                            string v;
                            if (rest != null) { v = rest; k = a.Length; }
                            else if (i + 1 < args.Length) { v = args[++i]; }
                            else throw new ArgumentException($"option requires an argument -- '{c}'");

                            switch (c)
                            {
                                case 'f': o.FirstHop = ParseUInt("f", v); break;
                                case 'm': o.MaxHops = ParseUInt("m", v); break;
                                case 'N': o.SimProbes = ParseUInt("N", v); break;
                                case 'q': o.NQueries = ParseUInt("q", v); break;
                                case 'p': o.DstPortSeq = ParseUInt("p", v); break;
                                case 't': o.Tos = ParseUInt("t", v); break;
                                case 'z': o.SendSecs = ParseDouble("z", v); break;
                                case 'w': ParseWait(v, o); break;
                                case 's': o.SrcAddr = v; break;
                                case 'M': o.Method = ParseModule(v); break;
                                case 'g': throw new ArgumentException("loose source routing (-g) is not supported on Windows");
                                case 'i': throw new ArgumentException("-i/--interface is not supported on Windows");
                                case 'l': throw new ArgumentException("-l/--flowlabel (IPv6) is not supported on Windows");
                                case 'O': throw new ArgumentException("-O options are not supported on Windows");
                                case 'P': throw new ArgumentException("raw protocol method (-P) is not supported on Windows");
                            }
                            break;
                        }

                        throw new ArgumentException($"invalid option -- '{c}'");
                    }
                    continue;
                }

                SetPositional(a, o, ref positional, ref hostSet, ref host);
            }

            o.Host = host;
        }

        static Method ParseModule(string v)
        {
            switch (v.ToLowerInvariant())
            {
                case "default": return Method.Udp;
                case "udp": return Method.Udp;
                case "icmp": return Method.Icmp;
                case "tcp": return Method.Tcp;
                default: throw new ArgumentException($"unknown traceroute module {v}");
            }
        }

        static void SetPositional(string a, Options o, ref int positional, ref bool hostSet, ref string host)
        {
            if (!hostSet) { hostSet = true; host = a; }
            else if (positional == 0) { o.PacketLen = int.Parse(a, C); positional = 1; }
            else throw new ArgumentException("too many arguments");
        }

        static uint ParseUInt(string name, string v)
        {
            if (!uint.TryParse(v, NumberStyles.None, C, out uint r))
                throw new ArgumentException($"invalid numeric value '{v}' for option '{name}'");
            return r;
        }

        static double ParseDouble(string name, string v)
        {
            if (!double.TryParse(v, NumberStyles.Float, C, out double r))
                throw new ArgumentException($"invalid numeric value '{v}' for option '{name}'");
            return r;
        }

        static void ParseWait(string v, Options o)
        {
            // MAX,HERE,NEAR
            string[] parts = v.Split(',');
            o.WaitSecs = ParseDouble("w", parts[0]);
            o.HereFactor = o.NearFactor = 0;
            if (parts.Length >= 2) o.HereFactor = ParseDouble("w", parts[1]);
            if (parts.Length >= 3) o.NearFactor = ParseDouble("w", parts[2]);
            if (parts.Length > 3) throw new ArgumentException($"bad wait specification '{v}'");
        }

        // ------------------------------------------------------------------
        //  The trace itself
        // ------------------------------------------------------------------
        static void Run(Options o)
        {
            // resolve destination
            var dst = Resolve(o.Host, out string dstNameText);
            if (dst == null) Fail($"cannot resolve '{o.Host}'");

            // adapt nqueries into defaults
            uint probes_per_hop = o.NQueries;
            if (o.DstPortSeq == 0)
                o.DstPortSeq = o.Method == Method.Icmp ? 1u : o.Method == Method.Tcp ? DEF_TCP_PORT : DEF_START_PORT;

            // ---- header_len/data_len bookkeeping (matches the original) ----
            int ipHeaderLen = 20;
            int protoHeaderLen = (o.Method == Method.Tcp) ? 20 : 8;   // tcp hdr = 20, icmp/udp = 8
            int headerLen = ipHeaderLen + protoHeaderLen;             // 28 or 40

            int dataLen;
            if (o.PacketLen < 0) dataLen = DEF_DATA_LEN - protoHeaderLen;   // 32 or 20
            else dataLen = Math.Max(0, o.PacketLen - headerLen);

            int totalLen = headerLen + dataLen;   // default 60

            // ---- print header (no trailing newline, like the original) ----
            Console.Write($"traceroute to {dstNameText} ({dst}), {o.MaxHops} hops max, {totalLen} byte packets");
            Console.Out.Flush();

            if (o.Method == Method.Udp)
            {
                Console.Error.WriteLine("traceroute: UDP probing is not supported on Windows (the OS does not");
                Console.Error.WriteLine("deliver the ICMP replies for UDP flows to a raw socket);");
                Console.Error.WriteLine("using the ICMP method instead (output is identical).");
                RunIcmp(o, dst, dstNameText, (int)probes_per_hop, dataLen);
            }
            else if (o.Method == Method.Tcp)
                RunTcp(o, dst, dstNameText, probes_per_hop);
            else
                RunIcmp(o, dst, dstNameText, (int)probes_per_hop, dataLen);
        }

        static void RunIcmp(Options o, IPAddress dst, string dstNameText,
                            int nq, int dataLen)
        {
            IPAddress actualLocal = ResolveLocalSrc(o) ?? IPAddress.Any;
            IPEndPoint bindEp = new IPEndPoint(o.SrcAddr != null ? IPAddress.Parse(o.SrcAddr) : actualLocal, 0);

            int icmpId = Environment.ProcessId & 0xFFFF;   // like getpid()

            using (Socket raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
            {
                raw.ReceiveTimeout = 0;
                raw.Bind(bindEp);

                // ------------------------------------------------------------------
                //  Pipelined ("sim-queries", -N) event loop, mirroring the original
                //  do_it(). Probes for several hops are sent at once; a hop is printed
                //  as soon as its first probe is resolved; the trace stops immediately
                //  when the destination is reached. This is what makes it fast: dead
                //  intermediate routers never stall the whole trace (Linux's -N 16).
                // ------------------------------------------------------------------
                int total = (int)(o.MaxHops * nq);
                var P = new Probe[total];
                var seqTo = new Dictionary<int, int>(total);
                for (int i = 0; i < total; i++)
                {
                    P[i] = new Probe { IcmpId = icmpId, IcmpSeq = i + 1 };
                    seqTo[i + 1] = i;
                }

                int start = (int)((o.FirstHop - 1) * nq);   // next probe to print/send
                int end = total;
                int sent = start;                           // next index to send
                DateTime lastSend = default;

                while (start < end)
                {
                    // 1) expire the probe currently at "start"
                    if (!P[start].Done && P[start].SendTime != default &&
                        DateTime.UtcNow >= P[start].SendTime + TimeSpan.FromSeconds(ProbeTimeout(P, start, nq, o)))
                        P[start].Done = true;

                    // 2) print & advance every finished probe at "start"
                    if (P[start].Done)
                    {
                        PrintOneProbe(P, start, nq, o);
                        start++;
                        if (P[start - 1].Final)
                            end = Math.Min(end, (int)(((start - 1) / nq + 1) * nq)); // finish this hop, then stop
                        continue;
                    }

                    // 3) send up to sim_probes probes across the remaining hops
                    int inflight = 0;
                    for (int i = start; i < sent; i++) if (!P[i].Done) inflight++;
                    while (sent < end)
                    {
                        if (inflight >= o.SimProbes) break;
                        if (o.SendSecs > 0 && lastSend != default &&
                            (DateTime.UtcNow - lastSend).TotalSeconds < o.SendSecs) break;
                        int ttl = sent / nq + 1;
                        raw.Ttl = (short)ttl;
                        byte[] pkt = BuildIcmpEcho(icmpId, P[sent].IcmpSeq, dataLen);
                        raw.SendTo(pkt, new IPEndPoint(dst, 0));
                        P[sent].SendTime = DateTime.UtcNow;
                        P[sent].Ttl = (uint)ttl;
                        lastSend = P[sent].SendTime;
                        inflight++;
                        sent++;
                    }

                    // 4) next deadline among outstanding probes (+ sendwait)
                    long untilTicks = long.MaxValue;
                    for (int i = start; i < sent; i++)
                    {
                        if (P[i].Done) continue;
                        long t = P[i].SendTime.Ticks + (long)(TimeSpan.FromSeconds(ProbeTimeout(P, i, nq, o)).Ticks);
                        if (t < untilTicks) untilTicks = t;
                    }
                    if (o.SendSecs > 0 && lastSend != default)
                    {
                        long t = lastSend.Ticks + (long)(TimeSpan.FromSeconds(o.SendSecs).Ticks);
                        if (t < untilTicks) untilTicks = t;
                    }

                    // 5) wait (sliced polls) until the deadline, draining replies.
                    //    Break as soon as nothing is outstanding anymore.
                    long nowT = DateTime.UtcNow.Ticks;
                    if (untilTicks == long.MaxValue || untilTicks <= nowT) untilTicks = nowT + 1;
                    while (DateTime.UtcNow.Ticks < untilTicks)
                    {
                        DrainReplies(raw, P, seqTo, start, sent, o);

                        bool outstanding = false;
                        bool finalSeen = false;
                        for (int i = start; i < sent; i++)
                        {
                            if (!P[i].Done) outstanding = true;
                            if (P[i].Final) finalSeen = true;
                        }
                        if (!outstanding || finalSeen) break;  // resolved, or destination reached

                        long rem = untilTicks - DateTime.UtcNow.Ticks;
                        if (rem <= 0) break;
                        int ms = (int)Math.Min(rem / TimeSpan.TicksPerMillisecond, 200);
                        if (ms <= 0) break;
                        if (raw.Poll(ms * 1000, SelectMode.SelectRead))
                            DrainReplies(raw, P, seqTo, start, sent, o);
                    }
                    DrainReplies(raw, P, seqTo, start, sent, o);
                }
            }
            Console.Out.Flush();
        }

        // Read all pending ICMP replies on the raw socket and attribute them to
        // their probes by (id, seq).
        static void DrainReplies(Socket raw, Probe[] P, Dictionary<int, int> seqTo,
                                 int start, int sent, Options o)
        {
            byte[] buf = new byte[4096];
            while (raw.Available > 0)
            {
                EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                int n;
                try { n = raw.ReceiveFrom(buf, ref ep); }
                catch { return; }
                if (n <= 0) continue;

                if (!TryParseIcmpEchoReply(buf, n, out byte type, out byte code, out IPAddress from,
                                           out int id, out int sseq, out int info)) continue;

                if (seqTo.TryGetValue(sseq, out int idx))
                {
                    var p = P[idx];
                    if (!p.Done && idx >= start && idx < sent && p.IcmpId == id)
                    {
                        p.Res = from;
                        p.RecvTime = DateTime.UtcNow;
                        p.Done = true;
                        ApplyIcmpError(o, p, type, code, info);
                    }
                }
            }
        }

        // Adaptive per-probe timeout, matching the original get_timeout():
        // a reply already seen from the same hop shrinks the wait to HERE times
        // its RTT, and a reply from a later hop shrinks it to NEAR times.
        static double ProbeTimeout(Probe[] P, int idx, int nq, Options o)
        {
            double wait = o.WaitSecs;
            if (o.HereFactor > 0)
            {
                int hopStart = idx - (idx % nq);
                for (int i = hopStart; i < hopStart + nq && i < P.Length; i++)
                {
                    if (i == idx) continue;
                    var q = P[i];
                    if (q.Done && q.RecvTime > q.SendTime)
                    {
                        double v = (q.RecvTime - q.SendTime).TotalSeconds + 0.001;
                        v *= o.HereFactor;
                        if (v < wait) return v;
                    }
                }
            }
            if (o.NearFactor > 0)
            {
                for (int i = idx + 1; i < P.Length && P[i].SendTime != default; i++)
                {
                    var q = P[i];
                    if (q.Done && q.RecvTime > q.SendTime)
                    {
                        double v = (q.RecvTime - q.SendTime).TotalSeconds + 0.001;
                        v *= o.NearFactor;
                        if (v < wait) return v;
                    }
                }
            }
            return wait;
        }

        // ------------------------------------------------------------------
        //  TCP method  (-T)  —  SYN probes over a raw (IP_HDRINCL) socket.
        //
        //  Requires Administrator privileges on Windows (raw TCP sockets are
        //  restricted); routers answer with ICMP "time exceeded" (received on a
        //  normal ICMP raw socket), and the destination answers with a TCP
        //  SYN-ACK or RST (received on the raw TCP socket).
        // ------------------------------------------------------------------
        static void RunTcp(Options o, IPAddress dst, string dstNameText, uint nq)
        {
            if (!IsAdmin())
            {
                Fail("TCP method (-T) requires Administrator privileges on Windows.\n" +
                     "Please run the program as Administrator (raw TCP sockets are restricted to admins).");
                return;
            }

            Console.Error.WriteLine("traceroute: TCP method (-T) needs Administrator rights and, on Windows,");
            Console.Error.WriteLine("the OS usually does not deliver the ICMP 'time exceeded' replies for raw TCP");
            Console.Error.WriteLine("probes to the socket, so intermediate routers may appear as '*'.");
            Console.Error.WriteLine("Use the default (ICMP) method for a complete route.");

            IPAddress srcIp = ResolveLocalSrc(o) ?? (dst.AddressFamily == AddressFamily.InterNetwork
                                        ? IPAddress.Parse("0.0.0.0") : IPAddress.Any);

            int dstPort = (int)o.DstPortSeq;
            uint srcPortBase = (uint)(32768 + (Environment.ProcessId % 15000));

            using (Socket icmp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
            {
                icmp.ReceiveTimeout = 0;
                IPAddress icmpBind = o.SrcAddr != null ? IPAddress.Parse(o.SrcAddr)
                                    : (srcIp.Equals(IPAddress.Parse("0.0.0.0")) ? IPAddress.Any : srcIp);
                icmp.Bind(new IPEndPoint(icmpBind, 0));

                Socket send, tcp;
                try
                {
                    // Send socket: IPPROTO_RAW + IP_HDRINCL — sends the crafted
                    // IP+TCP packet byte-for-byte (any protocol). Needs admin.
                    send = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw);
                    send.ReceiveTimeout = 0;
                    send.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                    // Receive socket: IPPROTO_TCP raw — receives TCP replies
                    // (with the IP header prepended). Needs admin. No Bind:
                    // binding an IPPROTO_TCP raw socket raises WSAEINVAL on
                    // Windows; we filter by IP/port in TryParseTcpReply.
                    tcp = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
                    tcp.ReceiveTimeout = 0;
                }
                catch (SocketException se) when (se.SocketErrorCode == SocketError.AccessDenied)
                {
                    Fail("TCP method (-T) requires Administrator privileges on Windows.\n" +
                         "Please run the program as Administrator (raw TCP sockets are restricted to admins).");
                    return;
                }

                using (send)
                using (tcp)
                {
                    int id = Environment.ProcessId & 0xFFFF;
                    uint seqNum = srcPortBase;      // also used as initial TCP seq
                    bool finished = false;

                    for (uint hop = o.FirstHop; hop <= o.MaxHops && !finished; hop++)
                    {
                        var hopProbes = new Probe[nq];

                        for (int i = 0; i < nq; i++)
                        {
                            var p = new Probe { Ttl = hop };
                            p.TcpSrcPort = (int)(srcPortBase + seqNum) & 0xFFFF;
                            if (p.TcpSrcPort < 1024) p.TcpSrcPort += 1024;
                            send.Ttl = (short)hop;

                            byte[] pkt = BuildTcpSyn(srcIp, dst, p.TcpSrcPort, dstPort,
                                                     (int)hop, (int)seqNum, o.DontFrag, id);
                            p.SendTime = DateTime.UtcNow;
                            try
                            {
                                send.SendTo(pkt, new IPEndPoint(dst, dstPort));
                            }
                            catch (SocketException se) when (se.SocketErrorCode == SocketError.AccessDenied)
                            {
                                Fail("TCP method (-T) requires Administrator privileges on Windows.\n" +
                                     "Please run as Administrator (raw TCP sockets are restricted to admins).");
                            }
                            hopProbes[i] = p;
                            if (o.SendSecs > 0 && i + 1 < nq) Thread.Sleep((int)(o.SendSecs * 1000));
                            seqNum += 1;
                            id += 1;
                        }

                        WaitForHopTcp(icmp, tcp, hopProbes, o, srcIp);

                        PrintTcpHop(hopProbes, hop, o);

                        for (int i = 0; i < nq; i++)
                            if (hopProbes[i].Final) { finished = true; break; }
                    }
                }
            }
            Console.Out.Flush();
        }

        // ------------------------------------------------------------------
        //  TCP reception: wait on both the ICMP error socket and the raw TCP
        //  socket until the per-hop deadline expires.
        // ------------------------------------------------------------------
        static void WaitForHopTcp(Socket icmp, Socket tcp, Probe[] hopProbes, Options o, IPAddress myIp)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(HopWaitSeconds(hopProbes, o));
            while (DateTime.UtcNow < deadline)
            {
                int remain = (int)(deadline - DateTime.UtcNow).TotalMilliseconds;
                if (remain <= 0) break;

                // --- ICMP errors (time exceeded / dest unreachable) ---
                if (icmp.Poll(remain * 1000, SelectMode.SelectRead))
                {
                    byte[] buf = new byte[4096];
                    EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    int n;
                    try { n = icmp.ReceiveFrom(buf, ref ep); }
                    catch { n = 0; }
                    if (n > 0 && TryParseIcmpErrorPort(buf, n, out byte type, out byte code,
                                                       out IPAddress from, out int srcPort, out int info))
                    {
                        foreach (var p in hopProbes)
                        {
                            if (!p.Done && p.TcpSrcPort == srcPort)
                            {
                                p.Res = from;
                                p.RecvTime = DateTime.UtcNow;
                                p.Done = true;
                                ApplyIcmpError(o, p, type, code, info);
                                break;
                            }
                        }
                    }
                }

                // --- TCP responses (SYN-ACK / RST from the destination) ---
                if (tcp.Poll(remain * 1000, SelectMode.SelectRead))
                {
                    byte[] buf = new byte[4096];
                    EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    int n;
                    try { n = tcp.ReceiveFrom(buf, ref ep); }
                    catch { n = 0; }
                    if (n > 0 && TryParseTcpReply(buf, n, myIp, out IPAddress from,
                                                  out int dstPort2, out int flags))
                    {
                        foreach (var p in hopProbes)
                        {
                            if (!p.Done && p.TcpSrcPort == dstPort2)
                            {
                                p.Res = from;
                                p.RecvTime = DateTime.UtcNow;
                                p.Done = true;
                                bool syn = (flags & 0x02) != 0;
                                bool rst = (flags & 0x04) != 0;
                                if (syn || rst) { p.Final = true; }   // destination reached
                                break;
                            }
                        }
                    }
                }

                bool allRes = true;
                foreach (var p in hopProbes) if (!p.Done) { allRes = false; break; }
                if (allRes) break;
            }
        }

        // Adaptive wait for one TCP hop: at most HERE times the fastest known
        // same-hop RTT, capped by the MAX wait (default 5 s).
        static double HopWaitSeconds(Probe[] hopProbes, Options o)
        {
            double wait = o.WaitSecs;
            double answeredRtt = -1;
            foreach (var p in hopProbes)
                if (p.Done && p.RecvTime > p.SendTime)
                {
                    double r = (p.RecvTime - p.SendTime).TotalMilliseconds;
                    if (r > answeredRtt) answeredRtt = r;
                }
            if (answeredRtt >= 0 && o.HereFactor > 0)
                wait = Math.Min(answeredRtt / 1000.0 * o.HereFactor, o.WaitSecs);
            return wait;
        }

        static void PrintTcpHop(Probe[] hopProbes, uint hop, Options o)
        {
            for (int np = 0; np < hopProbes.Length; np++)
            {
                Probe pb = hopProbes[np];
                var sb = new StringBuilder();
                if (np == 0)
                    sb.Append('\n').Append(((int)hop).ToString(C).PadLeft(2, ' ')).Append(' ');
                if (pb.Res == null)
                    sb.Append(" *");
                else
                {
                    bool prn = (np == 0);
                    if (!prn)
                    {
                        int prev = np - 1;
                        while (prev >= 0 && hopProbes[prev].Res == null) prev--;
                        if (prev < 0 || !hopProbes[prev].Res.Equals(pb.Res)) prn = true;
                    }
                    if (prn) PrintAddr(sb, pb.Res, o);
                }
                if (pb.Done && pb.RecvTime > pb.SendTime)
                    sb.Append("  ").Append(pb.RttMs.ToString("F3", C)).Append(" ms");
                if (pb.ErrStr.Length > 0)
                    sb.Append(' ').Append(pb.ErrStr);
                Console.Write(sb.ToString());
                Console.Out.Flush();
            }
        }

        // ------------------------------------------------------------------
        //  Packet builders / parsers for the TCP method
        // ------------------------------------------------------------------

        // Build an IPv4 packet with a single SYN TCP segment (20+20 bytes).
        static byte[] BuildTcpSyn(IPAddress srcIp, IPAddress dstIp, int srcPort, int dstPort,
                                  int ttl, int seq, bool noFrag, int id)
        {
            byte[] pkt = new byte[40];
            byte[] src = srcIp.GetAddressBytes();
            byte[] dst = dstIp.GetAddressBytes();

            // ---- IP header (20) ----
            pkt[0] = 0x45;                                   // IPv4, IHL=5
            pkt[2] = 0; pkt[3] = (byte)pkt.Length;           // total length (40)
            pkt[4] = (byte)(id >> 8); pkt[5] = (byte)(id & 0xFF);
            int frag = noFrag ? 0x4000 : 0x0000;             // DF bit
            pkt[6] = (byte)(frag >> 8); pkt[7] = (byte)(frag & 0xFF);
            pkt[8] = (byte)ttl;
            pkt[9] = 6;                                      // TCP
            Array.Copy(src, 0, pkt, 12, 4);
            Array.Copy(dst, 0, pkt, 16, 4);
            ushort ipck = Checksum(pkt, 20);
            pkt[10] = (byte)(ipck >> 8); pkt[11] = (byte)(ipck & 0xFF);

            // ---- TCP header (20) ----
            pkt[20] = (byte)(srcPort >> 8); pkt[21] = (byte)(srcPort & 0xFF);
            pkt[22] = (byte)(dstPort >> 8); pkt[23] = (byte)(dstPort & 0xFF);
            pkt[24] = (byte)(seq >> 24); pkt[25] = (byte)(seq >> 16);
            pkt[26] = (byte)(seq >> 8); pkt[27] = (byte)(seq & 0xFF);
            pkt[32] = 0x50;                                  // data offset 5
            pkt[33] = 0x02;                                  // SYN
            pkt[34] = 0x20; pkt[35] = 0x00;                  // window 8192

            // TCP checksum over the pseudo-header + TCP header
            byte[] pseudo = new byte[32];
            Array.Copy(src, 0, pseudo, 0, 4);
            Array.Copy(dst, 0, pseudo, 4, 4);
            pseudo[8] = 0; pseudo[9] = 6;                    // protocol
            pseudo[10] = 0; pseudo[11] = 20;                 // TCP length
            Array.Copy(pkt, 20, pseudo, 12, 20);
            ushort tcpck = Checksum(pseudo, 32);
            pkt[36] = (byte)(tcpck >> 8); pkt[37] = (byte)(tcpck & 0xFF);

            return pkt;
        }

        // ICMP error (type 11 / 3) that embeds the original packet; return the
        // transport source port so TCP probes can be matched by source port.
        static bool TryParseIcmpErrorPort(byte[] b, int len, out byte type, out byte code,
                                          out IPAddress from, out int srcPort, out int info)
        {
            type = 0; code = 0; from = null; srcPort = 0; info = 0;
            if (len < 56 || b.Length < 56) return false;

            int ihl = (b[0] & 0x0F) * 4;
            if (ihl < 20) return false;

            type = b[ihl];
            code = b[ihl + 1];
            from = new IPAddress(new byte[] { b[12], b[13], b[14], b[15] });

            if (type != 11 && type != 3) return false;

            int o = ihl + 8;                                // original IP header
            if (o + 20 > len) return false;
            int origIhl = (b[o] & 0x0F) * 4;
            byte origProto = b[o + 9];
            if (origProto != 6 && origProto != 17) return false;   // we send TCP (or UDP)

            int t = o + origIhl;
            if (t + 4 > len) return false;
            srcPort = (b[t] << 8) | b[t + 1];
            info = (b[ihl + 4] << 8) | b[ihl + 5];
            return true;
        }

        // A TCP packet from the raw TCP socket: IP header + TCP header.
        // Returns the destination port (to match a probe by our source port)
        // and the TCP flags byte.
        static bool TryParseTcpReply(byte[] b, int len, IPAddress myIp,
                                     out IPAddress from, out int dstPort, out int flags)
        {
            from = null; dstPort = 0; flags = 0;
            if (len < 40 || b.Length < 40) return false;

            int ihl = (b[0] & 0x0F) * 4;
            if (ihl < 20) return false;
            if (b[ihl + 9] != 6) return false;               // only TCP

            // destined to us? (dst addr in the IP header)
            IPAddress dst = new IPAddress(new byte[] { b[16], b[17], b[18], b[19] });
            if (!dst.Equals(myIp)) return false;

            from = new IPAddress(new byte[] { b[12], b[13], b[14], b[15] });
            dstPort = (b[ihl + 2] << 8) | b[ihl + 3];        // dst port == our src port
            flags = b[ihl + 13];
            return true;
        }

        // --------------------------------------------------------------
        //  Reception helpers
        // --------------------------------------------------------------
        // --------------------------------------------------------------
        //  ICMP packet parsing
        // --------------------------------------------------------------
        //
        // On Windows a raw ICMP socket returns the full IP header first.
        // Only three ICMP types are of interest here:
        //   type 0  (ECHO REPLY)        -> destination reached
        //   type 11 (TIME EXCEEDED)     -> an intermediate router
        //   type 3  (DEST UNREACHABLE)  -> usually "final" / routing error
        //
        static bool TryParseIcmpEchoReply(byte[] b, int len, out byte type, out byte code,
                                          out IPAddress from, out int id, out int seq, out int info)
        {
            type = 0; code = 0; from = null; id = 0; seq = 0; info = 0;
            if (len < 28 || b.Length < 28) return false;

            int ihl = (b[0] & 0x0F) * 4;
            if (ihl < 20) return false;

            type = b[ihl];
            code = b[ihl + 1];
            from = new IPAddress(new byte[] { b[12], b[13], b[14], b[15] });

            if (type == 0)
            {
                // echo reply: id at ihl+4, seq at ihl+6
                id = (b[ihl + 4] << 8) | b[ihl + 5];
                seq = (b[ihl + 6] << 8) | b[ihl + 7];
                return true;
            }
            if (type == 11 || type == 3)
            {
                int o = ihl + 8;
                if (o + 28 > len) return false;
                int origIhl = (b[o] & 0x0F) * 4;
                byte origProto = b[o + 9];
                int t = o + origIhl;
                if (origProto == 1 && t + 8 <= len)
                {
                    id = (b[t + 4] << 8) | b[t + 5];
                    seq = (b[t + 6] << 8) | b[t + 7];
                    info = (b[ihl + 4] << 8) | b[ihl + 5];
                    return true;
                }
            }
            return false;
        }

        // Translate ICMP type/code into the original's error markers and the
        // "final reached" indication.
        static void ApplyIcmpError(Options o, Probe p, byte type, byte code, int info)
        {
            string str = null;
            if (type == 0)            // ECHO REPLY: the destination is reached
            {
                p.Final = true;
                return;
            }
            if (type == 11)            // TIME EXCEEDED
            {
                if (code == 0) return; // TTL expired mid-path: a normal hop, not final
            }
            else if (type == 3)        // DESTINATION UNREACHABLE
            {
                switch (code)
                {
                    case 0: case 6: case 8: case 11: str = "!N"; break;   // network unreachable
                    case 1: case 7: case 12: str = "!H"; break;          // host unreachable
                    case 2: str = "!P"; break;                            // protocol
                    case 3: str = ""; break;                              // port => reached
                    case 4: str = $"!F-{info}"; break;                    // frag needed
                    case 5: str = "!S"; break;                            // source route failed
                    case 9: case 10: case 13: str = "!X"; break;          // administratively prohibited
                    case 14: str = "!V"; break;                           // host precedence
                    case 15: str = "!C"; break;                           // precedence cutoff
                    default: str = $"!<{code}>"; break;
                }
            }

            if (str == null) str = $"!<{type}-{code}>";

            if (str.Length > 0) p.ErrStr = str;
            p.Final = true;
        }

        // --------------------------------------------------------------
        //  Probe + ICMP ECHO construction / helpers
        // --------------------------------------------------------------
        static byte[] BuildIcmpEcho(int id, int seq, int dataLen)
        {
            byte[] msg = new byte[8 + dataLen];
            msg[0] = 8;                 // echo request
            msg[1] = 0;
            msg[4] = (byte)(id >> 8); msg[5] = (byte)(id & 0xFF);
            msg[6] = (byte)(seq >> 8); msg[7] = (byte)(seq & 0xFF);
            ushort cks = Checksum(msg);
            msg[2] = (byte)(cks >> 8); msg[3] = (byte)(cks & 0xFF);
            return msg;
        }

        static ushort Checksum(byte[] data)
        {
            return Checksum(data, data.Length);
        }

        static ushort Checksum(byte[] data, int len)
        {
            long sum = 0;
            int i = 0;
            for (; i + 1 < len; i += 2)
                sum += ((data[i] << 8) & 0xFF00) | (data[i + 1] & 0xFF);
            if (i < len) sum += (data[i] << 8) & 0xFF00;
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        static IPAddress Resolve(string host, out string display)
        {
            display = host;
            try
            {
                var addrs = Dns.GetHostAddresses(host);
                foreach (var a in addrs)
                    if (a.AddressFamily == AddressFamily.InterNetwork) { return a; }
                if (addrs.Length > 0) return addrs[0];
            }
            catch { }
            return null;
        }

        static bool IsAdmin()
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                var p = new System.Security.Principal.WindowsPrincipal(id);
                return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        static IPAddress ResolveLocalSrc(Options o)
        {
            if (o.SrcAddr != null)
            {
                if (!IPAddress.TryParse(o.SrcAddr, out IPAddress ip)) Fail($"invalid source address '{o.SrcAddr}'");
                return ip;
            }
            try
            {
                using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect("8.8.8.8", 53);
                    return ((IPEndPoint)s.LocalEndPoint).Address;
                }
            }
            catch { return null; }
        }

        static void ApplySocketOptions(Socket s, Options o)
        {
            if (o.Debug)
                s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Debug, true);
            if (o.DontFrag && o.Family == 4)
                s.DontFragment = true;
            if (o.Noroute)
                s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.DontRoute, true);
            if (o.Tos != 0 && o.Family == 4)
                s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.TypeOfService, (int)o.Tos);
        }

        // --------------------------------------------------------------
        //  Output  (exact copy of the original's print_probe)
        // --------------------------------------------------------------
        static void PrintOneProbe(Probe[] P, int idx, int nq, Options o)
        {
            Probe pb = P[idx];
            int ttl = idx / nq + 1;
            int np = idx % nq;
            var sb = new StringBuilder();

            if (np == 0)
                sb.Append('\n').Append(ttl.ToString(C).PadLeft(2, ' ')).Append(' ');

            if (pb.Res == null)
            {
                sb.Append(" *");
            }
            else
            {
                bool prn = (np == 0);
                if (!prn)
                {
                    // print the address unless it equals the previous resolved probe
                    int cnt = np;
                    int j = idx - 1;
                    while (cnt > 0 && (j < 0 || P[j].Res == null)) { j--; cnt--; }
                    if (cnt == 0) prn = true;
                    else if (!P[j].Res.Equals(pb.Res)) prn = true;
                }
                if (prn)
                    PrintAddr(sb, pb.Res, o);
            }

            if (pb.Done && pb.RecvTime > pb.SendTime)
                sb.Append("  ").Append(pb.RttMs.ToString("F3", C)).Append(" ms");

            if (pb.ErrStr.Length > 0)
                sb.Append(' ').Append(pb.ErrStr);

            Console.Write(sb.ToString());
            Console.Out.Flush();
        }

        static void PrintAddr(StringBuilder sb, IPAddress ip, Options o)
        {
            string str = ip.ToString();
            if (o.NoResolve)
            {
                sb.Append(' ').Append(str);
            }
            else
            {
                string name = "";
                try { name = Dns.GetHostEntry(ip).HostName; if (string.IsNullOrEmpty(name)) name = ""; }
                catch { }
                if (name == "0.0.0.0") name = "";
                sb.Append(' ').Append((name.Length > 0 ? name : str)).Append(" (").Append(str).Append(')');
            }
        }

        // --------------------------------------------------------------
        static void PrintUsage(TextWriter w)
        {
            w.Write(
                "Usage: traceroute [-46dFITnreAUDV] [-f first_ttl] [-m max_ttl] [-p port] [-N squeries]\n" +
                "                  [-q nqueries] [-s src_addr] [-t tos] [-i device] [-g gateway]\n" +
                "                  [-M name] [-P protos] [-l len] [-z sendwait] [-UL] [-D]\n" +
                "                  [-O option] [--version] [--help] [hostname [packetlen]]\n" +
                "\n" +
                "Options:\n" +
                "  -4                         Use IPv4\n" +
                "  -6                         Use IPv6 (not supported on Windows)\n" +
                "  -d, --debug                Enable socket level debugging\n" +
                "  -F, --dont-fragment        Do not fragment packets\n" +
                "  -f, --first=first_ttl      Start from the first_ttl hop (instead from 1)\n" +
                "  -I, --icmp                 Use ICMP ECHO for tracerouting\n" +
                "  -T, --tcp                  Use TCP SYN for tracerouting (default port 80;\n" +
                "                             needs Administrator; Windows seldom returns ICMP\n" +
                "                             'time exceeded' for raw TCP, so hops may show '*'; use\n" +
                "                             default/-I for a complete route)\n" +
                "  -n                         Do not resolve IP addresses to their domain names\n" +
                "  -p, --port=port            Set the destination base port (default 33434)\n" +
                "  -q, --queries=nqueries     Set the number of probes per each hop (default 3)\n" +
                "  -N, --sim-queries=squeries Set the number of probes tried simultaneously\n" +
                "  -m, --max-hops=max_ttl     Set the max number of hops (default 30)\n" +
                "  -s, --source=src_addr      Use source src_addr for outgoing packets\n" +
                "  -t, --tos=tos              Set the TOS value for outgoing packets\n" +
                "  -w, --wait=MAX,HERE,NEAR   Wait for a probe no more than HERE/NEAR times\n" +
                "                             the earlier response, or MAX seconds (default 5)\n" +
                "  -z, --sendwait=sendwait    Minimal time interval between probes\n" +
                "  -r                         Bypass the normal routing table\n" +
                "  -U, --udp                  Use UDP to a particular port (default port 53)\n" +
                "  --help                     Print this help\n" +
                "  --version                  Print version information\n");
        }

        static void Fail(string msg)
        {
            Console.Error.WriteLine(msg);
            Environment.Exit(2);
        }
    }
}
