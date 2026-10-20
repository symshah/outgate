using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Outbound.Core.Network;
using Outbound.Core.Engine;

namespace Outbound.Core.Etw;

public enum NetOp { Send, Recv, Connect, Accept }

/// <summary>One kernel TCP/IP or UDP/IP event (TcpIp_TypeGroup1 / UdpIp_TypeGroup1 + IPv6 variants).</summary>
public sealed record NetEvent(DateTime Utc, int Pid, Protocol Proto, NetOp Op,
    string LocalIp, ushort LocalPort, string RemoteIp, ushort RemotePort, int Size);

/// <summary>Microsoft-Windows-DNS-Client event 3008 "DNS query is completed for the name %1 ... Results %5".</summary>
public sealed record DnsEvent(DateTime Utc, int Pid, string Name, IReadOnlyList<string> Addresses, int Status);

/// <summary>
/// Two real-time ETW sessions (needs elevation):
///  1. OutboundWin-Net: kernel provider, keyword NetworkTCPIP → TcpIp/UdpIp Send/Recv/Connect/Accept (v4+v6)
///     with PID, size, daddr, saddr, dport, sport.
///  2. OutboundWin-Dns: Microsoft-Windows-DNS-Client {1c95126e-…}, event 3008 → QueryName + QueryResults.
/// </summary>
public sealed class EtwNetworkCollector : IDisposable
{
    public const string NetSessionName = "OutboundWin-Net";
    public const string DnsSessionName = "OutboundWin-Dns";
    public static readonly Guid DnsClientProvider = new("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");
    public const int DnsQueryCompletedEventId = 3008;

    private TraceEventSession? _net, _dns;
    private long _netCount, _dnsCount;
    public long NetEventCount => Interlocked.Read(ref _netCount);
    public long DnsEventCount => Interlocked.Read(ref _dnsCount);

    public event Action<NetEvent>? Net;
    public event Action<DnsEvent>? Dns;
    /// <summary>(pid, parentPid, exe path or null, isNewStart)</summary>
    public event Action<int, int, string?, bool>? ProcessSeen;

    public static bool CanRun => TraceEventSession.IsElevated() == true;

    /// <summary>Stop leftover sessions from a crashed run (ours, plus old probe names starting "Outbound").</summary>
    public static List<string> StopStaleSessions()
    {
        var stopped = new List<string>();
        foreach (var n in TraceEventSession.GetActiveSessionNames())
        {
            if (!n.StartsWith("Outbound", StringComparison.OrdinalIgnoreCase)) continue;
            try { using var s = TraceEventSession.GetActiveSession(n); s?.Stop(true); stopped.Add(n); } catch { }
        }
        return stopped;
    }

    public void Start()
    {
        EngineLog.Write($"ETW start: elevated={CanRun}, packet-dns={CapturePacketDns}");
        if (!CanRun) throw new UnauthorizedAccessException("ETW real-time sessions need elevation (run Outbound as administrator)");
        var stopped = StopStaleSessions();
        if (stopped.Count > 0) EngineLog.Write("stale sessions stopped before start: " + string.Join(", ", stopped));

        _net = new TraceEventSession(NetSessionName) { StopOnDispose = true, BufferSizeMB = 64 };
        // Process keyword adds Process/Start + DCStart rundown with the image path, so short-lived
        // processes (curl) keep their identity even when their network events are read after exit.
        _net.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process);
        var k = _net.Source.Kernel;
        k.ProcessStart += e => ProcessSeen?.Invoke(e.ProcessID, e.ParentID, ExeFrom(e), true);
        k.ProcessDCStart += e => ProcessSeen?.Invoke(e.ProcessID, e.ParentID, ExeFrom(e), false);
        k.TcpIpSend += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Send, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        k.TcpIpRecv += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Recv, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        k.TcpIpConnect += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Connect, e.saddr, e.sport, e.daddr, e.dport, 0, e.TimeStamp);
        k.TcpIpAccept += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Accept, e.saddr, e.sport, e.daddr, e.dport, 0, e.TimeStamp);
        k.TcpIpSendIPV6 += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Send, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        k.TcpIpRecvIPV6 += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Recv, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        k.TcpIpConnectIPV6 += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Connect, e.saddr, e.sport, e.daddr, e.dport, 0, e.TimeStamp);
        k.TcpIpAcceptIPV6 += e => Emit(e.ProcessID, Protocol.Tcp, NetOp.Accept, e.saddr, e.sport, e.daddr, e.dport, 0, e.TimeStamp);
        k.UdpIpSend += e => Emit(e.ProcessID, Protocol.Udp, NetOp.Send, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        // UDP Recv uses literal packet semantics (daddr = this PC), unlike TCP Recv (daddr = remote peer).
        // Verified live: Chrome's DNS replies arrived as daddr=192.168.31.2:<ephemeral>, saddr=192.168.31.1:53.
        k.UdpIpRecv += e => Emit(e.ProcessID, Protocol.Udp, NetOp.Recv, e.daddr, e.dport, e.saddr, e.sport, e.size, e.TimeStamp);
        k.UdpIpSendIPV6 += e => Emit(e.ProcessID, Protocol.Udp, NetOp.Send, e.saddr, e.sport, e.daddr, e.dport, e.size, e.TimeStamp);
        k.UdpIpRecvIPV6 += e => Emit(e.ProcessID, Protocol.Udp, NetOp.Recv, e.daddr, e.dport, e.saddr, e.sport, e.size, e.TimeStamp);
        // The reader must never die silently: a dead reader means zero events and zero bytes with
        // no visible error (the exact symptom that made every byte count read 0).
        var tn = new Thread(() =>
        {
            try { _net.Source.Process(); EngineLog.Write("etw-net reader exited normally"); }
            catch (Exception ex) { EngineLog.MonitoringFailed("ETW network reader stopped", ex); }
        }) { IsBackground = true, Name = "etw-net" };
        tn.Start();
        EngineLog.Write($"ETW network session '{NetSessionName}' started (kernel NetworkTCPIP+Process)");

        _dns = new TraceEventSession(DnsSessionName) { StopOnDispose = true, BufferSizeMB = 16 };
        _dns.EnableProvider(DnsClientProvider, TraceEventLevel.Verbose, ulong.MaxValue);
        if (CapturePacketDns)
            _dns.EnableProvider(NdisCaptureProvider, TraceEventLevel.Informational, NdisReceiveKeywords);
        var reg = new RegisteredTraceEventParser(_dns.Source);
        reg.All += OnDns;
        var td = new Thread(() =>
        {
            try { _dns.Source.Process(); EngineLog.Write("etw-dns reader exited normally"); }
            catch (Exception ex) { EngineLog.MonitoringFailed("ETW DNS reader stopped", ex); }
        }) { IsBackground = true, Name = "etw-dns" };
        td.Start();
        EngineLog.Write($"ETW DNS session '{DnsSessionName}' started");
    }

    public static string? LastRawImage;
    /// <summary>Exe path from a Process/Start event: kernel image path, else the command line's first token, else PATH search.</summary>
    private static string? ExeFrom(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData e)
    {
        string? kimg = null, cl = null, img = null;
        try { kimg = e.KernelImageFileName; } catch { }
        try { cl = e.CommandLine?.Trim(); } catch { }
        try { img = e.ImageFileName; } catch { }
        LastRawImage = $"kimg='{kimg}' img='{img}' cl='{cl}'";
        var p = DevicePaths.ToDos(kimg);
        if (p != null && File.Exists(p)) return p;
        if (!string.IsNullOrEmpty(cl))
        {
            string first = cl[0] == '"' ? cl[1..].Split('"')[0] : cl.Split(' ')[0];
            if (first.StartsWith(@"\??\")) first = first[4..];
            if (Path.IsPathRooted(first) && File.Exists(first)) return first;
        }
        if (!string.IsNullOrEmpty(img))
        {
            if (Path.IsPathRooted(img) && File.Exists(img)) return img;
            var sys = Path.Combine(Environment.SystemDirectory, Path.GetFileName(img));
            if (File.Exists(sys)) return sys;
        }
        return null;
    }

    private void Emit(int pid, Protocol p, NetOp op, IPAddress local, int lport, IPAddress remote, int rport, int size, DateTime ts)
    {
        Interlocked.Increment(ref _netCount);
        var r = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote;
        var l = local.IsIPv4MappedToIPv6 ? local.MapToIPv4() : local;
        Net?.Invoke(new NetEvent(ts.ToUniversalTime(), pid, p, op, l.ToString(), (ushort)lport, r.ToString(), (ushort)rport, size));
    }

    /// <summary>Microsoft-Windows-NDIS-PacketCapture (in-box ndiscap; same provider netsh trace capture=yes uses).</summary>
    public static readonly Guid NdisCaptureProvider = new("2ed6006e-4729-4609-b423-3ee7bcd678ef");
    // Ethernet802.3 | Native802.11 | ut:ReceivePath | ut:PiiPresent | ut:Packet  (from the provider manifest)
    private const ulong NdisReceiveKeywords = 0x1UL | 0x10000UL | 0x200000000UL | 0x20000000000UL | 0x40000000000UL;
    public bool CapturePacketDns { get; set; } = true;
    private long _wireDns;
    public long WireDnsCount => Interlocked.Read(ref _wireDns);

    private void OnDns(TraceEvent e)
    {
        if (e.ProviderGuid == NdisCaptureProvider)
        {
            if ((int)e.ID != 1001) return;
            if (e.PayloadByName("Fragment") is not byte[] frame) return;
            if (!Pipeline.DnsWire.TryExtractDnsFromEthernet(frame, out var dnsPayload)) return;
            var parsed = Pipeline.DnsWire.ParseResponse(dnsPayload);
            if (parsed == null) return;
            Interlocked.Increment(ref _wireDns);
            Dns?.Invoke(new DnsEvent(e.TimeStamp.ToUniversalTime(), 0, parsed.Value.Name, parsed.Value.Ips, 0));
            return;
        }
        if ((int)e.ID != DnsQueryCompletedEventId) return;
        Interlocked.Increment(ref _dnsCount);
        string? name = (e.PayloadByName("QueryName") ?? SafePayload(e, 0))?.ToString();
        string results = (e.PayloadByName("QueryResults") ?? SafePayload(e, 4))?.ToString() ?? "";
        int status = 0;
        try { status = Convert.ToInt32(e.PayloadByName("QueryStatus") ?? SafePayload(e, 3) ?? 0); } catch { }
        if (string.IsNullOrWhiteSpace(name)) return;
        Dns?.Invoke(new DnsEvent(e.TimeStamp.ToUniversalTime(), e.ProcessID, name.TrimEnd('.'), ParseDnsResults(results), status));
    }

    private static object? SafePayload(TraceEvent e, int i) { try { return i < e.PayloadNames.Length ? e.PayloadValue(i) : null; } catch { return null; } }

    /// <summary>QueryResults looks like "type:  5 cname.example;::ffff:93.184.215.14;2606:2800::1;". Returns IPs only.</summary>
    public static List<string> ParseDnsResults(string results)
    {
        var list = new List<string>();
        foreach (var raw in results.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IPAddress.TryParse(raw, out var ip)) continue;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var s = ip.ToString();
            if (!list.Contains(s)) list.Add(s);
        }
        return list;
    }

    public void Dispose()
    {
        try { _net?.Dispose(); } catch { }
        try { _dns?.Dispose(); } catch { }
        _net = null; _dns = null;
    }
}

/// <summary>\Device\HarddiskVolumeN\… → C:\… via QueryDosDevice.</summary>
public static class DevicePaths
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint QueryDosDeviceW(string name, System.Text.StringBuilder target, int max);
    private static readonly Lazy<List<(string Dev, string Drive)>> Map = new(() =>
    {
        var l = new List<(string, string)>();
        foreach (var d in Environment.GetLogicalDrives())
        {
            var drive = d.TrimEnd('\\'); var sb = new System.Text.StringBuilder(512);
            if (QueryDosDeviceW(drive, sb, sb.Capacity) > 0) l.Add((sb.ToString(), drive));
        }
        return l;
    });

    public static string? ToDos(string? kernelPath)
    {
        if (string.IsNullOrEmpty(kernelPath)) return null;
        if (kernelPath.Length > 2 && kernelPath[1] == ':') return kernelPath;
        if (kernelPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), kernelPath[12..]);
        if (kernelPath.StartsWith(@"\??\")) return kernelPath[4..];
        foreach (var (dev, drive) in Map.Value)
            if (kernelPath.StartsWith(dev + "\\", StringComparison.OrdinalIgnoreCase)) return drive + kernelPath[dev.Length..];
        return null;
    }
}
