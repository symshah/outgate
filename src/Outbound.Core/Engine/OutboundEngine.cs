using System.Collections.Concurrent;
using Outbound.Core.Domains;
using Outbound.Core.Etw;
using Outbound.Core.Geo;
using Outbound.Core.Identity;
using Outbound.Core.Network;
using Outbound.Core.Pipeline;
using Outbound.Core.Store;

namespace Outbound.Core.Engine;

/// <summary>
/// Phase 1 data pipeline. Elevated: ETW kernel TCP/IP + DNS-Client 3008 (bytes, endpoints, hostnames).
/// Not elevated: IP Helper snapshot (no bytes) + Get-DnsClientCache for hostnames. The IP Helper snapshot
/// also runs in ETW mode every 5 s as a reconciler (adds flows that were open before we started).
/// </summary>
public sealed class OutboundEngine : IDisposable
{
    private readonly ConcurrentDictionary<FlowKey, FlowStats> _flows = new();
    private EtwNetworkCollector? _etw;
    private Timer? _reconcile, _sample;
    public DnsMap Dns { get; } = new();
    public GeoIp? Geo { get; }
    public PublicSuffixList? Psl { get; }
    public TrafficStore? Store { get; }
    public string Source { get; private set; } = "stopped";
    /// <summary>Why live monitoring is on/off, shown in the status bar and the Overview banner.</summary>
    public string MonitoringReason { get; private set; } = "";
    /// <summary>True when byte-accurate kernel ETW monitoring is running (IP Helper has no byte counters).</summary>
    public bool LiveMonitoring => Source == "etw";
    public long NetEvents => _etw?.NetEventCount ?? 0;
    public long DnsEvents => _etw?.DnsEventCount ?? 0;
    public long WireDnsEvents => _etw?.WireDnsCount ?? 0;
    public string? EtwError { get; private set; }

    /// <summary>Fires once per new (pid, proto, remote ip, port). Phase 2 hooks decisions here.</summary>
    public event Action<FlowStats>? FlowStarted;
    public event Action<DnsEvent>? DnsResolved;

    public OutboundEngine(string? dbPath = null)
    {
        Geo = GeoIp.TryOpenDefault();
        Psl = PublicSuffixList.Default;
        if (dbPath != null) Store = new TrafficStore(dbPath);
    }

    public void Start(bool preferEtw = true)
    {
        if (preferEtw && EtwNetworkCollector.CanRun)
        {
            try
            {
                _etw = new EtwNetworkCollector();
                _etw.ProcessSeen += AppResolver.NoteProcess;
                _etw.Net += OnNet;
                _etw.Dns += e =>
                {
                    Dns.Add(e.Pid, e.Name, e.Addresses, e.Utc);
                    // DNS events come from a separate session and may be read after the flow's packets:
                    // back-fill hostnames on flows that are still unnamed.
                    foreach (var f in _flows.Values)
                        if (f.Host == null && e.Addresses.Contains(f.RemoteIp)) Enrich(f);
                    DnsResolved?.Invoke(e);
                };
                _etw.Start();
                Source = "etw";
                MonitoringReason = "live: ETW kernel NetworkTCPIP sessions (byte counts from TcpIp Send/Recv)";
                EngineLog.Monitoring("live monitoring started (ETW)");
            }
            catch (Exception ex)
            {
                EtwError = ex.Message;
                _etw?.Dispose();
                _etw = null;
                EngineLog.MonitoringFailed("ETW session failed to start", ex);
            }
        }
        if (_etw == null)
        {
            Source = "iphelper";
            Dns.SeedFromSystemCache();
            if (!string.IsNullOrEmpty(EtwError))
            {
                MonitoringReason = "ETW failed: " + EtwError;
            }
            else if (!EtwNetworkCollector.CanRun)
            {
                MonitoringReason = "Outbound is not running as administrator — real-time ETW sessions are admin-only, and the IP Helper fallback has no byte counters";
                EngineLog.MonitoringFailed(MonitoringReason);
            }
            else
            {
                MonitoringReason = "ETW disabled at startup";
                EngineLog.MonitoringFailed(MonitoringReason);
            }
        }
        _reconcile = new Timer(_ => Reconcile(), null, 0, _etw == null ? 2000 : 5000);
        _sample = new Timer(_ => { try { Store?.Flush(_flows.Values, DateTime.UtcNow); } catch { } }, null, 5000, 5000);
    }

    private void OnNet(NetEvent e)
    {
        if (e.Op == NetOp.Accept) return; // inbound accept: not an outbound flow
        var key = new FlowKey(e.Pid, e.Proto, e.RemoteIp, e.RemotePort);
        var f = _flows.TryGetValue(key, out var existing) ? existing : GetOrCreate(key);
        if (e.Op == NetOp.Send) Interlocked.Add(ref f.BytesSent, e.Size);
        else if (e.Op == NetOp.Recv) Interlocked.Add(ref f.BytesRecv, e.Size);
        Interlocked.Increment(ref f.Packets);
        f.LastSeenUtc = e.Utc;
        if (e.Utc < f.FirstSeenUtc) f.FirstSeenUtc = e.Utc; // ETW timestamps can precede our read time
        if (f.Host == null) Enrich(f);
    }

    private FlowStats GetOrCreate(FlowKey key)
    {
        bool created = false;
        var f = _flows.GetOrAdd(key, k =>
        {
            created = true;
            var s = new FlowStats { Key = k, App = AppResolver.Resolve(k.Pid), Geo = Geo?.Lookup(k.RemoteIp) ?? GeoInfo.Unknown };
            Enrich(s);
            return s;
        });
        if (created) { try { FlowStarted?.Invoke(f); } catch { } try { Store?.RecordNewFlow(f); } catch { } }
        return f;
    }

    private void Enrich(FlowStats f)
    {
        var h = Dns.Lookup(f.Pid, f.RemoteIp);
        if (h == null) return;
        f.Host = h;
        f.Domain = Psl?.RegistrableDomain(h) ?? h;
    }

    private void Reconcile()
    {
        try
        {
            if (_etw == null) Dns.SeedFromSystemCache();
            foreach (var r in NetworkTable.Snapshot())
            {
                if (r.Proto != Protocol.Tcp || r.State != TcpState.Established) continue;
                if (r.RemoteIp is "0.0.0.0" or "::" ) continue;
                var key = new FlowKey(r.Pid, Protocol.Tcp, r.RemoteIp, r.RemotePort);
                var f = _flows.TryGetValue(key, out var ex) ? ex : GetOrCreate(key);
                if (_etw == null) f.LastSeenUtc = DateTime.UtcNow;
            }
        }
        catch { }
    }

    public List<FlowStats> Snapshot() => _flows.Values.ToList();

    public void Dispose()
    {
        _reconcile?.Dispose(); _sample?.Dispose();
        try { Store?.Flush(_flows.Values, DateTime.UtcNow); } catch { }
        _etw?.Dispose();
        Store?.Dispose(); Geo?.Dispose();
    }
}
