using Outbound.Core.Identity;
using Outbound.Core.Network;

namespace Outbound.Core.Monitoring;

/// <summary>A tracked outbound flow with accumulated volume + resolved identity.</summary>
public sealed class TrackedFlow
{
    public required int Pid { get; init; }
    public required string LocalIp { get; init; }
    public required ushort LocalPort { get; init; }
    public required string RemoteIp { get; init; }
    public required ushort RemotePort { get; init; }
    public required Protocol Proto { get; init; }
    public TcpState State { get; set; } = TcpState.Established;

    public long BytesSent { get; internal set; }
    public long BytesReceived { get; internal set; }
    public DateTime FirstSeenUtc { get; internal set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; internal set; } = DateTime.UtcNow;

    /// <summary>Key: remote endpoint + proto (stable for the life of a TCP connection).</summary>
    public string Key => $"{Pid}|{Proto}:{LocalIp}:{LocalPort}->{RemoteIp}:{RemotePort}";

    public SigningIdentity? Identity { get; internal set; }
    public string ProcessName { get; internal set; } = "";
    public string? Hostname { get; internal set; } // resolved via DNS reverse or SNI (phase 2)
}

/// <summary>
/// Polls the OS network tables and maintains a live flow table with per-flow byte deltas.
/// The extended TCP table has no byte counters, so volume is derived from successive
/// snapshots of the *process-level* counters when available; for PoC we track socket
/// lifetime + state transitions and expose counters as best-effort (0 until phase 2
/// adds ETW/perf-counter sampling).
/// </summary>
public sealed class FlowMonitor : IDisposable
{
    private readonly Timer _timer;
    private readonly object _gate = new();
    private Dictionary<string, TrackedFlow> _flows = new();
    private int? _lastPidSeen; // not used — kept for future per-process counter deltas

    public event Action<List<TrackedFlow>>? FlowsUpdated;
    public event Action<TrackedFlow>? FlowAppeared;

    /// <summary>Current snapshot of tracked flows (copy).</summary>
    public List<TrackedFlow> Current { get { lock (_gate) return _flows.Values.ToList(); } }

    public FlowMonitor(int pollIntervalMs = 1000)
    {
        _timer = new Timer(_ => Poll(), null, 0, pollIntervalMs);
    }

    private void Poll()
    {
        List<FlowRow> rows;
        try { rows = NetworkTable.Snapshot(); }
        catch (Exception) { return; } // transient failure — keep last table

        var appeared = new List<TrackedFlow>();
        lock (_gate)
        {
            var seen = new HashSet<string>();
            foreach (var row in rows)
            {
                if (row.Pid <= 4) continue; // skip System
                string key = $"{row.Pid}|{row.Proto}:{row.LocalIp}:{row.LocalPort}->{row.RemoteIp}:{row.RemotePort}";
                if (!seen.Add(key)) continue;

                if (_flows.TryGetValue(key, out var existing))
                {
                    existing.LastSeenUtc = DateTime.UtcNow;
                    existing.State = row.State;
                }
                else
                {
                    var flow = new TrackedFlow
                    {
                        Pid = row.Pid,
                        LocalIp = row.LocalIp,
                        LocalPort = row.LocalPort,
                        RemoteIp = row.RemoteIp,
                        RemotePort = row.RemotePort,
                        Proto = row.Proto,
                        State = row.State,
                        FirstSeenUtc = DateTime.UtcNow,
                        LastSeenUtc = DateTime.UtcNow,
                    };
                    flow.ProcessName = SafeProcessName(row.Pid);
                    _flows[key] = flow;
                    appeared.Add(flow);
                }
            }

            // Drop flows gone from the table (connection closed) — keep for Review via event.
            var stale = _flows.Where(kv => !seen.Contains(kv.Key)).Select(kv => kv.Value).ToList();
            foreach (var s in stale) _flows.Remove(s.Key);
        }

        if (appeared.Count > 0)
            foreach (var a in appeared) FlowAppeared?.Invoke(a);
        FlowsUpdated?.Invoke(Current);
    }

    private static string SafeProcessName(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch { return $"<pid {pid}>"; }
    }

    public void Dispose() => _timer.Dispose();
}
