using System.Diagnostics;

namespace Outbound.Core.Monitoring;

/// <summary>
/// Best-effort per-process network volume via "Process" performance counters
/// (IO Data Bytes Sent / Received). User-mode, no admin. NOTE: these counters include
/// file IO as well as network — treat the numbers as an activity proxy for PoC display.
/// Phase 2 swaps this for ETW tcpv4/DNS-Client events for true per-flow wire bytes.
/// </summary>
public sealed class ProcessNetCounters : IDisposable
{
    private readonly object _gate = new();
    // One PerformanceCounter pair per PID + last raw values, so we can return per-interval deltas.
    private readonly Dictionary<int, (PerformanceCounter Sent, PerformanceCounter Recv, long LastSent, long LastRecv)> _counters = new();

    /// <summary>Sample counters for the given PIDs; returns deltas since last sample per PID.</summary>
    public IReadOnlyDictionary<int, (long Sent, long Recv)> Sample(IEnumerable<int> pids)
    {
        var result = new Dictionary<int, (long, long)>();
        lock (_gate)
        {
            foreach (var pid in pids.Distinct())
            {
                if (!_counters.TryGetValue(pid, out var prev))
                {
                    try
                    {
                        // First sample primes the baseline; discard it.
                        var s = new PerformanceCounter("Process", "IO Data Bytes Sent", pid.ToString());
                        var r = new PerformanceCounter("Process", "IO Data Bytes Received", pid.ToString());
                        long baseSent = (long)s.NextSample().RawValue;
                        long baseRecv = (long)r.NextSample().RawValue;
                        _counters[pid] = (s, r, baseSent, baseRecv);
                    }
                    catch { /* counter unavailable — skip */ }
                    continue;
                }

                try
                {
                    long sent = (long)prev.Sent.NextSample().RawValue;
                    long recv = (long)prev.Recv.NextSample().RawValue;
                    result[pid] = (Math.Max(0, sent - prev.LastSent), Math.Max(0, recv - prev.LastRecv));
                    _counters[pid] = (prev.Sent, prev.Recv, sent, recv);
                }
                catch { /* process exited between snapshots */ }
            }

            var live = pids.ToHashSet();
            foreach (var dead in _counters.Keys.Where(k => !live.Contains(k)).ToList())
            {
                _counters[dead].Sent.Dispose();
                _counters[dead].Recv.Dispose();
                _counters.Remove(dead);
            }
        }
        return result;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var c in _counters.Values) { c.Sent.Dispose(); c.Recv.Dispose(); }
            _counters.Clear();
        }
    }
}
