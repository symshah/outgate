using System.Text.Json;
using Outbound.Core.Engine;

namespace Outbound.Core.Policy;

/// <summary>One app's daily data limit (SPEC Phase 5: set in inspector, notify at 80 %/100 %, optional block until midnight).</summary>
public sealed class AppDataLimit
{
    public string AppKey { get; set; } = "";
    public long LimitBytes { get; set; }
    /// <summary>When true, the app is denied new connections at 100 % until local midnight.</summary>
    public bool BlockUntilMidnight { get; set; }

    // runtime state (not persisted — resets daily)
    [System.Text.Json.Serialization.JsonIgnore]
    public long TodayBytes { get; internal set; }
    [System.Text.Json.Serialization.JsonIgnore]
    public DateTime DayStartLocal { get; internal set; } = DateTime.Today;
    [System.Text.Json.Serialization.JsonIgnore]
    public bool Notified80 { get; internal set; }
    [System.Text.Json.Serialization.JsonIgnore]
    public bool Notified100 { get; internal set; }
    [System.Text.Json.Serialization.JsonIgnore]
    public DateTime? BlockedUntilUtc { get; internal set; }

    public double Percent => LimitBytes <= 0 ? 0 : Math.Min(1.0, (double)TodayBytes / LimitBytes);
}

/// <summary>
/// Daily data limits per app (SPEC Phase 5). Tracks today's bytes from engine snapshots,
/// fires Threshold events at 80 % and 100 %, and optionally blocks the app until local midnight.
/// Limits persist to %LOCALAPPDATA%\OutboundWin\limits.json; usage resets at local midnight.
/// </summary>
public sealed class DataLimitService : IDisposable
{
    private readonly object _gate = new();
    private readonly string? _path;
    private Dictionary<string, AppDataLimit> _limits = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Fired (on a background thread) when an app crosses 80 % or 100 % of its daily limit.</summary>
    public event Action<AppDataLimit, double>? Threshold;
    /// <summary>Fired after any mutation so the UI can re-render.</summary>
    public event Action? Changed;

    public DataLimitService(string? path = null)
    {
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "limits.json");
        Load();
    }

    public List<AppDataLimit> All()
    {
        lock (_gate) return _limits.Values.ToList();
    }

    public AppDataLimit? Find(string appKey)
    {
        lock (_gate) return _limits.TryGetValue(appKey, out var l) ? l : null;
    }

    /// <summary>True when the app is over its daily limit and blocking is on (until local midnight).</summary>
    public bool IsBlocked(string appKey, DateTime nowUtc = default)
    {
        if (nowUtc == default) nowUtc = DateTime.UtcNow;
        lock (_gate)
        {
            var l = _limits.TryGetValue(appKey, out var x) ? x : null;
            return l != null && l.BlockedUntilUtc.HasValue && nowUtc < l.BlockedUntilUtc.Value;
        }
    }

    /// <summary>Feed today's per-app byte totals (from the engine snapshot). Resets counters at local midnight.</summary>
    public void Sample(IEnumerable<FlowStats> flows, DateTime? nowLocal = null)
    {
        var nowL = nowLocal ?? DateTime.Now;
        List<(AppDataLimit L, double Pct)> fired80 = new(), fired100 = new();
        lock (_gate)
        {
            foreach (var f in flows)
            {
                if (!_limits.TryGetValue(f.App.Key, out var l)) continue;
                long total = Interlocked.Read(ref f.BytesSent) + Interlocked.Read(ref f.BytesRecv);
                if (nowL.Date != l.DayStartLocal) // local midnight passed — fresh day
                {
                    l.TodayBytes = 0; l.Notified80 = false; l.Notified100 = false;
                    l.BlockedUntilUtc = null; l.DayStartLocal = nowL.Date;
                }
                if (total > l.TodayBytes)
                {
                    bool was80 = l.Notified80, was100 = l.Notified100;
                    l.TodayBytes = total;
                    double pct = l.Percent;
                    if (!was80 && pct >= 0.8) { l.Notified80 = true; fired80.Add((l, pct)); }
                    if (!was100 && pct >= 1.0)
                    {
                        l.Notified100 = true; fired100.Add((l, pct));
                        if (l.BlockUntilMidnight)
                            l.BlockedUntilUtc = nowL.Date.AddDays(1).AddTicks(-1).ToUniversalTime();
                    }
                }
            }
        }
        foreach (var (l, p) in fired80) Threshold?.Invoke(l, 0.8);
        foreach (var (l, p) in fired100) Threshold?.Invoke(l, 1.0);
    }

    /// <summary>Set or update a limit for an app. Fires Changed.</summary>
    public AppDataLimit Set(string appKey, long limitBytes, bool blockUntilMidnight)
    {
        if (limitBytes <= 0) throw new ArgumentException("limit must be > 0 bytes");
        lock (_gate)
        {
            var l = _limits.TryGetValue(appKey, out var x) ? x : new AppDataLimit { AppKey = appKey };
            l.LimitBytes = limitBytes;
            l.BlockUntilMidnight = blockUntilMidnight;
            if (!blockUntilMidnight) l.BlockedUntilUtc = null;
            _limits[appKey] = l;
        }
        Save();
        Changed?.Invoke();
        return Find(appKey)!;
    }

    public bool Clear(string appKey)
    {
        lock (_gate) { if (!_limits.Remove(appKey)) return false; }
        Save();
        Changed?.Invoke();
        return true;
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var doc = JsonDocument.Parse(File.ReadAllText(_path));
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                string key = el.TryGetProperty("appKey", out var k) ? k.GetString() ?? "" : "";
                if (key.Length == 0) continue; // defensive: skip corrupt entries
                long bytes = el.TryGetProperty("limitBytes", out var b) && b.ValueKind == JsonValueKind.Number ? b.GetInt64() : 0;
                bool block = el.TryGetProperty("blockUntilMidnight", out var bl) && bl.ValueKind == JsonValueKind.True;
                if (bytes <= 0) continue;
                _limits[key] = new AppDataLimit { AppKey = key, LimitBytes = bytes, BlockUntilMidnight = block };
            }
        }
        catch { /* corrupt file — start clean */ }
    }

    private void Save()
    {
        try
        {
            lock (_gate)
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
                File.WriteAllText(_path, JsonSerializer.Serialize(All(), opts));
            }
        }
        catch { /* best effort */ }
    }

    public void Dispose() { }
}
