namespace Outbound.Core.Policy;

/// <summary>
/// Phase 5: toast notifications for blocked connections / first connection to a new country.
/// Rate-limited to at most one toast per 8 s (SPEC). Pure and testable — inject the clock.
/// </summary>
public sealed class ToastService
{
    /// <summary>Fired on the caller's thread when a toast should be shown. Args: title, message.</summary>
    public event Action<string, string>? Toast;
    /// <summary>Minimum interval between toasts (8 s per SPEC).</summary>
    public static readonly TimeSpan MinGap = TimeSpan.FromSeconds(8);

    private readonly Func<DateTime> _now;
    private DateTime _lastAt = DateTime.MinValue;
    private readonly HashSet<string> _seenCountries = new(StringComparer.OrdinalIgnoreCase);

    public ToastService(Func<DateTime>? now = null) => _now = now ?? (() => DateTime.UtcNow);

    /// <summary>True if the last toast was more than the minimum gap ago (poll-safe; tracks time, not traffic).</summary>
    public bool Due() => _now() - _lastAt >= MinGap;

    /// <summary>Fire a blocked-connection toast if the gap has elapsed. Returns true if shown.</summary>
    public bool NotifyBlocked(string appDisplay, string dest)
    {
        if (!Due()) return false;
        _lastAt = _now();
        Toast?.Invoke("Outbound — blocked", $"{appDisplay} → {dest} was blocked.");
        return true;
    }

    /// <summary>Fire a toast the first time we see a connection to <paramref name="country"/> in this session.
    /// Rate-limited like every other toast.</summary>
    public bool NotifyFirstCountry(string country)
    {
        if (string.IsNullOrEmpty(country)) return false;
        if (!_seenCountries.Add(country)) return false;
        if (!Due()) return false;
        _lastAt = _now();
        Toast?.Invoke("Outbound — new country", $"First connection to {country}.");
        return true;
    }

    /// <summary>For tests: how many distinct countries have been seen.</summary>
    public int SeenCountryCount => _seenCountries.Count;
}