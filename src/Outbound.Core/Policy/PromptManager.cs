using Microsoft.Data.Sqlite;

using Outbound.Core.Engine;
using Outbound.Core.Rules;

namespace Outbound.Core.Policy;

/// <summary>A decision pending a human answer (Ask mode).</summary>
public sealed record PendingAsk(FlowKey K, FlowContext Ctx, DateTime AskedAt, DateTime ExpiresAt, bool Udp)
{
    /// <summary>App key of the asking process — lets the UI group "answer all for this app".</summary>
    public string? AppKey { get; init; }
    /// <summary>ID of the review row created with this prompt (so Answer() can mark it).</summary>
    public long ReviewId { get; init; }
}

/// <summary>Tracks outstanding Ask prompts and their timeout expiry.</summary>
public sealed class PromptManager
{
    private readonly Dictionary<FlowKey, PendingAsk> _pending = new();
    private readonly object _gate = new();

    /// <summary>Raised (on the engine thread) when a new prompt is queued — UI opens its window here.</summary>
    public event Action<PendingAsk>? NewPrompt;
    /// <summary>Raised (on the engine thread) when a prompt expires unanswered: (prompt, allowed by default).</summary>
    public event Action<PendingAsk, bool>? TimeoutDecision;
    /// <summary>Raised (on the engine thread) when a pending prompt is removed — answered or timed out.</summary>
    public event Action<FlowKey>? Resolved;

    public void Add(PendingAsk a) { lock (_gate) _pending[a.K] = a; NewPrompt?.Invoke(a); }
    public PendingAsk? Get(FlowKey k) { lock (_gate) return _pending.TryGetValue(k, out var a) ? a : null; }
    public int Count { get { lock (_gate) return _pending.Count; } }
    public List<PendingAsk> All() { lock (_gate) return _pending.Values.ToList(); }

    /// <summary>Expire it, returning the last decision (default-allow or default-block per settings).</summary>
    public PendingAsk? Remove(FlowKey k, bool allowOnTimeout, bool blockOnTimeout)
    {
        lock (_gate)
        {
            var a = _pending.TryGetValue(k, out var x) ? x : null;
            if (a != null) _pending.Remove(k);
            return a;
        }
    }

    /// <summary>Removes prompts past their deadline; returns them so callers can record the default decision.</summary>
    public List<PendingAsk> PurgeExpired(DateTime now)
    {
        lock (_gate)
        {
            var out_ = _pending.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Value).ToList();
            foreach (var a in out_) _pending.Remove(a.K);
            return out_;
        }
    }

    /// <summary>Notify the UI that a prompt left the queue (answered or timed out).</summary>
    public void NotifyResolved(FlowKey k) => Resolved?.Invoke(k);

    /// <summary>Raise TimeoutDecision for an expired prompt (called by PolicyService on purge).</summary>
    public void NotifyTimeout(PendingAsk a, bool allowOnTimeout) => TimeoutDecision?.Invoke(a, allowOnTimeout);

    /// <summary>Remove the pending prompt tied to a review row (user answered it); returns it.</summary>
    public PendingAsk? RemoveByReview(long reviewId)
    {
        lock (_gate)
        {
            var hit = _pending.Values.FirstOrDefault(a => a.ReviewId == reviewId);
            if (hit != null) _pending.Remove(hit.K);
            return hit;
        }
    }
}
