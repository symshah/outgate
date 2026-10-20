using Outbound.Core.Engine;
using Outbound.Core.Identity;
using Outbound.Core.Network;
using Outbound.Core.Rules;
using Outbound.Core.Store;

namespace Outbound.Core.Policy;

/// <summary>
/// Listens to the engine's FlowStarted, runs each flow through the PolicyEngine, and records
/// decisions that didn't get a rule: review entries (learn/strict) and pending prompts (ask).
/// Enforcement is the separate EnforcementPlanner (dry-run by default).
/// </summary>
public sealed class PolicyService : IDisposable
{
    public PolicyEngine Engine { get; } = new();
    /// <summary>Per-network profiles (Phase 5): active profile drives the engine mode + rule filtering.</summary>
    public ProfileService Profiles { get; }
    /// <summary>Blocklists over HTTPS (Phase 5): unmatched hosts on a loaded list are denied.</summary>
    public BlocklistService Blocklists { get; }
    /// <summary>Daily data limits per app (Phase 5): notify at 80 %/100 %, optional block until midnight.</summary>
    public DataLimitService Limits { get; }
    /// <summary>Phase 5 toasts: blocked connections / first-to-new-country, rate-limited ≤1 per 8 s.</summary>
    public ToastService Toasts { get; } = new();
    private readonly RuleStore? _rules;
    private readonly ReviewStore _review;
    private readonly AppTrustStore _trust;
    public PromptManager Prompts { get; } = new();
    public bool Hooked;
    /// <summary>UI gate (tray Pause/Turn off): while false, flows are not evaluated or recorded.</summary>
    public volatile bool Enabled = true;

    public PolicyService(string? dbPath)
    {
        _rules = dbPath != null ? new RuleStore(dbPath) : null;
        _review = new ReviewStore(dbPath ?? Path.Combine(Path.GetTempPath(), "ob_review_empty.db"));
        _trust = new AppTrustStore(dbPath ?? Path.Combine(Path.GetTempPath(), "ob_trust_empty.db"));
        Engine.Rules = _rules?.All() ?? [];
        Profiles = new ProfileService();
        Engine.Profiles = Profiles;
        // Active profile's mode drives the engine (Learn/Ask/Strict) — updated on every network/profile change.
        Profiles.Changed += (_, _) => { var m = Profiles.ActiveMode(); if (m != null) Engine.Settings.Mode = m.Value; };
        Blocklists = new BlocklistService();
        Engine.Blocklists = Blocklists;
        Limits = new DataLimitService();
        Engine.Limits = Limits;
    }

    private OutboundEngine? _engine;
    private System.Threading.Timer? _limitTimer;

    public void Attach(OutboundEngine eng)
    {
        _engine = eng;
        eng.FlowStarted += OnFlow;
        // Sample per-app byte totals every 5 s so daily-limit thresholds fire promptly.
        _limitTimer = new System.Threading.Timer(_ =>
        {
            try { Limits.Sample(_engine?.Snapshot() ?? []); } catch { /* best effort */ }
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5));
        Hooked = true;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, string> _hashCache = new();

    private void OnFlow(FlowStats f)
    {
        if (!Enabled) return; // paused / turned off from tray
        if (f.Geo.IsLocal) return; // local chatter is never blocked/prompted
        if (f.RemoteIp == "127.0.0.1" || f.RemoteIp == "::1" || f.RemoteIp == "0.0.0.0") return;
        string? exe = f.App.ExePath;
        string hash = exe == null ? "" : _hashCache.GetOrAdd(f.Pid, _ => AppTrustStore.Sha256Of(exe) ?? "");
        bool trusted = _trust.IsTrusted(f.App.Key, f.App, hash == "" ? null : hash);
        var ctx = new FlowContext(f.Pid, exe == null ? f.App.DisplayName : Path.GetFileName(exe), exe ?? "", f.RemoteIp, f.RemotePort, f.Host, ToProto(f.Proto), f.App.Key);
        var d = Engine.Evaluate(ctx, trusted, DateTime.UtcNow, SystemKeys.Current());
        if (d.Review && !d.Prompt) // in Ask mode the dedicated "awaiting answer" row below covers it
            _review.Add(f.App.Key, f.App.DisplayName, f.Host, f.RemoteIp, f.RemotePort, ProtocolToString(f.Proto), d.ReviewNote ?? d.Reason,
                Engine.Settings.Mode == Mode.Ask ? ReviewAction.Pending : ReviewAction.Learned, DateTime.UtcNow);
        if (d.Prompt)
        {
            bool udp = f.Proto == Protocol.Udp;
            long reviewId = _review.Add(f.App.Key, f.App.DisplayName, f.Host, f.RemoteIp, f.RemotePort, ProtocolToString(f.Proto), "ask: awaiting answer", ReviewAction.Pending, DateTime.UtcNow);
            Prompts.Add(new PendingAsk(f.Key, ctx, DateTime.UtcNow, DateTime.UtcNow.Add(Engine.Settings.Timeouts.For(udp)), udp) { AppKey = f.App.Key, ReviewId = reviewId });
        }
        bool blockOnTimeout = Engine.Settings.BlockWhenPromptUnanswered;
        foreach (var expired in Prompts.PurgeExpired(DateTime.UtcNow))
            Prompts.NotifyTimeout(expired, !blockOnTimeout);
        _review.Prune(DateTime.UtcNow);

        // Phase 5 toasts (rate-limited inside ToastService): blocked connection, and first-to-new-country.
        try
        {
            if (!d.Allow && !d.Prompt) Toasts.NotifyBlocked(f.App.DisplayName, f.DisplayHost);
            else if (!f.Geo.IsLocal && f.Geo.Country != null) Toasts.NotifyFirstCountry(f.Geo.Country);
        }
        catch { /* a toast must never break flow evaluation */ }
    }

    /// <summary>User answered a prompt: record the rule, mark the review row, re-read the rule set.</summary>
    public Rule? Answer(long reviewId, RuleAction action, LifetimeKind lifetime, string scope, int? pid)
    {
        var item = _review.Items().FirstOrDefault(i => i.Id == reviewId);
        _review.SetAction(reviewId, action == RuleAction.Allow ? ReviewAction.Allowed : ReviewAction.Blocked);
        if (item == null) return null;
        var rule = new Rule
        {
            AppMatcher = FindExe(item.AppKey, pid), Destination = item.Host ?? item.RemoteIp, Kind = DestKind.Domain,
            PortSpec = scope == "port" ? FromInt(item.Port) : "any",
            Protocol = scope == "any-any" ? ProtoSpec.Any : ToProto(item.Proto),
            Action = action, Lifetime = lifetime, Source = RuleSources.User,
        };
        rule.StampLifetime(DateTime.UtcNow, pid);
        _rules?.Add(rule);
        Engine.Rules = _rules?.All() ?? Engine.Rules;
        var pending = Prompts.RemoveByReview(reviewId);
        if (pending != null) Prompts.NotifyResolved(pending.K);
        return rule;
    }

    private static string? FindExe(string appKey, int? pid)
{
    if (pid == null) return null;
    return AppResolver.ExePath((int)pid);
}
    static string FromInt(int v) => string.Format("{0}", v);
    private static string ProtocolToString(Protocol p) => p == Protocol.Tcp ? "Tcp" : p == Protocol.Udp ? "Udp" : "Any";
    private static ProtoSpec ToProto(Protocol p) => p == Protocol.Tcp ? ProtoSpec.Tcp : p == Protocol.Udp ? ProtoSpec.Udp : ProtoSpec.Any;
    public static ProtoSpec ToProto(string p) => p.Equals("Tcp", StringComparison.OrdinalIgnoreCase) ? ProtoSpec.Tcp : p.Equals("Udp", StringComparison.OrdinalIgnoreCase) ? ProtoSpec.Udp : ProtoSpec.Any;

    /// <summary>Flyout counts: (apps seen today, allowed, blocked) from the review store.</summary>
    public (int Apps, int Allowed, int Blocked) Counts()
    {
        var items = _review.Items();
        return (items.Select(i => i.AppKey).Distinct().Count(),
                items.Count(i => i.Action == ReviewAction.Allowed),
                items.Count(i => i.Action == ReviewAction.Blocked));
    }

    /// <summary>Review rows for the UI (Review page, Overview "recently blocked", Help window).</summary>
    public List<ReviewItem> ReviewItems() => _review.Items();

    /// <summary>Re-read the rule set after the UI added/removed rules through its own RuleStore handle.</summary>
    public void ReloadRules() { Engine.Rules = _rules?.All() ?? Engine.Rules; }

    /// <summary>Review page: mark a row allowed/blocked/dismissed (no rule created — use Answer for that).</summary>
    public bool SetReviewAction(long id, ReviewAction action) => _review.SetAction(id, action);

    /// <summary>"Allow verified publishers": trust one app by its current binary hash + signer.</summary>
    public void TrustApp(string appKey, AppInfo app, string? exeHash) => _trust.Trust(appKey, app, exeHash);

    public void Dispose() { _limitTimer?.Dispose(); _rules?.Dispose(); _review.Dispose(); _trust.Dispose(); Profiles.Dispose(); Blocklists.Dispose(); Limits.Dispose(); }
}
