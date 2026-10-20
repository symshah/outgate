using Outbound.Core.Rules;

namespace Outbound.Core.Policy;

public enum Mode { Learn = 1, Ask = 2, Strict = 3 }
public static class ModeNames { public static string Of(Mode m) => m switch { Mode.Ask => "Ask", Mode.Strict => "Strict", _ => "Learn" }; }

public static class SafetyPorts
{
    public static bool IsAlwaysAllowed(ushort remotePort, ProtoSpec proto)
    {
        if (proto != ProtoSpec.Udp) return false;
        return remotePort == 53 || remotePort == 123 || remotePort == 67 || remotePort == 68 || remotePort == 546 || remotePort == 547;
    }
}

/// <summary>Timeouts for Ask-mode prompts (SPEC Phase 2): UDP 8 s, TCP 60 s configurable 15..120.</summary>
public sealed class PromptTimeouts
{
    public int TcpSeconds { get; set; } = 60;
    public int UdpSeconds { get; set; } = 8;
    public int ClampedTcp => TcpSeconds < 15 ? 15 : TcpSeconds > 120 ? 120 : TcpSeconds;
    public TimeSpan For(bool udp) => DurationInSeconds(udp ? UdpSeconds : ClampedTcp);
    private static TimeSpan DurationInSeconds(int s) => TimeSpan.FromSeconds(s);
}

/// <summary>Settings the policy engine consults.</summary>
public sealed class PolicySettings
{
    public Mode Mode { get; set; } = Mode.Learn; // dry-run default: never block quietly
    public bool EnforceDeny { get; set; } = false;   // dry-run during development
    public bool BlockNewAppsUntilAnswered { get; set; } = false;
    public bool BlockWhenPromptUnanswered { get; set; } = false;
    public PromptTimeouts Timeouts { get; } = new();
}

/// <summary>Result of evaluating one nascent outbound flow.</summary>
public sealed record Decision(bool Allow, string Reason, Rule? Rule, bool Prompt, bool Review, string? ReviewNote);

public static class Decisions
{
    public static Decision Allow(string why, Rule? r = null) => new(true, why, r, false, false, null);
    public static Decision Review(string why, string note) => new(true, why, null, false, true, note);
    public static Decision DenyRule(string why, Rule r) => new(false, why, r, false, false, null);
    public static Decision DenyPrompt(string why) => new(false, why, null, true, false, null);
    public static Decision DenyStrict(string why) => new(false, why, null, false, true, "no rule");
    public static Decision AllowTrustBreach(string why, Rule r, bool prompt) => new(true, why, r, prompt, true, "binary changed");
}

/// <summary>
/// Pure policy: given the rule set and settings, decide one flow. No I/O.
/// Lifetime protection: an ALLOW rule whose app binary hash or signer no longer matches is not trusted
/// (treated as a brand-new app) unless the caller supplied the current trust signature.
/// </summary>
public sealed class PolicyEngine
{
    public PolicySettings Settings { get; } = new();
    public IEnumerable<Rule> Rules { get; set; } = new Rule[0];
    /// <summary>Per-network profiles (Phase 5). When a profile is active, only rules tagged with it (or untagged) apply.</summary>
    public ProfileService? Profiles { get; set; }
    /// <summary>Blocklists over HTTPS (Phase 5): unmatched hosts on a loaded list are denied. An explicit ALLOW rule wins over the blocklist.</summary>
    public BlocklistService? Blocklists { get; set; }
    /// <summary>Daily data limits per app (Phase 5): an app over its limit with blocking on is denied until local midnight.</summary>
    public DataLimitService? Limits { get; set; }

    private static bool RuleApplies(Rule r, string? activeProfile) =>
        r.Profile == null || r.Profile == activeProfile; // untagged = global; tagged = only on its profile

    public Decision Evaluate(FlowContext ctx, bool appTrusted, DateTime now, LifetimeContext lc)
    {
        // SPEC Phase 2 safety: always-allow DNS, DHCP, NTP + core Windows networking so Strict can't orphan the machine.
        if (SafetyPorts.IsAlwaysAllowed(ctx.RemotePort, ctx.Proto) && IsCoreNetworking(ctx.ExePath, ctx.ProcessName))
            return Decisions.Allow("safety net: DNS/DHCP/NTP is always allowed");
        if (string.IsNullOrEmpty(ctx.ExePath))
            return Decisions.Allow("no process identity — allowed");

        // Daily data limit (Phase 5): an app over its daily cap with blocking on is denied until local midnight.
        if (ctx.AppKey != null && Limits?.IsBlocked(ctx.AppKey, now) == true)
            return Decisions.DenyRule($"daily data limit reached — blocked until midnight", null);

        var rules = Rules.Where(r => RuleApplies(r, Profiles?.ActiveProfile)); // per-network profiles (Phase 5)
        var matched = RuleMatcher.Matching(rules, ctx, now, lc);
        if (matched.Count > 0)
        {
            var r = matched[0];
            bool exempt = r.Source == RuleSources.Learned || r.Source == RuleSources.Pending;
            if (r.Action == RuleAction.Allow && !appTrusted && !exempt)
                return Decisions.AllowTrustBreach($"app binary/signature changed — allow rule {r.Id} suspended, treated as new (review)",
                    r, Settings.Mode == Mode.Ask);
            if (r.Action == RuleAction.Allow)
                return Decisions.Allow($"rule {r.Id}: {r.Describe()}", r);
            if (Settings.Mode == Mode.Ask)
                return Decisions.DenyPrompt($"rule {r.Id}: {r.Describe()} — awaiting your answer");
            if (Settings.Mode == Mode.Strict)
                return Decisions.DenyStrict($"rule {r.Id}: {r.Describe()}");
            return Decisions.DenyRule($"rule {r.Id}: {r.Describe()}", r);
        }

        // Blocklists over HTTPS (Phase 5): unmatched hosts on a loaded list are denied. An explicit ALLOW rule above wins.
        var bl = Blocklists?.WhichList(ctx.Host);
        if (bl != null)
            return Decisions.DenyRule($"blocklist '{bl}': host {ctx.Host} is listed", null);

        if (Settings.Mode == Mode.Ask)
            return Decisions.DenyPrompt("ask mode: awaiting your answer");
        if (Settings.Mode == Mode.Strict)
            return Decisions.DenyStrict("strict mode: no rule, blocked");
        return Decisions.Review("learn mode: new connection recorded for review", "learned");
    }

    private static bool IsCoreNetworking(string? exe, string processName)
    {
        string p = exe == null ? "" : Path.GetFileName(exe);
        string n = p.ToLowerInvariant() + "|" + processName.ToLowerInvariant();
        if (n.Contains("dns") || n.Contains("dhcp") || n.Contains("ntp") || n.Contains("w32time")) return true;
        if (n.Contains("slhdcxp") || n.Contains("wlan") || n.Contains("svchost")) return true;
        return n == "|wificm.exe" || n == "|wificlt.exe";
    }
}
