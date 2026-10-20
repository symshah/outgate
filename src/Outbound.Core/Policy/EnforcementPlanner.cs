using Outbound.Core.Rules;

namespace Outbound.Core.Policy;

/// <summary>One installed/desired firewall rule in the form netsh understands.</summary>
public sealed record EnforceRule(long RuleId, string Name, string Program, string RemoteIps, string Protocol, string Action);

public sealed class EnforcementPlan
{
    public List<string> AddCommands { get; } = new();
    public List<string> RemoveCommands { get; } = new();
    public List<string> AllCommands
    {
        get
        {
            var rows = new List<string>();
            foreach (var c in AddCommands) rows.Add("would run: " + c);
            foreach (var c in RemoveCommands) rows.Add("would run: " + c);
            return rows;
        }
    }
    public int Count => AddCommands.Count + RemoveCommands.Count;
}

/// <summary>
/// Turns live rules (+ DNS-observed IPs) into a set of Windows Firewall block rules and diffs it
/// against what's already installed, so `outboundctl enforce` is idempotent and never deletes
/// foreign rules. Enforcement stays DRY-RUN during development (SPEC §0.5).
/// </summary>
public sealed class EnforcementPlanner
{
    public static string RuleName(long id) => $"OutboundWin {id}";

    public static List<EnforceRule> Desired(IEnumerable<Rule> rules, Func<string /*domain*/, IEnumerable<string>>? dnsIps = null)
    {
        var rows = new List<EnforceRule>();
        foreach (var r in rules)
        {
            if (!r.Enabled || r.Action != RuleAction.Deny) continue;
            string program = !string.IsNullOrEmpty(r.AppMatcher) && LooksLikePath(r.AppMatcher) ? r.AppMatcher : "";
            string remote = RemoteIps(r, dnsIps);
            if (remote == null) continue; // hostname with no IPs yet → nothing installable
            if (remote == "") continue;    // deny-any: too broad for v1, skip
            rows.Add(new EnforceRule(r.Id, RuleName(r.Id), program, remote ?? "", "Block", "out"));
        }
        return rows;
    }

    /// <summary>remoteip value: IP/CIDR directly; hostname via DNS mapping (union creation IPs + observed); empty = any.</summary>
    public static string? RemoteIps(Rule r, Func<string, IEnumerable<string>>? dnsIps)
    {
        if (r.Kind == DestKind.Any) return "";
        if (r.Kind == DestKind.LocalNetwork) return "LocalSubnet";
        if (r.Kind == DestKind.Ip || r.Kind == DestKind.Cidr) return r.Destination;
        var seen = new List<string>();
        if (r.ResolvedIps != null)
            foreach (var ip in r.ResolvedIps)
                if (!seen.Contains(ip)) seen.Add(ip);
        if (dnsIps != null)
            foreach (var ip in dnsIps(r.Destination))
                if (!seen.Contains(ip)) seen.Add(ip);
        return seen.Count > 0 ? string.Join(",", seen) : null; // no IPs yet → cannot install yet
    }

    public static EnforcementPlan Plan(IEnumerable<Rule> rules, IEnumerable<string> installed, Func<string, IEnumerable<string>>? dnsIps = null)
    {
        var plan = new EnforcementPlan();
        var wanted = Desired(rules, dnsIps).ToDictionary(e => e.Name);
        foreach (var (name, e) in wanted)
            if (!installed.Contains(name))
            {
                var cmd = new System.Text.StringBuilder($"netsh advfirewall firewall add rule name=\"{e.Name}\" dir=out action=block enable=yes");
                if (e.Program.Length > 0) cmd.Append($" program=\"{e.Program}\"");
                if (e.RemoteIps != null && e.RemoteIps.Length > 0) cmd.Append($" remoteip={e.RemoteIps}");
                plan.AddCommands.Add(cmd.ToString());
            }
        foreach (var n in installed)
            if (!wanted.ContainsKey(n))
                plan.RemoveCommands.Add($"netsh advfirewall firewall delete rule name=\"{n}\"");
        return plan;
    }

    private static bool LooksLikePath(string s) => s.Contains('\\') || s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
}
