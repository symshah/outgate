using System.Diagnostics;
using System.Security.Principal;
using Outbound.Core.Rules;

namespace Outbound.Core.Enforcement;

public sealed record EnforcementResult(bool Applied, bool RequiresElevation, List<string> CommandsRun, string? Error);

/// <summary>
/// Windows Firewall enforcement via netsh advfirewall.
/// PoC scope: DENY rules become real outbound block rules (per-app and/or per-destination).
/// ALLOW rules are advisory in this phase — a global default-deny policy is deliberately NOT
/// installed, because it would break the machine's own traffic (updates, DNS, etc.).
/// Strict mode (default-deny + allowlist) is phase 3.
/// </summary>
public sealed class FirewallEnforcer : IDisposable
{
    public const string RuleNamePrefix = "OutboundWin";

    private readonly bool _dryRun;
    public bool DryRun => _dryRun;
    public bool IsElevated { get; }

    public FirewallEnforcer(bool dryRun = true) // SPEC §0.5: dry-run by default
    {
        _dryRun = dryRun;
        IsElevated = CheckElevation();
    }

    public static bool CheckElevation()
    {
        var id = WindowsIdentity.GetCurrent();
        if (id == null) return false;
        var principal = new WindowsPrincipal(id);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Build the netsh commands that would enforce the given rules.</summary>
    public List<string> BuildCommands(IEnumerable<Rule> rules)
    {
        var cmds = new List<string>();
        foreach (var r in rules.Where(r => r.Action == RuleAction.Deny))
        {
            string program = !string.IsNullOrEmpty(r.AppMatcher) && LooksLikePath(r.AppMatcher) ? $" program=\"{r.AppMatcher}\"" : "";
            string remote = RemoteIpSpec(r);
            if (remote == "-") continue; // hostname with no resolved IPs yet: nothing installable
            if (program == "" && remote == "") continue; // deny-any is not installable in PoC
            cmds.Add($"netsh advfirewall firewall add rule name=\"{RuleNamePrefix} {r.Id}\" dir=out action=block{program}{remote} enable=yes");
        }
        return cmds;
    }

    /// <summary>Remove all previously installed OutboundWin rules.</summary>
    public List<string> BuildClearCommands() =>
        [.. EnumerateInstalledRules().Select(n => $"netsh advfirewall firewall delete rule name=\"{n}\"")];

    public List<string> EnumerateInstalledRuleNames()
    {
        return EnumerateInstalledRules();
    }

    private static List<string> EnumerateInstalledRules()
    {
        var names = new List<string>();
        try
        {
            var psi = new ProcessStartInfo("netsh", "advfirewall firewall show rule name=all")
            { RedirectStandardOutput = true, UseShellExecute = false };
            using var p = Process.Start(psi)!;
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null)
                if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    var name = line["Rule Name:".Length..].Trim();
                    if (name.StartsWith(RuleNamePrefix, StringComparison.Ordinal)) names.Add(name);
                }
            p.WaitForExit(5000);
        }
        catch { /* not elevated or netsh unavailable */ }
        return names;
    }

    /// <summary>Apply deny-rules as firewall block rules. Returns what happened.</summary>
    public EnforcementResult Apply(IEnumerable<Rule> rules)
    {
        var cmds = BuildCommands(rules);
        if (cmds.Count == 0) return new(true, false, [], null);

        if (_dryRun)
            return new(true, !IsElevated, cmds, "dry-run: no commands executed");

        if (!IsElevated)
            return new(false, true, cmds, "elevation required — run Outbound as administrator to apply blocking");

        var ran = new List<string>();
        foreach (var c in cmds)
        {
            try
            {
                RunNetsh(c);
                ran.Add(c);
            }
            catch (Exception ex)
            {
                return new(false, false, ran, $"failed: {c} — {ex.Message}");
            }
        }
        return new(true, false, ran, null);
    }

    /// <summary>Remove all OutboundWin firewall rules.</summary>
    public EnforcementResult Clear()
    {
        var cmds = BuildClearCommands();
        if (cmds.Count == 0) return new(true, false, [], null);
        if (_dryRun) return new(true, !IsElevated, cmds, "dry-run: no commands executed");
        if (!IsElevated) return new(false, true, cmds, "elevation required to remove rules");

        var ran = new List<string>();
        foreach (var c in cmds)
        {
            try { RunNetsh(c); ran.Add(c); }
            catch (Exception ex) { return new(false, false, ran, $"failed: {c} — {ex.Message}"); }
        }
        return new(true, false, ran, null);
    }

    private static void RunNetsh(string fullCommand)
    {
        // "netsh advfirewall firewall add rule ..." → split into args
        var parts = Tokenize(fullCommand);
        var psi = new ProcessStartInfo(parts[0], string.Join(' ', parts.Skip(1)))
        { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        string? err = p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        if (p.ExitCode != 0) throw new InvalidOperationException(err.Trim());
    }

    private static List<string> Tokenize(string s)
    {
        var tokens = new List<string>();
        bool inQuotes = false;
        var cur = new System.Text.StringBuilder();
        foreach (var ch in s)
        {
            if (ch == '"') { inQuotes = !inQuotes; continue; }
            if (!inQuotes && char.IsWhiteSpace(ch))
            {
                if (cur.Length > 0) { tokens.Add(cur.ToString()); cur.Clear(); }
                continue;
            }
            cur.Append(ch);
        }
        if (cur.Length > 0) tokens.Add(cur.ToString());
        return tokens;
    }

    /// <summary>netsh remoteip= value. Hostnames are not valid there: use the IPs from the DNS mapping.</summary>
    internal static string RemoteIpSpec(Rule r)
    {
        if (r.Destination == "any") return "";
        if (r.Destination.Equals("localnetwork", StringComparison.OrdinalIgnoreCase)) return " remoteip=LocalSubnet";
        bool ip = System.Net.IPAddress.TryParse(r.Destination, out _);
        bool cidr = r.Destination.Contains('/') && System.Net.IPAddress.TryParse(r.Destination.Split('/')[0], out _);
        if (ip || cidr) return $" remoteip={r.Destination}";
        return r.ResolvedIps is { Count: > 0 } ? $" remoteip={string.Join(',', r.ResolvedIps)}" : "-";
    }

    private static bool LooksLikePath(string s) =>
        s.Contains('\\') || s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    public void Dispose() { }
}
