using System.Net;
using System.Net.Sockets;

namespace Outbound.Core.Rules;

public enum RuleAction { Allow = 1, Deny = 2 }

/// <summary>SPEC Phase 2 lifetimes: Once, 1 Hour, Until Quit, Until Logout, Until Restart, Forever.</summary>
public enum LifetimeKind { Once, Hours, UntilQuit, UntilLogout, UntilRestart, Forever }

public enum DestKind { Any, Host, Domain, Ip, Cidr, LocalNetwork }

public enum ProtoSpec { Any = 0, Tcp = 1, Udp = 2 }

public static class RuleSources
{
    public const string User = "user", Blocklist = "blocklist", Profile = "profile", Ai = "ai", Imported = "imported", Pending = "pending", Learned = "learned";
}

/// <summary>Current values used to expire session-bound rules (see <see cref="SystemKeys"/>).</summary>
public sealed record LifetimeContext(Func<int, bool>? PidAlive = null, string? SessionKey = null, string? BootKey = null);

/// <summary>A firewall rule: app matcher × destination × port × protocol → action, with a lifetime.</summary>
public sealed class Rule
{
    public long Id { get; set; }
    /// <summary>Exe path (case-insensitive) or process name. Null/empty = any app.</summary>
    public string? AppMatcher { get; set; }
    /// <summary>Host, domain (incl. subdomains), IP, CIDR, "localnetwork", or "any".</summary>
    public required string Destination { get; set; }
    private DestKind? _kind;
    /// <summary>Explicit kind; when unset, names are treated as Domain (covers subdomains).</summary>
    public DestKind Kind { get => _kind ?? DeriveKind(Destination); set => _kind = value; }
    public bool HasExplicitKind => _kind.HasValue;
    /// <summary>"443", "53-80" range, "80,443" list, or "any".</summary>
    public string PortSpec { get; set; } = "any";
    public ProtoSpec Protocol { get; set; } = ProtoSpec.Any;
    public string Direction { get; set; } = "out";
    public RuleAction Action { get; set; } = RuleAction.Allow;
    public LifetimeKind Lifetime { get; set; } = LifetimeKind.Forever;
    /// <summary>For Hours: expiry UTC.</summary>
    public DateTime? ExpiresUtc { get; set; }
    /// <summary>For UntilQuit: the PID to watch.</summary>
    public int? WatchPid { get; set; }
    /// <summary>For UntilLogout: the logon session key at creation. For UntilRestart: the boot key.</summary>
    public string? SessionKey { get; set; }
    public string? BootKey { get; set; }
    /// <summary>Once-rules are consumed by the first connection they decide.</summary>
    public bool Consumed { get; set; }
    public bool Enabled { get; set; } = true;
    public int Priority { get; set; } = 100; // higher wins
    /// <summary>The UI "Priority" flag: priority rules beat normal rules regardless of specificity.</summary>
    public bool IsPriority { get => Priority > 100; set => Priority = value ? Math.Max(Priority, 200) : Math.Min(Priority, 100); }
    /// <summary>user | blocklist | profile | ai | imported | pending | learned</summary>
    public string Source { get; set; } = RuleSources.User;
    /// <summary>Null = applies in every profile.</summary>
    public string? Profile { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    /// <summary>When Destination is a hostname: IPs it resolved to (creation + DNS mapping refreshes).</summary>
    public List<string>? ResolvedIps { get; set; }
    public string? Note { get; set; }

    public static DestKind DeriveKind(string d)
    {
        if (string.IsNullOrEmpty(d) || d.Equals("any", StringComparison.OrdinalIgnoreCase)) return DestKind.Any;
        if (d.Equals("localnetwork", StringComparison.OrdinalIgnoreCase) || d.Equals("local", StringComparison.OrdinalIgnoreCase)) return DestKind.LocalNetwork;
        if (IPAddress.TryParse(d, out _)) return DestKind.Ip;
        if (d.Contains('/') && IPAddress.TryParse(d.Split('/')[0], out _)) return DestKind.Cidr;
        return DestKind.Domain;
    }

    /// <summary>If destination looks like a hostname, resolve it now and cache the result (v4 + v6).</summary>
    public void ResolveDestination()
    {
        if (Kind is not (DestKind.Domain or DestKind.Host)) return;
        try
        {
            ResolvedIps = Dns.GetHostAddresses(Destination)
                .Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                .Select(a => a.ToString()).Distinct().ToList();
        }
        catch { ResolvedIps = []; } // unresolvable — rule will match by hostname only
    }

    public void AddResolvedIps(IEnumerable<string> ips)
    {
        ResolvedIps ??= [];
        foreach (var ip in ips) if (!ResolvedIps.Contains(ip)) ResolvedIps.Add(ip);
    }

    public bool IsExpired(DateTime now, Func<int, bool>? pidAlive = null) => IsExpired(now, new LifetimeContext(pidAlive));

    public bool IsExpired(DateTime now, LifetimeContext lc) => Lifetime switch
    {
        LifetimeKind.Forever => false,
        LifetimeKind.Once => Consumed,
        LifetimeKind.Hours => ExpiresUtc is null || now >= ExpiresUtc.Value,
        LifetimeKind.UntilQuit => WatchPid is null || !(lc.PidAlive?.Invoke(WatchPid.Value) ?? true),
        // A restart also ends the logon session.
        LifetimeKind.UntilLogout => Differs(SessionKey, lc.SessionKey) || Differs(BootKey, lc.BootKey),
        LifetimeKind.UntilRestart => Differs(BootKey, lc.BootKey),
        _ => false,
    };

    private static bool Differs(string? stored, string? current) => stored != null && current != null && stored != current;

    /// <summary>Stamp the session/boot keys a lifetime needs (call when creating the rule).</summary>
    public Rule StampLifetime(DateTime nowUtc, int? pid = null)
    {
        switch (Lifetime)
        {
            case LifetimeKind.Hours: ExpiresUtc ??= nowUtc.AddHours(1); break;
            case LifetimeKind.UntilQuit: WatchPid ??= pid; break;
            case LifetimeKind.UntilLogout: SessionKey ??= SystemKeys.SessionKey(); BootKey ??= SystemKeys.BootKey(); break;
            case LifetimeKind.UntilRestart: BootKey ??= SystemKeys.BootKey(); break;
        }
        return this;
    }

    /// <summary>Parse a lifetime token; unknown values are REJECTED (never silently Forever).</summary>
    public static LifetimeKind ParseLifetime(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) throw new ArgumentException("lifetime required (once, 1h, quit, logout, restart, forever)");
        return s.ToLowerInvariant() switch
        {
            "once" => LifetimeKind.Once,
            "1h" or "hour" => LifetimeKind.Hours,
            "quit" => LifetimeKind.UntilQuit,
            "logout" => LifetimeKind.UntilLogout,
            "restart" => LifetimeKind.UntilRestart,
            "forever" => LifetimeKind.Forever,
            _ => throw new ArgumentException($"unknown lifetime '{s}' — valid values: once, 1h, quit, logout, restart, forever"),
        };
    }

    public static string LifetimeText(LifetimeKind k) => k switch
    {
        LifetimeKind.Once => "once", LifetimeKind.Hours => "for 1 hour", LifetimeKind.UntilQuit => "until the app quits",
        LifetimeKind.UntilLogout => "until logout", LifetimeKind.UntilRestart => "until restart", _ => "forever",
    };

    /// <summary>Rule as a sentence: "Deny connections to telemetry.zoom.us on any port for Zoom".</summary>
    public string Describe()
    {
        string dest = Kind switch
        {
            DestKind.Any => "anywhere",
            DestKind.LocalNetwork => "the local network",
            DestKind.Domain => $"{Destination} (and subdomains)",
            _ => Destination,
        };
        string port = PortSpec == "any" ? "any port" : PortSpec.Contains(',') || PortSpec.Contains('-') ? $"ports {PortSpec}" : $"port {PortSpec}";
        string proto = Protocol == ProtoSpec.Any ? "" : $" {Protocol.ToString().ToUpperInvariant()}";
        string app = string.IsNullOrEmpty(AppMatcher) ? "any app" : Path.GetFileName(AppMatcher);
        string life = Lifetime == LifetimeKind.Forever ? "" : $", {LifetimeText(Lifetime)}";
        return $"{(Action == RuleAction.Allow ? "Allow" : "Deny")} connections to {dest} on {port}{proto} for {app}{life}";
    }
}

/// <summary>Context of a flow being evaluated. Host = the name the app asked for (null when unknown).</summary>
public sealed record FlowContext(
    int Pid,
    string ProcessName,
    string ExePath,
    string RemoteIp,
    ushort RemotePort,
    string? Host = null,
    ProtoSpec Proto = ProtoSpec.Any,
    string? AppKey = null);

/// <summary>Pure rule matching — no I/O, fully unit-testable.</summary>
public static class RuleMatcher
{
    /// <summary>Find the deciding rule. Priority desc; most-specific next; deny wins remaining ties.</summary>
    public static (Rule? Matched, string Reason) Decide(
        IEnumerable<Rule> rules, FlowContext ctx, DateTime now, Func<int, bool>? pidAlive = null)
        => Decide(rules, ctx, now, new LifetimeContext(pidAlive));

    public static (Rule? Matched, string Reason) Decide(IEnumerable<Rule> rules, FlowContext ctx, DateTime now, LifetimeContext lc)
    {
        var m = Matching(rules, ctx, now, lc);
        if (m.Count == 0) return (null, "no matching rule");
        var best = m[0];
        return (best, $"rule {best.Id}: {best.Describe()}");
    }

    /// <summary>All live matching rules, best first.</summary>
    public static List<Rule> Matching(IEnumerable<Rule> rules, FlowContext ctx, DateTime now, LifetimeContext lc)
    {
        var candidates = new List<(Rule R, int Specificity)>();
        foreach (var r in rules)
        {
            if (!LiveMatch(r, ctx, now, lc)) continue;
            candidates.Add((r, SpecificityOf(r)));
        }
        return candidates
            .OrderByDescending(c => c.R.Priority)
            .ThenByDescending(c => c.Specificity)
            .ThenByDescending(c => c.R.Action == RuleAction.Deny ? 1 : 0) // deny wins ties
            .ThenBy(c => c.R.Id)
            .Select(c => c.R).ToList();
    }

    /// <summary>True if the rule is live (enabled + unexpired) and matches this flow on app/dest/port/proto.</summary>
    public static bool LiveMatch(Rule r, FlowContext ctx, DateTime now, LifetimeContext lc) =>
        r.Enabled && !r.IsExpired(now, lc)
        && AppMatches(r.AppMatcher, ctx)
        && DestMatches(r, ctx)
        && PortMatches(r.PortSpec, ctx.RemotePort)
        && (r.Protocol == ProtoSpec.Any || ctx.Proto == ProtoSpec.Any || r.Protocol == ctx.Proto);

    public static bool AppMatches(string? matcher, FlowContext ctx)
    {
        if (string.IsNullOrEmpty(matcher)) return true;
        if (string.Equals(matcher, ctx.ProcessName, StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(matcher, ctx.ExePath, StringComparison.OrdinalIgnoreCase)) return true;
        // Match when either side is a bare name against the other side's file name.
        string matcherName = matcher.Contains('\\') ? Path.GetFileName(matcher) : matcher;
        string exeName = string.IsNullOrEmpty(ctx.ExePath) ? "" : Path.GetFileName(ctx.ExePath);
        if (!string.IsNullOrEmpty(exeName) && string.Equals(matcherName, exeName, StringComparison.OrdinalIgnoreCase))
            return true;
        // A full-path matcher can still match a flow that only has a process name.
        if (matcher.Contains('\\'))
        {
            string m = Path.GetFileName(matcher);
            if (!string.IsNullOrEmpty(ctx.ProcessName) && string.Equals(m, ctx.ProcessName, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static bool DestMatches(Rule r, FlowContext ctx)
    {
        switch (r.Kind)
        {
            case DestKind.Any: return true;
            case DestKind.LocalNetwork: return IPAddress.TryParse(ctx.RemoteIp, out var a) && Geo.GeoIp.IsLocal(a);
            case DestKind.Host:
                if (ctx.Host != null && string.Equals(ctx.Host.TrimEnd('.'), r.Destination.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)) return true;
                return r.ResolvedIps is { Count: > 0 } && r.ResolvedIps.Contains(ctx.RemoteIp);
            case DestKind.Domain:
                if (ctx.Host != null && HostMatchesDomain(ctx.Host, r.Destination)) return true;
                return DestMatches(r.Destination, ctx.RemoteIp, r.ResolvedIps);
            default: return DestMatches(r.Destination, ctx.RemoteIp, r.ResolvedIps);
        }
    }

    /// <summary>Destination match: domain (incl. subdomains + cached resolved IPs), IP, or CIDR.</summary>
    public static bool DestMatches(Rule r, string remoteIp) =>
        DestMatches(r.Destination, remoteIp, r.ResolvedIps);

    public static bool DestMatches(string destination, string remoteIp, List<string>? resolvedIps = null)
    {
        if (destination == "any") return true;
        if (TryParseCidr(destination, out var cidrNet, out var cidrMask))
            return IpInCidr(remoteIp, cidrNet, cidrMask);
        if (IPAddress.TryParse(destination, out var exact) &&
            IPAddress.TryParse(remoteIp, out var ip) &&
            exact.AddressFamily == ip.AddressFamily)
            return exact.Equals(ip);
        if (resolvedIps is { Count: > 0 } && resolvedIps.Contains(remoteIp))
            return true;
        if (!IPAddress.TryParse(remoteIp, out _))
            return HostMatchesDomain(remoteIp, destination);
        return false;
    }

    /// <summary>True if host equals domain or is a subdomain of it.</summary>
    public static bool HostMatchesDomain(string host, string domain)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        domain = domain.TrimEnd('.').ToLowerInvariant();
        return host == domain || host.EndsWith("." + domain, StringComparison.Ordinal);
    }

    public static bool PortMatches(string spec, ushort port)
    {
        if (spec == "any") return true;
        if (spec.Contains(','))
            return spec.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Any(p => PortMatches(p, port));
        if (spec.Contains('-'))
        {
            var parts = spec.Split('-', 2);
            if (ushort.TryParse(parts[0], out var lo) && ushort.TryParse(parts[1], out var hi))
                return port >= lo && port <= hi;
            return false;
        }
        return ushort.TryParse(spec, out var p) && p == port;
    }

    private static int SpecificityOf(Rule r) =>
        (string.IsNullOrEmpty(r.AppMatcher) ? 0 : 1) +
        r.Kind switch { DestKind.Any => 0, DestKind.LocalNetwork => 1, DestKind.Cidr => 2, DestKind.Domain => 2, _ => 3 } +
        (r.PortSpec == "any" ? 0 : 1) +
        (r.Protocol == ProtoSpec.Any ? 0 : 1);

    private static bool TryParseCidr(string s, out IPAddress network, out int maskBits)
    {
        network = IPAddress.Any; maskBits = 0;
        var slash = s.IndexOf('/');
        if (slash < 0) return false;
        if (!IPAddress.TryParse(s[..slash], out network!)) return false;
        if (!int.TryParse(s[(slash + 1)..], out maskBits)) return false;
        int max = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return maskBits >= 0 && maskBits <= max;
    }

    private static bool IpInCidr(string ip, IPAddress network, int maskBits)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        if (addr.AddressFamily != network.AddressFamily) return false;
        byte[] a = addr.GetAddressBytes();
        byte[] n = network.GetAddressBytes();
        for (int i = 0; i < a.Length; i++)
        {
            int bitsLeft = maskBits - i * 8;
            if (bitsLeft <= 0) break;
            int mask = bitsLeft >= 8 ? 0xFF : (byte)(0xFF << (8 - bitsLeft));
            if ((a[i] & mask) != (n[i] & mask)) return false;
        }
        return true;
    }
}
