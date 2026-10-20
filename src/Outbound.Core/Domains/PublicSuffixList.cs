using System.Globalization;
using System.Net;

namespace Outbound.Core.Domains;

/// <summary>Public Suffix List (publicsuffix.org, MPL-2.0, bundled offline) → registrable domain ("main domain").</summary>
public sealed class PublicSuffixList
{
    private readonly HashSet<string> _rules = new(StringComparer.Ordinal), _wild = new(StringComparer.Ordinal), _exc = new(StringComparer.Ordinal);
    private static readonly Lazy<PublicSuffixList?> _default = new(() =>
    {
        var p = AssetLocator.Find(Path.Combine("psl", "psl.dat"));
        return p == null ? null : Load(p);
    });
    public static PublicSuffixList? Default => _default.Value;
    public int RuleCount => _rules.Count + _wild.Count + _exc.Count;

    public static PublicSuffixList Load(string path) => Parse(File.ReadLines(path));

    public static PublicSuffixList Parse(IEnumerable<string> lines)
    {
        var psl = new PublicSuffixList();
        var idn = new IdnMapping();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("//")) continue;
            line = line.Split(' ', '\t')[0].ToLowerInvariant();
            bool exc = line.StartsWith('!'); if (exc) line = line[1..];
            bool wild = line.StartsWith("*."); if (wild) line = line[2..];
            try { line = idn.GetAscii(line); } catch { }
            (exc ? psl._exc : wild ? psl._wild : psl._rules).Add(line);
        }
        return psl;
    }

    /// <summary>"www.bbc.co.uk" → "bbc.co.uk"; IPs and bare suffixes → null.</summary>
    public string? RegistrableDomain(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || IPAddress.TryParse(host, out _)) return null;
        var labels = host.Trim().TrimEnd('.').ToLowerInvariant().Split('.');
        int n = labels.Length;
        int suffixLen = 1; // default rule "*"
        for (int i = 0; i < n; i++)
        {
            string c = string.Join('.', labels, i, n - i);
            if (_exc.Contains(c)) { suffixLen = n - i - 1; break; }
            if (_rules.Contains(c)) { suffixLen = n - i; break; }
            if (n - i - 1 > 0 && _wild.Contains(string.Join('.', labels, i + 1, n - i - 1))) { suffixLen = n - i; break; }
        }
        if (suffixLen >= n) return null;
        return string.Join('.', labels, n - suffixLen - 1, suffixLen + 1);
    }
}

/// <summary>Finds bundled assets: $OUTBOUND_ASSETS, then "assets" next to the exe or in any parent folder.</summary>
public static class AssetLocator
{
    public static string? Find(string relative)
    {
        var env = Environment.GetEnvironmentVariable("OUTBOUND_ASSETS");
        if (!string.IsNullOrEmpty(env) && File.Exists(Path.Combine(env, relative))) return Path.Combine(env, relative);
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
        {
            var p = Path.Combine(d.FullName, "assets", relative);
            if (File.Exists(p)) return p;
        }
        return null;
    }
}
