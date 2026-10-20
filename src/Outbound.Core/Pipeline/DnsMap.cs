using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace Outbound.Core.Pipeline;

/// <summary>Remote IP → hostname, per process first (the name that app asked for), then global.</summary>
public sealed class DnsMap
{
    private readonly ConcurrentDictionary<(int Pid, string Ip), (string Host, DateTime At)> _perPid = new();
    private readonly ConcurrentDictionary<string, (string Host, DateTime At)> _global = new();
    public int Count => _global.Count;

    public void Add(int pid, string host, IEnumerable<string> ips, DateTime atUtc)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        foreach (var ip in ips)
        {
            if (pid > 0) _perPid[(pid, ip)] = (host, atUtc);
            _global[ip] = (host, atUtc);
        }
    }

    public string? Lookup(int pid, string ip)
    {
        if (_perPid.TryGetValue((pid, ip), out var p)) return p.Host;
        return _global.TryGetValue(ip, out var g) ? g.Host : null;
    }

    /// <summary>Non-elevated fallback: seed from Get-DnsClientCache (A/AAAA records, keyed by the queried Entry).</summary>
    public int SeedFromSystemCache()
    {
        int n = 0;
        foreach (var (host, ip) in ReadSystemDnsCache()) { Add(0, host, [ip], DateTime.UtcNow); n++; }
        return n;
    }

    public static List<(string Host, string Ip)> ReadSystemDnsCache()
    {
        var list = new List<(string, string)>();
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object Entry,Data | ConvertTo-Json -Compress\"")
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi)!;
            string json = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);
            if (string.IsNullOrWhiteSpace(json)) return list;
            using var doc = JsonDocument.Parse(json);
            IEnumerable<JsonElement> items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray() : [doc.RootElement];
            foreach (var it in items)
            {
                var e = it.GetProperty("Entry").GetString(); var d = it.GetProperty("Data").GetString();
                if (!string.IsNullOrEmpty(e) && !string.IsNullOrEmpty(d)) list.Add((e, d));
            }
        }
        catch { }
        return list;
    }
}
