using System.Net;
using System.Net.Sockets;
using MaxMind.Db;
using Outbound.Core.Domains;

namespace Outbound.Core.Geo;

public sealed record GeoInfo(string? CountryCode, string? Country, string? City, double? Lat, double? Lon, bool IsLocal)
{
    public static readonly GeoInfo Local = new(null, "Local network", null, null, null, true);
    public static readonly GeoInfo Unknown = new(null, null, null, null, null, false);
    public override string ToString() => IsLocal ? "Local network" : CountryCode == null ? "?" : $"{CountryCode} {City}".Trim();
}

/// <summary>Offline GeoIP: DB-IP Lite City (CC BY 4.0) mmdb via MaxMind.Db (Apache-2.0). No online lookups.</summary>
public sealed class GeoIp : IDisposable
{
    private readonly Reader _reader;
    public GeoIp(string mmdbPath) => _reader = new Reader(mmdbPath, FileAccessMode.MemoryMapped);

    public static GeoIp? TryOpenDefault()
    {
        var p = AssetLocator.Find(Path.Combine("geoip", "dbip-city-lite.mmdb"));
        try { return p == null ? null : new GeoIp(p); } catch { return null; }
    }

    public GeoInfo Lookup(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return GeoInfo.Unknown;
        if (IsLocal(a)) return GeoInfo.Local;
        try
        {
            var d = _reader.Find<Dictionary<string, object>>(a);
            if (d == null) return GeoInfo.Unknown;
            string? cc = Get(d, "country", "iso_code") as string;
            string? country = Get(d, "country", "names", "en") as string;
            string? city = Get(d, "city", "names", "en") as string;
            double? lat = Get(d, "location", "latitude") is double la ? la : null;
            double? lon = Get(d, "location", "longitude") is double lo ? lo : null;
            return new GeoInfo(cc, country, city, lat, lon, false);
        }
        catch { return GeoInfo.Unknown; }
    }

    private static object? Get(Dictionary<string, object> d, params string[] path)
    {
        object? cur = d;
        foreach (var k in path)
            cur = cur is Dictionary<string, object> m && m.TryGetValue(k, out var v) ? v : null;
        return cur;
    }

    public static bool IsLocal(IPAddress a)
    {
        if (IPAddress.IsLoopback(a)) return true;
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || (a.GetAddressBytes()[0] & 0xFE) == 0xFC || a.Equals(IPAddress.IPv6Any);
        var b = a.GetAddressBytes();
        return b[0] == 10 || b[0] == 127 || b[0] == 0 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || b[0] >= 224;
    }

    public void Dispose() => _reader.Dispose();
}
