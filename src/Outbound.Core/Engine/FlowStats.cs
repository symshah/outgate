using Outbound.Core.Geo;
using Outbound.Core.Identity;
using Outbound.Core.Network;

namespace Outbound.Core.Engine;

public readonly record struct FlowKey(int Pid, Protocol Proto, string RemoteIp, ushort RemotePort);

/// <summary>Per (process, remote endpoint) traffic aggregate. Thread-safe counters.</summary>
public sealed class FlowStats
{
    public required FlowKey Key { get; init; }
    public required AppInfo App { get; init; }
    public string? Host { get; set; }          // hostname the app asked DNS for (null → show IP)
    public string? Domain { get; set; }        // registrable domain via PSL
    public GeoInfo Geo { get; set; } = GeoInfo.Unknown;
    public long BytesSent;
    public long BytesRecv;
    public long Packets;
    public DateTime FirstSeenUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    public string? Decision { get; set; }      // "allow" / "deny" / null (Phase 2)
    public long? DecidingRuleId { get; set; }
    internal long StoredSent, StoredRecv;      // portion already flushed to SQLite

    public int Pid => Key.Pid;
    public string RemoteIp => Key.RemoteIp;
    public ushort RemotePort => Key.RemotePort;
    public Protocol Proto => Key.Proto;
    public string DisplayHost => Host ?? Key.RemoteIp;
}
