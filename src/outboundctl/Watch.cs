using System.Text.Json;
using Outbound.Core.Engine;
using Outbound.Core.Etw;
using Outbound.Core.Network;
using Outbound.Core.Policy;
using Outbound.Core.Rules;

namespace Outbound.Ctl;

/// <summary>outboundctl watch [--seconds N] [--pid P] [--host substr] [--json] — run the Phase 1/2 pipeline in-process.</summary>
public static class Watch
{
    public static int Run(string[] args, string db)
    {
        int seconds = 10; int? pid = null; string? host = null; bool json = args.Contains("--json"); string? exe = null;
        for (int i = 0; i < args.Length; i++)
            switch (args[i])
            {
                case "--seconds": seconds = int.Parse(args[++i]); break;
                case "--pid": pid = int.Parse(args[++i]); break;
                case "--host": host = args[++i]; break;
                case "--exe": exe = args[++i]; break;
            }
        using var eng = new OutboundEngine(db);
        var dnsLog = new List<DnsEvent>();
        eng.DnsResolved += e => { lock (dnsLog) dnsLog.Add(e); };
        eng.Start(preferEtw: !args.Contains("--no-etw"));

        var policy = new PolicyService(db);
        if (args.Contains("--strict")) policy.Engine.Settings.Mode = Mode.Strict;
        else if (args.Contains("--ask")) policy.Engine.Settings.Mode = Mode.Ask;

        Console.Error.WriteLine($"source={eng.Source} geo={(eng.Geo != null)} psl={eng.Psl?.RuleCount ?? 0} rules={policy.Engine.Rules.ToList().Count} mode={ModeNames.Of(policy.Engine.Settings.Mode)} {(eng.EtwError != null ? "etwError=" + eng.EtwError : "")}");
        Console.Error.WriteLine("READY"); Console.Error.Flush();
        Thread.Sleep(seconds * 1000);

        var flows = eng.Snapshot()
            .Where(f => pid == null || f.Pid == pid)
            .Where(f => exe == null || (f.App.ExePath ?? "").EndsWith(exe, StringComparison.OrdinalIgnoreCase))
            .Where(f => host == null || (f.Host ?? f.RemoteIp).Contains(host, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.BytesRecv + f.BytesSent).ToList();
        Console.Error.WriteLine($"netEvents={eng.NetEvents} dnsEvents={eng.DnsEvents} wireDns={eng.WireDnsEvents} flows={eng.Snapshot().Count}");

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(flows.Select(f => new
            {
                pid = f.Pid, app = f.App.DisplayName, appKey = f.App.Key, exe = f.App.ExePath, signer = f.App.Signer.Display,
                host = f.Host, domain = f.Domain, remote = f.RemoteIp, port = f.RemotePort, proto = f.Proto.ToString().ToUpperInvariant(),
                country = f.Geo.CountryCode, city = f.Geo.City, sent = f.BytesSent, recv = f.BytesRecv, packets = f.Packets,
                lastSeen = f.LastSeenUtc.ToLocalTime().ToString("HH:mm:ss"),
            }), new JsonSerializerOptions { WriteIndented = true }));
        }
        Console.WriteLine($"{"PID",6} {"APP",-22} {"SIGNER",-18} {"HOST",-28} {"REMOTE",-22} {"PORT",5} PR  {"GEO",-14} {"SENT",8} {"RECV",8} LAST");
        foreach (var f in flows)
            Console.WriteLine($"{f.Pid,6} {Trim(f.App.DisplayName, 22),-22} {Trim(f.App.Signer.Display, 18),-18} {Trim(f.Host ?? "-", 28),-28} {f.RemoteIp,-22} {f.RemotePort,5} {f.Proto.ToString().ToUpperInvariant(),-3} {Trim(f.Geo.ToString(), 14),-14} {f.BytesSent,8} {f.BytesRecv,8} {f.LastSeenUtc.ToLocalTime():HH:mm:ss}");
        Console.WriteLine("--- policy decisions (live) ---");
        foreach (var f in flows)
        {
            var d = policy.Engine.Evaluate(ToCtx(f), true, DateTime.UtcNow, SystemKeys.Current());
            string verdict = d.Allow ? "ALLOW" : "DENY";
            string target = (f.Host ?? f.RemoteIp) + ":" + string.Format("{0}", f.RemotePort) + "/" + f.Proto.ToString().ToUpperInvariant();
            Console.WriteLine($"{verdict} pid={f.Pid} {f.App.DisplayName} -> {target}  {d.Reason}");
        }
        return 0;
    }

    private static FlowContext ToCtx(FlowStats f)
    {
        string? exe = f.App.ExePath;
        string name = exe == null ? f.App.DisplayName : Path.GetFileName(exe);
        var proto = f.Proto == Protocol.Udp ? ProtoSpec.Udp : ProtoSpec.Tcp;
        return new FlowContext(f.Pid, name, exe ?? "", f.RemoteIp, f.RemotePort, f.Host, proto);
    }

    private static string Trim(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}
