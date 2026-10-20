using System.IO.Pipes;
using System.Text.Json;
using Outbound.Core.Enforcement;
using Outbound.Core.Identity;
using Outbound.Core.Monitoring;
using Outbound.Core.Network;
using Outbound.Core.Policy;
using Outbound.Core.Rules;
using Outbound.Core.Store;

namespace Outbound.Ctl;

public static class Program
{
    private const string PipeName = "OutboundWin"; // must match IpcServer.PipeName in the app

    private static string DbPath() =>
        Environment.GetEnvironmentVariable("OUTBOUND_RULES") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "rules.db");

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0) return PrintHelp();
            string db = DbPath();
            switch (args[0].ToLowerInvariant())
            {
                // ---- Phase 5: talk to the RUNNING app over a named pipe (same figures as the UI) ----
                case "status": return StatusCmd();
                case "mode": return ModeCmd(args.Skip(1).ToArray());
                case "rules": return RulesPipe(args.Skip(1).ToArray(), db);
                case "profiles": return ProfilesCmd();
                case "blocklists": return BlocklistsCmd(args.Skip(1).ToArray());
                case "limits": return LimitsCmd(args.Skip(1).ToArray());
                case "explain": return ExplainPipe(args.Skip(1).ToArray());
                case "export": return ExportCmd(args.Skip(1).ToArray());
                case "ui": return UiCmd(args.Skip(1).ToArray());
                case "diag": return DiagCmd(args.Skip(1).ToArray());
                case "mcp": return McpLaunch();

                // ---- local commands (no app needed) ----
                case "flows": return Flows(args.Skip(1).ToArray());
                case "stats": return Stats();
                case "watch": return Watch.Run(args.Skip(1).ToArray(), db);
                case "signer": return SignerCmd(args.Skip(1).ToArray());
                case "enforce": return EnforceCmd(args.Skip(1).ToArray(), db);
                case "review": return ReviewCmd(args.Skip(1).ToArray(), db);
                default: Console.Error.WriteLine($"unknown command '{args[0]}'"); return PrintHelp();
            }
        }
        catch (Exception ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 1; }
    }

    // ---------- pipe client ----------

    private static JsonElement Pipe(string cmd, Dictionary<string, object?>? args = null)
    {
        var payload = new Dictionary<string, object?> { ["id"] = 1, ["cmd"] = cmd };
        if (args != null) foreach (var kv in args) payload[kv.Key] = kv.Value;
        string reqLine = JsonSerializer.Serialize(payload);

        // Retry: the server swaps pipe instances between connections — a connect that lands on a dying
        // instance throws InvalidPipeException, so reconnect briefly.
        for (int attempt = 0; ; attempt++)
        {
            // SECURITY: the pipe is current-user-only via the SERVER's PipeSecurity (Allow current
            // user, Deny NETWORK S-1-5-2, default-deny everything else). We deliberately do NOT use
            // PipeOptions.CurrentUserOnly here: it is a known .NET bug (dotnet/runtime#123903) that
            // derives the allowed SID from the server process's OWNER (who launched it), so an app
            // started by admin (owner=Administrators) breaks access for the user's own token with
            // "pipe ... not owned by the current user". The server DACL is the authoritative control.
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.None);
            try
            {
                try { pipe.Connect(2000); }
                catch (TimeoutException)
                {
                    if (attempt == 0) { Console.Error.WriteLine("app not running — start Outbound first"); Environment.Exit(4); }
                    throw;
                }

                // Write the request FIRST, then read — creating a StreamReader before writing can block on its initial read.
                var reqBytes = System.Text.Encoding.UTF8.GetBytes(reqLine + "\n");
                pipe.Write(reqBytes, 0, reqBytes.Length);
                pipe.Flush();

                using var ms = new MemoryStream();
                var buf = new byte[4096];
                while (true) // read until the response line's newline arrives
                {
                    int n;
                    try { n = pipe.Read(buf, 0, buf.Length); }
                    catch (IOException) { throw; } // outer catch retries on instance-swap races
                    if (n == 0) break;
                    ms.Write(buf, 0, n);
                    var all = ms.ToArray();
                    int nl = Array.IndexOf(all, (byte)'\n');
                    if (nl >= 0) { ms.SetLength(nl); break; }
                }
                string line = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                if (line.Length == 0) throw new Exception("app closed the pipe");
                var doc = JsonDocument.Parse(line);
                if (!doc.RootElement.GetProperty("ok").GetBoolean())
                    throw new Exception(doc.RootElement.GetProperty("error").GetString() ?? "unknown error");
                return doc.RootElement.GetProperty("result");
            }
            catch (IOException) when (attempt < 2) { Thread.Sleep(150); continue; } // raced the instance swap — retry
        }
    }

    private static int StatusCmd()
    {
        var r = Pipe("status");
        Console.WriteLine($"mode={r.GetProperty("mode")}  dry-run=true  flows={r.GetProperty("flows")}  rules={r.GetProperty("rules")} (enabled {r.GetProperty("enabledRules")})  uptime={r.GetProperty("uptimeSeconds")}s");
        return 0;
    }

    private static int ModeCmd(string[] args)
    {
        if (args.Length == 0 || args[0] == "get")
        { Console.WriteLine(Pipe("mode.get").GetProperty("mode").GetString()!); return 0; }
        if (args[0] == "set" && args.Length >= 2)
        { Console.WriteLine($"mode set to {Pipe("mode.set", new() { ["mode"] = args[1] }).GetProperty("mode")}"); return 0; }
        Console.Error.WriteLine("usage: mode get | mode set <learn|ask|strict>"); return 2;
    }

    private static int ProfilesCmd()
    {
        var r = Pipe("profiles.list");
        Console.WriteLine($"network={r.GetProperty("network")}  activeProfile={(string.IsNullOrEmpty(r.GetProperty("activeProfile").GetString()) ? "(none)" : r.GetProperty("activeProfile"))}");
        foreach (var p in r.GetProperty("profiles").EnumerateArray())
            Console.WriteLine($"  {p.GetProperty("name")} — {p.GetProperty("mode")}");
        if (r.TryGetProperty("networkMap", out var map) && map.EnumerateObject().Any())
            foreach (var kv in map.EnumerateObject()) Console.WriteLine($"  auto: {kv.Name} → {kv.Value.GetString()}");
        return 0;
    }

    private static int BlocklistsCmd(string[] args)
    {
        if (args.Length == 0 || args[0] == "list")
        {
            var r = Pipe("blocklists.list");
            Console.WriteLine($"loaded entries={r.GetProperty("totalEntries")}");
            foreach (var s in r.GetProperty("subs").EnumerateArray())
                Console.WriteLine($"  {(s.GetProperty("enabled").GetBoolean() ? "" : "[off] ")}{s.GetProperty("name")} — {s.GetProperty("entries")} entries ({s.GetProperty("url")}){(string.IsNullOrEmpty(s.GetProperty("lastError").GetString()) ? "" : $"  ⚠ {s.GetProperty("lastError")} (cached list in use)")}");
            return 0;
        }
        if (args[0] == "add" && args.Length >= 3)
        { Console.WriteLine($"added blocklist '{Pipe("blocklists.add", new() { ["name"] = args[1], ["url"] = args[2] }).GetProperty("added")}' — fetching in background"); return 0; }
        if (args[0] == "remove" && args.Length >= 2)
        { Console.WriteLine($"removed blocklist '{Pipe("blocklists.remove", new() { ["name"] = args[1] }).GetProperty("removed")}'"); return 0; }
        if ((args[0] == "enable" || args[0] == "disable") && args.Length >= 2)
        { var r = Pipe("blocklists.toggle", new() { ["name"] = args[1], ["enabled"] = args[0] == "enable" }); Console.WriteLine($"blocklist '{r.GetProperty("name")}' {(r.GetProperty("enabled").GetBoolean() ? "enabled" : "disabled")}"); return 0; }
        if (args[0] == "refresh")
        { var r = Pipe("blocklists.refresh"); Console.WriteLine($"fetch started — entries so far: {r.GetProperty("totalEntries")}"); return 0; }
        Console.Error.WriteLine("usage: blocklists list|add <name> <url>|remove <name>|enable|disable <name>|refresh");
        return 2;
    }

    private static int LimitsCmd(string[] args)
    {
        if (args.Length == 0 || args[0] == "list")
        {
            var r = Pipe("limits.list");
            foreach (var s in r.GetProperty("limits").EnumerateArray())
                Console.WriteLine($"  {s.GetProperty("appKey")} — limit {s.GetProperty("limitBytes")} B/day · used {s.GetProperty("todayBytes")} B ({Math.Round(s.GetProperty("percent").GetDouble() * 100, 0):F0}% today){(s.GetProperty("blocked").GetBoolean() ? " — BLOCKED until midnight" : "")}");
            return 0;
        }
        if (args[0] == "set" && args.Length >= 3)
        { var r = Pipe("limits.set", new() { ["app"] = args[1], ["bytes"] = args[2] }); Console.WriteLine($"limit set: {r.GetProperty("appKey")} — {r.GetProperty("limitBytes")} B/day"); return 0; }
        if (args[0] == "clear" && args.Length >= 2)
        { var r = Pipe("limits.clear", new() { ["app"] = args[1] }); Console.WriteLine($"cleared limit for '{r.GetProperty("appKey")}'"); return 0; }
        Console.Error.WriteLine("usage: limits list|set <exe-or-name> <bytes e.g. 100MB>|clear <exe-or-name>");
        return 2;
    }

    private static int RulesPipe(string[] args, string db)
    {
        if (args.Length == 0 || args[0] == "list")
        {
            foreach (var r in Pipe("rules.list").EnumerateArray())
                Console.WriteLine($"#{r.GetProperty("id")} [{r.GetProperty("action")}] app={r.GetProperty("app")} dest={r.GetProperty("destination")}({r.GetProperty("kind")}) port={r.GetProperty("port")} proto={r.GetProperty("proto")} life={r.GetProperty("lifetime")} prio={r.GetProperty("priority")} prof={(string.IsNullOrEmpty(r.GetProperty("profile").GetString()) ? "(all)" : r.GetProperty("profile"))} src={r.GetProperty("source")} {(r.GetProperty("enabled").GetBoolean() ? "on" : "OFF")}");
            return 0;
        }
        if (args[0] == "count")
        { var c = Pipe("rules.count"); Console.WriteLine($"total={c.GetProperty("total")} enabled={c.GetProperty("enabled")} disabled={c.GetProperty("disabled")}"); return 0; }
        if (args[0] == "add" && args.Length >= 2)
        {
            var a = new Dictionary<string, object?>();
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--deny") a["action"] = "deny";
                else if (args[i] == "--allow") a["action"] = "allow";
                else if (args[i] == "--app" && i + 1 < args.Length) a["app"] = args[++i];
                else if (args[i] == "--dest" && i + 1 < args.Length) a["dest"] = args[++i];
                else if (args[i] == "--port" && i + 1 < args.Length) a["port"] = args[++i];
                else if (args[i] == "--proto" && i + 1 < args.Length) a["proto"] = args[++i];
                else if (args[i] == "--kind" && i + 1 < args.Length) a["kind"] = args[++i];
                else if (args[i] == "--priority") a["priority"] = true;
                else if (args[i] == "--profile" && i + 1 < args.Length) a["profile"] = args[++i];
                else if (args[i] == "--lifetime" && i + 1 < args.Length) a["lifetime"] = args[++i];
            }
            var r = Pipe("rules.add", a);
            Console.WriteLine($"added #{r.GetProperty("id")}: {r.GetProperty("description")}"); return 0;
        }
        if (args[0] == "remove" && long.TryParse(args.ElementAtOrDefault(1), out var rid))
        { Console.WriteLine($"removed #{Pipe("rules.remove", new() { ["id"] = rid }).GetProperty("removed")}"); return 0; }
        if ((args[0] == "enable" || args[0] == "disable") && long.TryParse(args.ElementAtOrDefault(1), out var id2))
        { Pipe($"rules.{args[0]}", new() { ["id"] = id2 }); Console.WriteLine($"rule #{id2} {(args[0] == "enable" ? "enabled" : "disabled")}"); return 0; }
        if (args[0] == "purge") // local op — no app needed
        {
            using var store = new RuleStore(db);
            var gone = store.PurgeExpired(DateTime.UtcNow, SystemKeys.Current());
            foreach (var g in gone) Console.WriteLine($"purged #{g}");
            Console.WriteLine($"purged {gone.Count} expired rule(s)"); return 0;
        }
        if (args[0] == "propose" && args.Length >= 2) // blocking: waits for the approval dialog (up to 60 s)
        {
            var a = new Dictionary<string, object?>();
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--deny") a["action"] = "deny";
                else if (args[i] == "--allow") a["action"] = "allow";
                else if (args[i] == "--app" && i + 1 < args.Length) a["app"] = args[++i];
                else if (args[i] == "--dest" && i + 1 < args.Length) a["dest"] = args[++i];
                else if (args[i] == "--port" && i + 1 < args.Length) a["port"] = args[++i];
                else if (args[i] == "--proto" && i + 1 < args.Length) a["proto"] = args[++i];
                else if (args[i] == "--kind" && i + 1 < args.Length) a["kind"] = args[++i];
                else if (args[i] == "--priority") a["priority"] = true;
                else if (args[i] == "--profile" && i + 1 < args.Length) a["profile"] = args[++i];
                else if (args[i] == "--lifetime" && i + 1 < args.Length) a["lifetime"] = args[++i];
            }
            var r = Pipe("rules.propose", a);
            if (r.TryGetProperty("approved", out var ap) && ap.GetBoolean()) Console.WriteLine($"APPROVED — added #{r.GetProperty("id")}: {r.GetProperty("description")}");
            else Console.WriteLine($"denied by user{(r.TryGetProperty("reason", out var rs) ? $" — {rs.GetString()}" : "")}");
            return 0;
        }
        Console.Error.WriteLine("usage: rules list|count|add --allow|--deny --dest D [--app X] [--port P] [--proto tcp|udp] [--kind host|domain|ip|cidr|local] [--priority] [--lifetime …]|remove <id>|enable|disable <id>|purge");
        return 2;
    }

    private static int ExplainPipe(string[] args)
    {
        string? app = null, host = null, ip = null, proto = null; ushort port = 0; bool json = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--app") app = args[++i];
            else if (args[i] == "--ip") ip = args[++i];
            else if (args[i] == "--host") host = args[++i];
            else if (args[i] == "--port") port = ushort.Parse(args[++i]);
            else if (args[i] == "--proto") proto = args[++i];
            else if (args[i] == "--json") json = true;
        }
        if (host == null && ip == null) { Console.Error.WriteLine("--ip or --host required"); return 2; }
        var r = Pipe("explain", new() { ["app"] = app, ["host"] = host, ["ip"] = ip, ["port"] = port, ["proto"] = proto });
        if (json) { Console.WriteLine(JsonSerializer.Serialize(r, JsonOpts)); return 0; }
        Console.WriteLine($"Decision: {r.GetProperty("decision")}");
        string reason = r.GetProperty("reason").GetString() ?? "";
        Console.WriteLine($"Decided by: rule {r.GetProperty("decidedBy")}{(reason.Length > 0 ? $" — {reason}" : "")}");
        foreach (var m in r.GetProperty("matchingRules").EnumerateArray())
            Console.WriteLine($"  matching #{m.GetProperty("id")}: {m.GetProperty("description")}");
        if (r.TryGetProperty("expiredMatches", out var ex) && ex.GetArrayLength() > 0)
            foreach (var m in ex.EnumerateArray())
                Console.WriteLine($"  expired #{m.GetProperty("id")}: {m.GetProperty("description")}");
        return r.GetProperty("decision").GetString() == "deny" ? 3 : 0;
    }

    /// <summary>ui show &lt;page&gt; — switch the running app's visible page (overview|activity|rules|review|map|settings).</summary>
    private static int UiCmd(string[] args)
    {
        if (args.Length >= 2 && args[0] == "show")
        {
            var r = Pipe("ui.show", new() { ["page"] = args[1] });
            Console.WriteLine($"ui page = {r.GetProperty("page")}");
            return 0;
        }
        if (args.Length >= 1 && args[0] == "compact")
        {
            Pipe("ui.compact");
            Console.WriteLine("compact Activity feed opened");
            return 0;
        }
        if (args.Length >= 1 && args[0] == "activate")
        {
            Pipe("ui.activate");
            Console.WriteLine("window activated");
            return 0;
        }
        if (args.Length >= 2 && args[0] == "theme")
        {
            var r = Pipe("ui.theme", new() { ["theme"] = args[1] });
            Console.WriteLine($"theme = {r.GetProperty("theme")}");
            return 0;
        }
        Console.Error.WriteLine("usage: ui show <page> | ui compact | ui theme <System|Light|Dark|Midnight|Aurora> | ui activate");
        return 2;
    }

    /// <summary>diag flows — dump the engine's flow table (biggest byte totals first).</summary>
    private static int DiagCmd(string[] args)
    {
        if (args.Length == 0 || args[0] != "flows") { Console.Error.WriteLine("usage: diag flows"); return 2; }
        var r = Pipe("diag.flows");
        Console.WriteLine($"source={r.GetProperty("source")}  live={r.GetProperty("live")}  netEvents={r.GetProperty("netEvents")}  dnsEvents={r.GetProperty("dnsEvents")}");
        Console.WriteLine($"flows={r.GetProperty("flowCount")}  withBytes={r.GetProperty("withBytes")}  totalRecv={r.GetProperty("totalRecv")}  totalSent={r.GetProperty("totalSent")}");
        if (r.TryGetProperty("reason", out var rs) && rs.GetString() is string reason && reason.Length > 0)
            Console.WriteLine("reason=" + reason);
        if (r.TryGetProperty("byApp", out var byApp))
            foreach (var a in byApp.EnumerateArray())
                Console.WriteLine($"  [app] {a.GetProperty("app").GetString(),-30} {a.GetProperty("bytes"),-14} ({a.GetProperty("flows")} flows)");
        foreach (var f in r.GetProperty("top").EnumerateArray())
            Console.WriteLine($"  {f.GetProperty("app").GetString(),-28} pid={f.GetProperty("pid"),-7} {f.GetProperty("host").GetString(),-30} {f.GetProperty("remote").GetString(),-24} {f.GetProperty("proto").GetString(),-4} sent={f.GetProperty("sent"),-12} recv={f.GetProperty("recv")}");
        return 0;
    }

    private static int ExportCmd(string[] args)
    {
        if (args.Length > 0 && args[0] != "--jsonl") { Console.Error.WriteLine("usage: export --jsonl"); return 2; }
        string? text = Pipe("export.jsonl").GetString();
        if (!string.IsNullOrEmpty(text)) Console.Write(text); // JSON Lines, one rule per line
        return 0;
    }

    private static int McpLaunch()
    {
        // outbound-mcp.exe is copied next to outboundctl via ProjectReference; fall back to the dev tree.
        string[] candidates =
        [
            Path.Combine(AppContext.BaseDirectory, "outbound-mcp.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "src", "outbound-mcp", "bin", "Debug", "net8.0", "outbound-mcp.exe")),
        ];
        string? exe = candidates.FirstOrDefault(File.Exists);
        if (exe == null) { Console.Error.WriteLine("outbound-mcp.exe not found next to outboundctl"); return 1; }
        var psi = new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = false };
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.WaitForExit();
        return p.ExitCode;
    }

    // ---------- local commands (unchanged from Phase 2/3) ----------

    private static int Flows(string[] args)
    {
        bool json = args.Contains("--json");
        var rows = NetworkTable.Snapshot();
        if (json)
        {
            var payload = rows.Select(r => new { pid = r.Pid, process = SafeName(r.Pid),
                local = $"{r.LocalIp}:{r.LocalPort}", remote = $"{r.RemoteIp}:{r.RemotePort}",
                proto = r.Proto.ToString().ToLowerInvariant(), state = r.State.ToString() });
            Console.WriteLine(JsonSerializer.Serialize(payload, JsonOpts));
            return 0;
        }
        Console.WriteLine($"{"{PROCESS",-24} {"PID",6} {"LOCAL",22} {"REMOTE",24} {"PROTO",5} STATE");
        foreach (var r in rows.OrderBy(r => r.Pid))
            Console.WriteLine($"{SafeName(r.Pid),-24} {r.Pid,6} {r.LocalIp}:{r.LocalPort,-15} {r.RemoteIp}:{r.RemotePort,-17} {r.Proto.ToString().ToLowerInvariant(),-5} {r.State}");
        return 0;
    }

    private static int SignerCmd(string[] args)
    {
        foreach (var f in args)
        {
            var s = Signer.Get(f);
            Console.WriteLine($"{s.Kind,-9} catalog={s.CatalogSigned,-5} publisher={s.Publisher ?? "-"} | display={s.Display} | {f}");
        }
        return 0;
    }

    private static int Stats()
    {
        var rows = NetworkTable.Snapshot();
        var byProc = rows.GroupBy(r => SafeName(r.Pid))
            .Select(g => new { process = g.Key, flows = g.Count(), tcp = g.Count(x => x.Proto == Protocol.Tcp), udp = g.Count(x => x.Proto == Protocol.Udp) })
            .OrderByDescending(x => x.flows).Take(15);
        Console.WriteLine($"{"{PROCESS",-24} {"FLOWS",6} {"TCP",5} {"UDP",5}");
        foreach (var s in byProc) Console.WriteLine($"{s.process,-24} {s.flows,6} {s.tcp,5} {s.udp,5}");
        return 0;
    }

    private static int EnforceCmd(string[] args, string db)
    {
        bool dry = !args.Contains("--apply");
        using var store = new RuleStore(db);
        var installed = new FirewallEnforcer().EnumerateInstalledRuleNames();
        var plan = EnforcementPlanner.Plan(store.All(), installed);
        Console.WriteLine($"dry-run={dry}  installed-OutboundWin-rules={installed.Count}  to-add={plan.AddCommands.Count}  to-remove={plan.RemoveCommands.Count}");
        foreach (var c in plan.AllCommands) Console.WriteLine(c);
        return dry ? 0 : (plan.Count > 0 ? 3 : 0); // --apply is a stub until you approve real blocking
    }

    private static int ReviewCmd(string[] args, string db)
    {
        var review = new ReviewStore(db);
        if (args.FirstOrDefault() == "items")
            foreach (var i in review.Items())
                Console.WriteLine($"#{i.Id} [{ReviewActionNames.Of(i.Action)}] {i.AppName,-24} {i.Host ?? i.RemoteIp} {i.Port}/{i.Proto} · {i.Reason}");
        else
            Console.WriteLine("usage: review items");
        review.Dispose();
        return 0;
    }

    private static string SafeName(int pid)
    {
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); return p.ProcessName; }
        catch { return $"<pid {pid}>"; }
    }

    private static int PrintHelp()
    {
        Console.WriteLine("""
            outboundctl — Outbound CLI (local-first, no telemetry)

            App commands (talk to the running app over a named pipe):
              status                                  mode, dry-run flag, flow/rule counts, uptime
              mode get | mode set <learn|ask|strict>  read / change enforcement mode live
              rules list|count                        same figures as the Rules page
              rules add --allow|--deny --dest D [--app X] [--port P] [--proto tcp|udp] [--kind host|domain|ip|cidr|local] [--priority] [--profile NAME] [--lifetime forever|1h|once|quit|logout|restart]
              profiles                                current network, active profile, auto-switch map
              blocklists list|add <name> <url>|remove <name>|enable|disable <name>|refresh   HTTPS domain lists (hosts format)
              limits list|set <exe-or-name> <bytes e.g. 100MB>|clear <exe-or-name>        per-app daily data limit
              rules remove <id> · rules enable|disable <id> · rules purge (local)
              rules propose --allow|--deny --dest D [same flags as add]   blocking — waits for the approval dialog
              explain --app X --host H [--ip IP] [--port P] [--proto x] [--json]   Decision + deciding rule ID + matching rules
              export --jsonl                          all rules as JSON Lines
              ui show <page>                          switch the running app to a page (overview|activity|rules|review|map|settings)
              mcp                                     launch the MCP server (stdio)

            Local commands (no app needed):
              flows [--json] · stats · watch [--seconds N] [--host s] [--exe x] [--json] [--no-etw]
              signer <file>… · enforce [--apply] · review items
            """);
        return 2;
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
}
