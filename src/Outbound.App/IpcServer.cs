using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Outbound.Core.Engine;
using Outbound.Core.Policy;
using Outbound.Core.Rules;
using Outbound.Core.Store;

namespace Outbound.App;

/// <summary>
/// Phase 5: named-pipe IPC server — outboundctl (and later the MCP server) talk to the
/// RUNNING app over this pipe, so figures match what the UI shows. Protocol: one JSON
/// object per line in each direction: {"id":1,"cmd":"status","args":{...}} →
/// {"id":1,"ok":true,"result":...} or {"id":1,"ok":false,"error":"..."}.
/// </summary>
public sealed class IpcServer : IDisposable
{
    public const string PipeName = "OutboundWin";
    /// <summary>Concurrent pipe instances — one per in-flight client, so a pending approval dialog never blocks status/list calls.</summary>
    public const int MaxInstances = 16;

    /// <summary>
    /// SECURITY: current-user-only pipe — explicit Allow for the current user (everyone else is
    /// denied by default-deny), plus an explicit DENY of the NETWORK SID (S-1-5-2) so the pipe
    /// cannot be reached over SMB from other machines on the LAN.
    /// </summary>
    public static PipeSecurity CreatePipeSecurity()
    {
        var me = WindowsIdentity.GetCurrent().User!;
        var sec = new PipeSecurity();
        sec.SetOwner(me); // app runs elevated: default owner would be Administrators, which breaks the client's CurrentUserOnly check
        sec.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-2"), PipeAccessRights.FullControl, AccessControlType.Deny)); // NETWORK
        return sec;
    }

    private readonly MainWindow _win;
    private readonly Thread _thread;
    private volatile bool _stop;

    public IpcServer(MainWindow win)
    {
        _win = win;
        _thread = new Thread(Loop) { IsBackground = true, Name = "ipc-pipe" };
        _thread.Start();
    }

    private void Loop()
    {
        LogPipeIdentity(); // Phase 5 regression guard: record pipe owner/user SID + elevation to engine.log
        while (!_stop)
        {
            try
            {
                // Multiple server instances: a blocking command (rules.propose → approval dialog, up to 60 s)
                // must not stall other clients — each connection is served on its own task.
                var pipe = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, MaxInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, CreatePipeSecurity());
                if (_stop) { pipe.Dispose(); return; }
                pipe.WaitForConnection(); // blocks until a client connects (background thread — dies with the process)
                Task.Run(() => Serve(pipe));
            }
            catch (Exception) { /* pipe broken / app closing — retry */ }
        }
    }

    /// <summary>
    /// Phase 5 pipe-ownership regression guard: logs the pipe's security identity to engine.log at
    /// startup. The pipe's owner is set to the current USER SID (CreatePipeSecurity → SetOwner). When
    /// the app is launched elevated, the process launch-OWNER is 'Administrators' — that is exactly
    /// what the old client-side PipeOptions.CurrentUserOnly compared against and failed on (see
    /// outboundctl). This line makes any owner/user mismatch — and a SYSTEM launch — diagnosable
    /// without a debugger.
    /// </summary>
    private static void LogPipeIdentity()
    {
        try
        {
            var id = WindowsIdentity.GetCurrent();
            string user = id.User?.Value ?? "?";
            string owner = id.Owner?.Value ?? "?";
            string account = id.Name ?? "?";
            bool elevated = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            string note = string.Equals(account, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase)
                ? "WARNING: running as SYSTEM — the IPC pipe ACL is keyed to the current user, so a local user's outboundctl CANNOT reach it (do not test via a SYSTEM scheduled task)"
                : elevated
                    ? "app ELEVATED (launch owner=Administrators) — outboundctl works because the client no longer uses PipeOptions.CurrentUserOnly; the server DACL is authoritative"
                    : "app non-elevated";
            EngineLog.Write($"pipe security: ownerSID={user} launchOwnerSID={owner} user={account} elevated={elevated} — {note}");
        }
        catch (Exception ex) { EngineLog.Write("pipe security: identity log failed: " + ex.Message); }
    }

    private void Serve(NamedPipeServerStream pipe)
    {
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096) { AutoFlush = true };
            string? line;
            while ((line = reader.ReadLine()) != null && !_stop)
                if (!string.IsNullOrWhiteSpace(line))
                    try { writer.WriteLine(Handle(JsonDocument.Parse(line))); }
                    catch (Exception ex) { writer.WriteLine(Err(null, "bad request: " + ex.Message)); }
        }
        catch (Exception) { /* client went away */ }
        finally { pipe.Dispose(); }
    }

    private string Handle(JsonDocument doc)
    {
        var root = doc.RootElement;
        object? id = root.TryGetProperty("id", out var i) ? i.Clone() : null;
        string cmd = root.GetProperty("cmd").GetString()?.ToLowerInvariant() ?? "";
        // Clients may nest args under "args" (documented protocol) or send them flat at the root — accept both.
        JsonElement args;
        if (root.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Object) args = a; else args = root;

        try
        {
            object? result = cmd switch
            {
                "status" => Status(),
                "mode.get" => new { mode = ModeNames.Of(_win.Policy.Engine.Settings.Mode) },
                "mode.set" => SetMode(args),
                "rules.list" => RulesList(),
                "rules.count" => RulesCount(),
                "rules.add" => RuleAdd(args),
                "rules.propose" => RulePropose(args),
                "rules.remove" => RuleRemove(args),
                "rules.enable" => RuleSetEnabled(args, true),
                "rules.disable" => RuleSetEnabled(args, false),
                "explain" => Explain(args),
                "profiles.list" => ProfilesList(),
                "blocklists.list" => BlocklistsList(),
                "blocklists.add" => BlocklistAdd(args),
                "blocklists.remove" => BlocklistRemove(args),
                "blocklists.toggle" => BlocklistToggle(args),
                "blocklists.refresh" => BlocklistRefresh(),
                "limits.list" => LimitsList(),
                "limits.set" => LimitSet(args),
                "limits.clear" => LimitClear(args),
                "export.jsonl" => ExportJsonl(),
                "ui.show" => UiShow(args),
                "ui.compact" => UiCompact(),
                "ui.theme" => UiTheme(args),
                "ui.activate" => UiActivate(),
                "diag.flows" => DiagFlows(),
                _ => throw new Exception($"unknown command '{cmd}'"),
            };
            return JsonSerializer.Serialize(new { id, ok = true, result });
        }
        catch (Exception ex) { LogFailure(cmd, ex); return Err(id, ex.Message); }
    }

    private static string Err(object? id, string message) =>
        JsonSerializer.Serialize(new { id, ok = false, error = message });

    /// <summary>Full exception (message + stack trace) for failed commands — %LocalAppData%\OutboundWin\ipc.log.</summary>
    public static void LogFailure(string cmd, Exception ex)
    {
        try
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "ipc.log"), $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] cmd={cmd}\n{ex}\n\n");
        }
        catch { /* logging must never break the pipe */ }
    }

    // ---------- commands ----------

    private object Status()
    {
        var s = _win.Policy.Engine.Settings;
        using var store = new RuleStore(_win.RulesDbPath);
        var rules = store.All();
        return new
        {
            app = "OutboundWin",
            mode = ModeNames.Of(s.Mode),
            dryRun = true, // enforcement stays dry-run until the user applies firewall rules
            flows = _win.FlowCount(),
            rules = rules.Count,
            enabledRules = rules.Count(r => r.Enabled),
            uptimeSeconds = (long)(DateTime.UtcNow - _win.StartedUtc).TotalSeconds,
        };
    }

    private object SetMode(JsonElement args)
    {
        string m = args.GetProperty("mode").GetString() ?? "";
        if (!Enum.TryParse<Outbound.Core.Policy.Mode>(m, true, out var mode))
            throw new Exception($"unknown mode '{m}' (learn|ask|strict)");
        _win.Policy.Engine.Settings.Mode = mode;
        // Keep the Settings page combo in sync when it's open.
        _win.Dispatcher.BeginInvoke(() =>
        {
            int idx = mode switch { Outbound.Core.Policy.Mode.Learn => 0, Outbound.Core.Policy.Mode.Ask => 1, _ => 2 };
            if (_win.CmbMode.SelectedIndex != idx) _win.CmbMode.SelectedIndex = idx;
        });
        return new { mode = ModeNames.Of(mode) };
    }

    private object RulesList()
    {
        using var store = new RuleStore(_win.RulesDbPath);
        return store.All().Select(r => new
        {
            id = r.Id, action = r.Action.ToString(), app = string.IsNullOrEmpty(r.AppMatcher) ? "(any)" : r.AppMatcher,
            destination = r.Destination, kind = r.Kind.ToString(), port = r.PortSpec, proto = r.Protocol.ToString(),
            lifetime = r.Lifetime.ToString(), priority = r.Priority, source = r.Source, enabled = r.Enabled,
            profile = r.Profile ?? "",
        }).ToArray();
    }

    private object ProfilesList()
    {
        var p = _win.Policy.Profiles;
        return new
        {
            network = p.CurrentNetwork,
            activeProfile = p.ActiveProfile ?? "",
            profiles = p.Profiles.Select(x => new { name = x.Name, mode = ModeNames.Of(x.Mode) }).ToArray(),
            networkMap = p.NetworkMap,
        };
    }

    // ---- blocklists (Phase 5) ---------------------------------------------
    private object BlocklistsList()
    {
        var b = _win.Policy.Blocklists;
        return new
        {
            totalEntries = b.TotalEntries,
            subs = b.Subs.Select(s => new
            {
                name = s.Name, url = s.Url, enabled = s.Enabled, entries = s.EntryCount,
                lastOkUtc = s.LastOkUtc?.ToString("o"), lastError = s.LastError ?? "",
            }).ToArray(),
        };
    }

    private object BlocklistAdd(JsonElement args)
    {
        var b = _win.Policy.Blocklists;
        string name = args.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        string url = args.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(name)) throw new Exception("--name required");
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http"))
            throw new Exception("url must be an http(s) URL");
        b.AddSub(name, url); // persists + fetches in background; UI re-renders via Changed event
        return new { added = name };
    }

    private object BlocklistRemove(JsonElement args)
    {
        var b = _win.Policy.Blocklists;
        string name = args.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        b.RemoveSub(name);
        return new { removed = name };
    }

    private object BlocklistToggle(JsonElement args)
    {
        var b = _win.Policy.Blocklists;
        string name = args.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        bool enabled = !args.TryGetProperty("enabled", out var e) || e.GetBoolean();
        b.SetEnabled(name, enabled);
        return new { name, enabled };
    }

    private object BlocklistRefresh()
    {
        var b = _win.Policy.Blocklists;
        // Refresh is a network fetch (up to 60 s) — run it off the pipe thread and report when done.
        Task.Run(async () => await b.RefreshAsync());
        return new { started = true, totalEntries = b.TotalEntries };
    }

    private object LimitsList()
    {
        var l = _win.Policy.Limits;
        return new
        {
            limits = l.All().Select(x => new
            {
                appKey = x.AppKey,
                name = LimitName(x.AppKey),
                limitBytes = x.LimitBytes,
                blockUntilMidnight = x.BlockUntilMidnight,
                todayBytes = x.TodayBytes,
                percent = Math.Round(x.Percent * 100, 1),
                blocked = l.IsBlocked(x.AppKey),
            }).ToArray(),
        };
    }

    private object LimitSet(JsonElement args)
    {
        var l = _win.Policy.Limits;
        string app = args.TryGetProperty("app", out var a) ? a.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(app)) throw new Exception("--app required");
        long bytes = ParseBytes(args.TryGetProperty("bytes", out var b) ? b.ToString() : "");
        bool block = args.TryGetProperty("block", out var bl) && bl.ValueKind == System.Text.Json.JsonValueKind.True;
        string key = NormalizeAppKey(app);
        l.Set(key, bytes, block); // persists + fires Changed (UI re-renders)
        return new { appKey = key, limitBytes = bytes, blockUntilMidnight = block };
    }

    private object LimitClear(JsonElement args)
    {
        var l = _win.Policy.Limits;
        string app = args.TryGetProperty("app", out var a) ? a.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(app)) throw new Exception("--app required");
        string key = NormalizeAppKey(app);
        bool removed = l.Clear(key);
        return new { appKey = key, removed };
    }

    /// <summary>Accepts an exe path or a bare name; resolves bare names against the apps the engine has seen.</summary>
    internal string NormalizeAppKey(string app) => Outbound.Core.Identity.AppResolver.NormalizeAppKey(app, _win.Engine.Snapshot().Select(f => f.App.ExePath).Where(p => !string.IsNullOrEmpty(p)));

    internal static string LimitName(string key)
    {
        if (key.StartsWith("exe:", StringComparison.OrdinalIgnoreCase))
            try { return Outbound.Core.Identity.AppResolver.ResolveByExe(key[4..]).DisplayName; } catch { }
        return key;
    }

    /// <summary>"100MB" / "1.5GB" / plain bytes.</summary>
    internal static long ParseBytes(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) throw new Exception("bytes required, e.g. 100MB");
        var t = s.Trim();
        int i = 0; while (i < t.Length && (char.IsDigit(t[i]) || t[i] == '.')) i++;
        string num = t[..i], unit = t[i..].Trim().ToUpperInvariant();
        if (!double.TryParse(num, System.Globalization.CultureInfo.InvariantCulture, out double v) || v <= 0) throw new Exception($"bad size '{s}'");
        long mult = unit switch { "" => 1, "B" => 1, "KB" => 1_024, "MB" => 1_048_576, "GB" => 1_073_741_824, _ => throw new Exception($"unknown unit '{unit}' (use KB/MB/GB)") };
        return (long)(v * mult);
    }

    private object RulesCount()
    {
        using var store = new RuleStore(_win.RulesDbPath);
        var rules = store.All();
        return new { total = rules.Count, enabled = rules.Count(r => r.Enabled), disabled = rules.Count(r => !r.Enabled) };
    }

    private object RuleAdd(JsonElement args)
    {
        using var store = new RuleStore(_win.RulesDbPath);
        var rule = ParseRule(args);
        rule.ResolveDestination(); rule.StampLifetime(DateTime.UtcNow);
        store.Add(rule);
        return new { id = rule.Id, description = rule.Describe() };
    }

    /// <summary>Phase 5 item 2: MCP path — same rule, but only applied after the user approves in a dialog.</summary>
    private object RulePropose(JsonElement args)
    {
        var rule = ParseRule(args);
        string desc = "action=" + rule.Action.ToString().ToLowerInvariant()
            + "  app=" + (string.IsNullOrEmpty(rule.AppMatcher) ? "(any)" : rule.AppMatcher)
            + "  dest=" + rule.Destination + " (" + rule.Kind.ToString() + ")"
            + "  port=" + rule.PortSpec + "  proto=" + rule.Protocol.ToString().ToLowerInvariant()
            + "  lifetime=" + rule.Lifetime.ToString();

        // Block the pipe thread until the user answers (or the dialog times out → auto-deny).
        bool approved = false; string? error = null;
        _win.Dispatcher.Invoke(() =>
        {
            try
            {
                var dlg = new ApprovalWindow(desc, 60);
                dlg.ShowDialog();
                approved = dlg.Approved;
            }
            catch (Exception ex) { error = "approval dialog failed: " + ex.Message; }
        });
        if (!string.IsNullOrEmpty(error)) throw new Exception(error!);
        if (!approved) return new { approved = false, reason = "denied by user" };

        using var store = new RuleStore(_win.RulesDbPath);
        rule.ResolveDestination(); rule.StampLifetime(DateTime.UtcNow);
        store.Add(rule);
        return new { id = rule.Id, description = rule.Describe(), approved = true };
    }

    private static Rule ParseRule(JsonElement args)
    {
        var rule = new Rule { Destination = "" };
        if (args.TryGetProperty("action", out var a)) rule.Action = a.GetString()!.ToLowerInvariant() == "deny" ? RuleAction.Deny : RuleAction.Allow;
        if (args.TryGetProperty("app", out var ap) && !string.IsNullOrEmpty(ap.GetString())) rule.AppMatcher = ap.GetString()!;
        if (!args.TryGetProperty("dest", out var d)) throw new Exception("--dest required");
        rule.Destination = d.GetString() ?? "";
        if (args.TryGetProperty("port", out var p) && !string.IsNullOrEmpty(p.GetString())) rule.PortSpec = p.GetString()!;
        if (args.TryGetProperty("proto", out var pr) && !string.IsNullOrEmpty(pr.GetString()))
            rule.Protocol = pr.GetString()!.ToLowerInvariant() switch { "udp" => ProtoSpec.Udp, "tcp" => ProtoSpec.Tcp, _ => ProtoSpec.Any };
        if (args.TryGetProperty("kind", out var k) && !string.IsNullOrEmpty(k.GetString()))
            rule.Kind = k.GetString()!.ToLowerInvariant() switch
            {
                "host" => DestKind.Host, "ip" => DestKind.Ip, "cidr" => DestKind.Cidr,
                "local" => DestKind.LocalNetwork, "any" => DestKind.Any, _ => DestKind.Domain,
            };
        if (args.TryGetProperty("priority", out var pr2) && pr2.GetBoolean()) rule.IsPriority = true;
        if (args.TryGetProperty("profile", out var pf) && !string.IsNullOrEmpty(pf.GetString())) rule.Profile = pf.GetString()!;
        if (args.TryGetProperty("lifetime", out var l) && !string.IsNullOrEmpty(l.GetString()))
            rule.Lifetime = Rule.ParseLifetime(l.GetString()!);
        return rule;
    }

    private object RuleRemove(JsonElement args)
    {
        using var store = new RuleStore(_win.RulesDbPath);
        long rid = args.GetProperty("id").GetInt64();
        bool ok = store.Remove(rid);
        if (!ok) throw new Exception($"no rule #{rid}");
        return new { removed = rid };
    }

    private object RuleSetEnabled(JsonElement args, bool enabled)
    {
        using var store = new RuleStore(_win.RulesDbPath);
        long rid = args.GetProperty("id").GetInt64();
        if (!store.SetEnabled(rid, enabled)) throw new Exception($"no rule #{rid}");
        return new { id = rid, enabled };
    }

    private object Explain(JsonElement args)
    {
        string? app = args.TryGetProperty("app", out var a) ? a.GetString() : null;
        string? host = args.TryGetProperty("host", out var h) ? h.GetString() : null;
        string? ip = args.TryGetProperty("ip", out var i) ? i.GetString() : null;
        ushort port = 0;
        if (args.TryGetProperty("port", out var p)) port = (ushort)p.GetInt32();
        if (host == null && ip == null) throw new Exception("--ip or --host required");

        using var store = new RuleStore(_win.RulesDbPath);
        string exePath = "";
        if (!string.IsNullOrEmpty(app))
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
                using (proc)
                    if (proc.ProcessName.Equals(app, StringComparison.OrdinalIgnoreCase))
                        try { exePath = proc.MainModule.FileName; } catch { /* elevated/other user */ }

        var ctx = new FlowContext(0, app ?? "", exePath, ip ?? "", port, host, PolicyService.ToProto(args.TryGetProperty("proto", out var pr) ? (pr.GetString() ?? "") : ""));
        var now = DateTime.UtcNow;
        var lc = SystemKeys.Current();
        var all = store.All().ToList();
        var (matched, reason) = RuleMatcher.Decide(all, ctx, now, lc);
        // No rule decides → the blocklist may still deny (same order as PolicyEngine.Evaluate).
        if (matched == null)
        {
            string? bl = _win.Policy.Blocklists.WhichList(host);
            if (bl != null)
            {
                matched = new Rule { Id = -1, Action = RuleAction.Deny, Destination = host ?? "" }; // sentinel: not a stored rule
                reason = $"blocklist '{bl}': host {host} is listed";
            }
        }
        // Live matches only — expired rules must NOT be listed as matching (they don't decide).
        return new
        {
            decision = matched == null ? "allow" : matched.Action.ToString().ToLowerInvariant(),
            decidedBy = matched?.Id == -1 ? "(blocklist)" : (matched?.Id.ToString() ?? "(default)"),
            matchingRules = all.Where(r => RuleMatcher.LiveMatch(r, ctx, now, lc))
                .Select(r => new { id = r.Id, description = r.Describe() }).ToArray(),
            // Rules that WOULD match if not expired — shown so the user sees why nothing applied.
            expiredMatches = all.Where(r => r.Enabled && r.IsExpired(now, lc)
                && RuleMatcher.AppMatches(r.AppMatcher, ctx)
                && RuleMatcher.DestMatches(r, ctx) && RuleMatcher.PortMatches(r.PortSpec, port))
                .Select(r => new { id = r.Id, description = r.Describe() + " (EXPIRED)" }).ToArray(),
            reason,
        };
    }

    /// <summary>
    /// Switch the running UI to a page on the UI thread — `outboundctl ui show &lt;page&gt;`.
    /// Used for automated screenshots/parity checks and by accessibility tooling.
    /// </summary>
    private object UiShow(JsonElement args)
    {
        string page = (args.TryGetProperty("page", out var p) ? p.GetString() : null)?.ToLowerInvariant() ?? "";
        string[] valid = { "overview", "activity", "rules", "review", "map", "settings" };
        if (!valid.Contains(page)) throw new Exception($"unknown page '{page}' (overview|activity|rules|review|map|settings)");

        // Run on the UI thread and wait for the render pass, so a screenshot taken right after
        // this call returns shows the new page.
        _win.Dispatcher.Invoke(() => _win.ShowPageForAutomation(page));
        _win.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);
        return new { page };
    }

    /// <summary>
    /// Flow-table diagnostics (`outboundctl diag flows`): what the engine actually holds, biggest
    /// byte totals first — answers "why isn't app X showing bytes?".
    /// </summary>
    private object DiagFlows()
    {
        var flows = _win.Engine.Snapshot();
        return new
        {
            source = _win.Engine.Source,
            live = _win.Engine.LiveMonitoring,
            reason = _win.Engine.MonitoringReason,
            netEvents = _win.Engine.NetEvents,
            dnsEvents = _win.Engine.DnsEvents,
            flowCount = flows.Count,
            withBytes = flows.Count(f => f.BytesSent + f.BytesRecv > 0),
            totalRecv = flows.Sum(f => f.BytesRecv),
            totalSent = flows.Sum(f => f.BytesSent),
            // exactly what the Overview card computes: per-app totals, biggest first
            byApp = flows.GroupBy(f => f.App.DisplayName)
                .Select(g => new { app = g.Key, bytes = g.Sum(x => x.BytesRecv + x.BytesSent), flows = g.Count() })
                .OrderByDescending(x => x.bytes).Take(6).ToArray(),
            top = flows.OrderByDescending(f => f.BytesSent + f.BytesRecv).Take(12).Select(f => new
            {
                app = f.App.DisplayName,
                pid = f.Pid,
                host = f.Host ?? "",
                remote = f.RemoteIp + ":" + f.RemotePort,
                proto = f.Proto.ToString(),
                sent = f.BytesSent,
                recv = f.BytesRecv,
                lastSeenUtc = f.LastSeenUtc.ToString("O"),
            }).ToArray(),
        };
    }

    /// <summary>Bring the main window to the front — a second launch uses this, and `outboundctl ui activate`.</summary>
    private object UiActivate()
    {
        _win.Dispatcher.Invoke(() => _win.ShowFromTray());
        return new { activated = true, source = _win.Engine.Source, monitoring = _win.Engine.LiveMonitoring, reason = _win.Engine.MonitoringReason };
    }

    /// <summary>Open (or focus) the compact live Activity window — `outboundctl ui compact`.</summary>
    private object UiCompact()
    {
        _win.Dispatcher.Invoke(() => _win.ToggleCompact());
        _win.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);
        return new { compact = true };
    }

    /// <summary>Switch the app theme live (System|Light|Dark|Midnight) — `outboundctl ui theme &lt;name&gt;`.</summary>
    private object UiTheme(JsonElement args)
    {
        string theme = (args.TryGetProperty("theme", out var t) ? t.GetString() : null) ?? "";
        theme = ThemeManager.Normalize(theme);
        _win.Dispatcher.Invoke(() => ThemeManager.Apply(theme, _win));
        _win.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);
        return new { theme = ThemeManager.Current };
    }

    private object ExportJsonl()
    {
        using var store = new RuleStore(_win.RulesDbPath);
        return string.Join("\n", store.All().Select(r => JsonSerializer.Serialize(new
        {
            id = r.Id, action = r.Action.ToString(), app = r.AppMatcher ?? "", destination = r.Destination,
            kind = r.Kind.ToString(), port = r.PortSpec, proto = r.Protocol.ToString(),
            lifetime = r.Lifetime.ToString(), priority = r.Priority, source = r.Source, enabled = r.Enabled,
        })));
    }

    public void Dispose()
    {
        _stop = true; // server thread is background — it exits on its own
    }
}
