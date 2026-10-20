using System.IO.Pipes;
using System.Text.Json;
using Outbound.Core.Network;
using Outbound.Core.Rules;
using Outbound.Core.Store;

namespace Outbound.Mcp;

/// <summary>
/// outbound-mcp — minimal Model Context Protocol server (JSON-RPC 2.0 over stdio).
/// Phase 5 item 2: talks to the RUNNING app over the named pipe so figures match the UI, and
/// rule changes go through the app's approval dialog (rules.propose) — an AI agent can never
/// change a rule without the user clicking Approve. Read-only tools fall back to local tables
/// when the app is not running; propose_rule requires the app (falls back to proposal text).
/// </summary>
public static class Program
{
    private const string ServerName = "outbound";
    private const string Version = "0.2.0";
    private const string PipeName = "OutboundWin"; // must match IpcServer.PipeName in the app

    public static async Task Main()
    {
        using var reader = new StreamReader(Console.OpenStandardInput());
        while (true)
        {
            string? line = await reader.ReadLineAsync();
            if (line == null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            string response;
            try { response = Handle(JsonDocument.Parse(line)); }
            catch (Exception ex)
            {
                response = JsonSerializer.Serialize(new
                {
                    jsonrpc = "2.0", id = (object?)null,
                    error = new { code = -32603, message = ex.Message },
                });
            }
            if (response.Length == 0) continue; // JSON-RPC notifications get no reply at all
            Console.WriteLine(response);
            Console.Out.Flush();
        }
    }

    private static string Handle(JsonDocument doc)
    {
        var root = doc.RootElement;
        object? id = root.TryGetProperty("id", out var i) ? i : null;
        string method = root.GetProperty("method").GetString() ?? "";
        JsonElement? @params = root.TryGetProperty("params", out var p) ? p : null;

        (object? Result, bool IsNotification) result = method switch
        {
            "initialize" => (new
            {
                protocolVersion = "2024-11-05",
                serverInfo = new { name = ServerName, version = Version },
                capabilities = new { tools = new { } },
            }, false),

            "notifications/initialized" => (null, true),

            "tools/list" => (new { tools = ToolDefs() }, false),

            "tools/call" => (ToolCall(@params!.Value), false),

            _ => throw new Exception($"method not found: {method}"),
        };

        if (result.IsNotification) return ""; // notifications get no response
        return JsonSerializer.Serialize(new { jsonrpc = "2.0", id, result = result.Result });
    }

    private static object[] ToolDefs() =>
    [
        new
        {
            name = "list_flows",
            description = "Snapshot of live outbound TCP/UDP flows on this machine: process, PID, local/remote endpoint, protocol, state. Read-only.",
            inputSchema = new Dictionary<string, object> { ["type"] = "object", ["properties"] = new Dictionary<string, object>(), ["additionalProperties"] = false },
        },
        new
        {
            name = "explain_flow",
            description = "Explain why a flow (app + remote IP + port) is allowed or denied by the current rule set. Returns decision, deciding rule id and reason.",
            inputSchema = new Dictionary<string, object>
            {
                ["type"] = "object",
                ["properties"] = new Dictionary<string, object>
                {
                    ["ip"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Remote IPv4 address" },
                    ["host"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Optional remote hostname (matches Host/Domain rules)" },
                    ["port"] = new Dictionary<string, object> { ["type"] = "integer", ["description"] = "Remote port (default 0/any)" },
                    ["app"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Optional process name to match against the rule's app matcher" },
                },
                ["required"] = new[] { "ip" },
            },
        },
        new
        {
            name = "list_rules",
            description = "List all firewall rules (id, action, app matcher, destination, port, lifetime, priority). Read-only.",
            inputSchema = new Dictionary<string, object> { ["type"] = "object", ["properties"] = new Dictionary<string, object>(), ["additionalProperties"] = false },
        },
        new
        {
            name = "propose_rule",
            description = "Request a rule change. The user is shown an approval dialog in the OutboundWin app; the rule is applied ONLY if they click Approve (auto-denied after 60 s). Returns the result of that decision.",
            inputSchema = new Dictionary<string, object>
            {
                ["type"] = "object",
                ["properties"] = new Dictionary<string, object>
                {
                    ["action"] = new Dictionary<string, object> { ["type"] = "string", ["enum"] = new[] { "deny", "allow" } },
                    ["destination"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Domain, IP, CIDR or 'any'" },
                    ["app"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Optional process name or exe path" },
                    ["port"] = new Dictionary<string, object> { ["type"] = "string", ["description"] = "Port spec: number, range like 53-80, or 'any' (default any)" },
                    ["lifetime"] = new Dictionary<string, object> { ["type"] = "string", ["enum"] = new[] { "forever", "1h", "quit", "once" } },
                },
                ["required"] = new[] { "action", "destination" },
            },
        },
    ];

    private static object ToolCall(JsonElement p)
    {
        string name = p.GetProperty("name").GetString() ?? "";
        var args = p.TryGetProperty("arguments", out var a) ? a : default;

        switch (name)
        {
            case "list_flows":
                return TextResult(FlowsJson());

            case "explain_flow":
            {
                string ip = args.GetProperty("ip").GetString()!;
                int port = args.TryGetProperty("port", out var pp) ? pp.GetInt32() : 0;
                string? app = args.TryGetProperty("app", out var ap) ? ap.GetString() : null;
                string? host = args.TryGetProperty("host", out var hp) ? hp.GetString() : null;

                try { return TextResult(PipeJson("explain", new Dictionary<string, object?> { ["ip"] = ip, ["port"] = port, ["app"] = app, ["host"] = host })); }
                catch (Exception ex) { return TextResult(LocalExplain(ip, port, app, host, ex.Message)); } // app not running → local rule set
            }

            case "list_rules":
                try { return TextResult(PipeJson("rules.list", null)); }
                catch (Exception ex) { return TextResult(LocalRules(ex.Message)); }

            case "propose_rule":
            {
                string action = args.GetProperty("action").GetString()!.ToLowerInvariant();
                string dest = args.GetProperty("destination").GetString()!;
                string? app = args.TryGetProperty("app", out var a2) ? a2.GetString() : null;
                string port = args.TryGetProperty("port", out var p2) && !string.IsNullOrEmpty(p2.GetString()) ? p2.GetString()! : "any";
                string life = args.TryGetProperty("lifetime", out var l) ? l.GetString()! : "forever";

                var req = new Dictionary<string, object?> { ["action"] = action, ["dest"] = dest };
                if (!string.IsNullOrEmpty(app)) req["app"] = app;
                if (port != "any") req["port"] = port;
                if (life != "forever") req["lifetime"] = life;

                try
                {
                    var r = Pipe("rules.propose", req); // blocks until the user approves/denies in the app dialog
                    string text = r.TryGetProperty("approved", out var approved) && !approved.GetBoolean()
                        ? "DENIED — the user declined this rule change (or did not answer within 60 s). Nothing was changed."
                        : $"APPROVED by the user. Rule #{r.GetProperty("id")} added: {r.GetProperty("description")}";
                    return TextResult(text);
                }
                catch (Exception ex)
                {
                    // App not running — fall back to the old proposal-only behaviour so the agent still gets something actionable.
                    var cmd = new System.Text.StringBuilder($"outboundctl rules add --{action} --dest \"{dest}\"");
                    if (!string.IsNullOrEmpty(app)) cmd.Append($" --app \"{app}\"");
                    if (port != "any") cmd.Append($" --port {port}");
                    if (life != "forever") cmd.Append($" --lifetime {life}");
                    return TextResult(
                        $"PROPOSAL ONLY — the OutboundWin app is not running ({ex.Message}), so no approval dialog was shown. For the user to review and run:\n\n  {cmd}\n\n" +
                        "The user must confirm this in their terminal or GUI before it takes effect.");
                }
            }

            default:
                throw new Exception($"unknown tool: {name}");
        }
    }

    // ---------- pipe client (same protocol as outboundctl) ----------

    private static JsonElement Pipe(string cmd, Dictionary<string, object?>? args = null)
    {
        var payload = new Dictionary<string, object?> { ["id"] = 1, ["cmd"] = cmd };
        if (args != null) foreach (var kv in args) payload[kv.Key] = kv.Value;
        string reqLine = JsonSerializer.Serialize(payload);

        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.CurrentUserOnly);
        try { pipe.Connect(2000); }
        catch (TimeoutException) { throw new Exception("app not running"); }

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
            catch (IOException) { throw new Exception("app closed the pipe"); }
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

    private static string PipeJson(string cmd, Dictionary<string, object?>? args) =>
        JsonSerializer.Serialize(Pipe(cmd, args), new JsonSerializerOptions { WriteIndented = true });

    // ---------- local fallbacks (app not running) ----------

    private static string LocalExplain(string ip, int port, string? app, string? host, string whyAppDown)
    {
        using var store = new RuleStore(DbPath());
        string exePath = "";
        if (!string.IsNullOrEmpty(app))
            foreach (var pr in System.Diagnostics.Process.GetProcesses())
                using (pr)
                    if (pr.ProcessName.Equals(app, StringComparison.OrdinalIgnoreCase))
                        try { exePath = pr.MainModule.FileName; } catch { }

        var ctx = new FlowContext(0, app ?? "", exePath, ip, (ushort)port);
        var (matched, reason) = RuleMatcher.Decide(store.All(), ctx, DateTime.UtcNow);
        return JsonSerializer.Serialize(new
        {
            note = "app not running (" + whyAppDown + ") — evaluated against the local rule set",
            decision = matched == null ? "allow" : matched.Action.ToString().ToLowerInvariant(),
            decidedBy = matched?.Id.ToString() ?? "(default)",
            reason,
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string LocalRules(string whyAppDown)
    {
        using var store = new RuleStore(DbPath());
        var rules = store.All().Select(r => new
        {
            id = r.Id, action = r.Action.ToString(), app = r.AppMatcher ?? "(any)",
            destination = r.Destination, port = r.PortSpec, lifetime = r.Lifetime.ToString(),
            priority = r.Priority, source = r.Source,
        });
        return JsonSerializer.Serialize(new { note = "app not running (" + whyAppDown + ") — local rule set", rules }, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string FlowsJson()
    {
        var rows = NetworkTable.Snapshot();
        return JsonSerializer.Serialize(rows.Select(r => new
        {
            pid = r.Pid,
            process = SafeName(r.Pid),
            local = $"{r.LocalIp}:{r.LocalPort}",
            remote = $"{r.RemoteIp}:{r.RemotePort}",
            proto = r.Proto.ToString().ToLowerInvariant(),
            state = r.State.ToString(),
        }), new JsonSerializerOptions { WriteIndented = true });
    }

    private static object TextResult(string text) =>
        new { content = new[] { new { type = "text", text } }, isError = false };

    private static string DbPath() =>
        Environment.GetEnvironmentVariable("OUTBOUND_DB") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "rules.db");

    private static string SafeName(int pid)
    {
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); return p.ProcessName; }
        catch { return $"<pid {pid}>"; }
    }
}
