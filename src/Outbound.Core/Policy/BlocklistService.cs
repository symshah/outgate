using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Outbound.Core.Policy;

/// <summary>One blocklist subscription (hosts format or plain domain list).</summary>
public class BlocklistSub
{
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public bool Enabled { get; set; } = true;

    [JsonIgnore] public int EntryCount { get; internal set; }
    [JsonIgnore] public DateTime? LastOkUtc { get; internal set; }
    [JsonIgnore] public string? LastError { get; internal set; }
}

/// <summary>
/// Blocklist engine: subscribes to hosts/domain lists over HTTPS, keeps them in a
/// memory-efficient domain trie (up to ~200k entries), and on a failed fetch KEEPS
/// the last good list. Matching is exact-or-subdomain: an entry "ads.example.com"
/// also blocks "x.ads.example.com".
/// </summary>
public sealed class BlocklistService : IDisposable
{
    private readonly object _gate = new();
    private readonly HttpClient _http;
    private readonly string _path;

    public List<BlocklistSub> Subs { get; } = [];

    /// <summary>Raised after a refresh round (success or failure) so the UI can re-render.</summary>
    public event Action? Changed;

    // ---- trie -------------------------------------------------------------
    private sealed class Node
    {
        public readonly Dictionary<string, Node> Children = new(StringComparer.OrdinalIgnoreCase);
        public bool Terminal;
        public readonly List<string> Subs = []; // names of lists that contain this exact domain
    }
    private Node _root = new();
    private int _count;

    public BlocklistService(string? path = null)
    {
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "blocklists.json");
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        Load();
    }

    public int TotalEntries { get { lock (_gate) return _count; } }

    /// <summary>Name of the loaded blocklist containing host (exact or subdomain), null when not blocked.</summary>
    public string? WhichList(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        var h = host.Trim().ToLowerInvariant();
        lock (_gate)
        {
            // Walk the trie label by label from the leftmost label: "a.b.c" matches entries on a.b.c, b.c or c.
            var labels = h.Split('.');
            for (int start = 0; start < labels.Length; start++)
            {
                Node n = _root;
                bool ok = true;
                for (int i = start; i < labels.Length; i++)
                {
                    if (!n.Children.TryGetValue(labels[i], out var c)) { ok = false; break; }
                    n = c;
                }
                if (ok && n.Terminal) return n.Subs.Count > 0 ? n.Subs[0] : null;
            }
            return null;
        }
    }

    // ---- parsing ----------------------------------------------------------
    /// <summary>Parse hosts-format or plain domain-list text and merge it into the live trie, tagged with subName. Returns entry count.</summary>
    public int ParseText(string text, string subName)
    {
        var root = new Node();
        int n = ParseInto(root, text, subName);
        lock (_gate) Merge(_root, root);
        return n;
    }

    private static int ParseInto(Node root, string text, string subName)
    {
        int added = 0;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            // hosts format: "127.0.0.1 ads.example.com" → take the first token that looks like a domain.
            string? domain = null;
            foreach (var tok in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (tok.Contains('.') && !tok.Any(char.IsDigit) && !tok.StartsWith("::")) { domain = tok; break; }
            }
            if (domain == null || domain.Length < 4) continue;
            var labels = domain.TrimStart('.').ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
            Node n = root;
            foreach (var lab in labels)
            {
                if (!n.Children.TryGetValue(lab, out var c)) { c = new Node(); n.Children[lab] = c; }
                n = c;
            }
            if (!n.Terminal) { n.Terminal = true; added++; }
            if (!n.Subs.Contains(subName)) n.Subs.Add(subName);
        }
        return added;
    }

    // ---- mutations (persist + refresh) ------------------------------------
    /// <summary>Add a subscription; persists immediately and starts fetching it.</summary>
    public void AddSub(string name, string url)
    {
        if (Subs.Any(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) throw new Exception($"blocklist '{name}' already exists");
        Subs.Add(new BlocklistSub { Name = name, Url = url });
        Save();
        Changed?.Invoke(); // UI re-renders immediately; entry counts fill in when the fetch lands
        Task.Run(async () => await RefreshAsync());
    }

    /// <summary>Remove a subscription; persists immediately and re-fetches the rest.</summary>
    public void RemoveSub(string name)
    {
        var sub = Subs.FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (sub == null) throw new Exception($"blocklist '{name}' not found");
        Subs.Remove(sub);
        Save();
        Changed?.Invoke();
        Task.Run(async () => await RefreshAsync());
    }

    /// <summary>Enable/disable a subscription; persists immediately and re-fetches.</summary>
    public void SetEnabled(string name, bool enabled)
    {
        var sub = Subs.FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (sub == null) throw new Exception($"blocklist '{name}' not found");
        sub.Enabled = enabled;
        Save();
        Changed?.Invoke();
        Task.Run(async () => await RefreshAsync());
    }

    // ---- refresh ----------------------------------------------------------
    /// <summary>Fetch all enabled subscriptions over HTTPS. A failed fetch KEEPS the last good list (cached on disk per sub).</summary>
    public async Task RefreshAsync()
    {
        var dir = Path.Combine(Path.GetDirectoryName(_path)!, "lists");
        Directory.CreateDirectory(dir);
        var root = new Node();
        int total = 0;
        foreach (var sub in Subs.Where(s => s.Enabled))
        {
            string file = Path.Combine(dir, Sanitize(sub.Name) + ".txt");
            try
            {
                using var resp = await _http.GetAsync(sub.Url, HttpCompletionOption.ResponseHeadersRead);
                if (!resp.IsSuccessStatusCode) throw new Exception($"HTTP {(int)resp.StatusCode}");
                string text;
                using (var sr = new StreamReader(await resp.Content.ReadAsStreamAsync()))
                    text = await sr.ReadToEndAsync();
                File.WriteAllText(file, text); // last good list now on disk
                sub.LastOkUtc = DateTime.UtcNow;
                sub.LastError = null;
            }
            catch (Exception ex)
            {
                sub.LastError = ex.Message; // keep cached file → last good list stays active
            }

            if (File.Exists(file))
            {
                try
                {
                    var tmp = new Node();
                    sub.EntryCount = ParseInto(tmp, File.ReadAllText(file), sub.Name);
                    Merge(root, tmp);
                    total += sub.EntryCount;
                }
                catch { /* unreadable cache → skip this sub */ }
            }
        }

        lock (_gate)
        {
            _root = root;
            _count = total;
        }
        Save();
        Changed?.Invoke();
    }

    /// <summary>Merge every terminal entry of src into dst (dedup by terminal flag).</summary>
    private static void Merge(Node dst, Node src)
    {
        foreach (var kv in src.Children)
        {
            if (!dst.Children.TryGetValue(kv.Key, out var d)) { d = new Node(); dst.Children[kv.Key] = d; }
            if (kv.Value.Terminal && !d.Terminal) d.Terminal = true;
            foreach (var s in kv.Value.Subs) if (!d.Subs.Contains(s)) d.Subs.Add(s);
            Merge(d, kv.Value);
        }
    }

    private static string Sanitize(string name) =>
        new string(name.Select(c => char.IsLetterOrDigit(c) || c == '-' ? c : '_').ToArray());

    /// <summary>Load persisted subscriptions and immediately fetch (best effort).</summary>
    public async Task LoadAndFetchAsync()
    {
        await RefreshAsync();
    }

    // ---- persistence ------------------------------------------------------
    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var doc = JsonDocument.Parse(File.ReadAllText(_path));
            foreach (var el in doc.RootElement.GetProperty("subs").EnumerateArray())
            {
                string name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                if (string.IsNullOrWhiteSpace(name)) continue; // defensive: skip corrupt entries
                Subs.Add(new BlocklistSub
                {
                    Name = name,
                    Url = el.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                    Enabled = !el.TryGetProperty("enabled", out var e) || e.GetBoolean(),
                });
            }
        }
        catch { /* corrupt file → start empty */ }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(new { subs = Subs.Select(s => new { s.Name, s.Url, s.Enabled }) }, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        }
        catch { /* persistence is best-effort */ }
    }

    public void Dispose() => _http.Dispose();
}
