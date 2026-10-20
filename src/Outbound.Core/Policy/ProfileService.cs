using System.Text.Json;
using Outbound.Core.Network;

namespace Outbound.Core.Policy;

/// <summary>One profile = a named mode (Learn/Ask/Strict) applied when on a matching network.</summary>
public sealed class Profile
{
    public string Name { get; set; } = "";
    public Mode Mode { get; set; } = Mode.Learn;
}

/// <summary>
/// Per-network profiles: each profile is a named mode. The active profile's mode drives the engine,
/// and rules tagged with that profile apply only on its networks (null-profile rules always apply).
/// State persists in %LOCALAPPDATA%\OutboundWin\profiles.json.
/// </summary>
public sealed class ProfileService : IDisposable
{
    public List<Profile> Profiles { get; } = new();
    /// <summary>Network name → profile name (auto-switch mapping).</summary>
    public Dictionary<string, string> NetworkMap { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string? ActiveProfile { get; private set; }
    public string CurrentNetwork { get; private set; } = "";
    /// <summary>Raised on the watcher thread when the active profile (or network) changed.</summary>
    public event Action<string?, string>? Changed;

    private readonly NetworkWatcher _watcher;
    private readonly object _gate = new();

    public ProfileService(string? path = null, bool startWatcher = true)
    {
        Path = path ?? System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin", "profiles.json");
        Load();
        if (startWatcher)
        {
            _watcher = new NetworkWatcher();
            _watcher.Changed += OnNetwork;
        }
    }

    public string Path { get; }

    private void OnNetwork(string name, bool connected)
    {
        CurrentNetwork = name;
        if (!connected || name == "") return; // offline — keep the last profile
        lock (_gate)
        {
            if (NetworkMap.TryGetValue(name, out var mapped))
                SetActive(mapped);
            else
                SetActive(null); // unknown network → no profile until the user maps one
        }
    }

    /// <summary>Set the active profile by name (null = none). Persists, and raises Changed only when it actually changed.</summary>
    public void SetActive(string? name)
    {
        string? next;
        lock (_gate)
        {
            next = Profiles.Any(p => p.Name == name) ? name : null;
            if (next == ActiveProfile)
            {
                // No-op writes must not raise Changed: listeners rebuild their UI on Changed,
                // and a rebuild that writes back here again would loop forever.
                Save();
                return;
            }
            ActiveProfile = next;
            Save();
        }
        Changed?.Invoke(ActiveProfile, CurrentNetwork);
    }

    /// <summary>Map a network to a profile (auto-switch on join). Persists + raises Changed.</summary>
    public void MapNetwork(string networkName, string profileName)
    {
        lock (_gate)
        {
            NetworkMap[networkName] = profileName;
            Save();
        }
        if (networkName == CurrentNetwork) SetActive(profileName);
    }

    /// <summary>Mode of the active profile, or null when no profile is active.</summary>
    public Mode? ActiveMode()
    {
        lock (_gate) return Profiles.FirstOrDefault(p => p.Name == ActiveProfile)?.Mode;
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(Path)) return;
            var doc = JsonDocument.Parse(File.ReadAllText(Path));
            var root = doc.RootElement;
            foreach (var el in root.GetProperty("profiles").EnumerateArray())
                Profiles.Add(new Profile
                {
                    Name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                    Mode = el.TryGetProperty("mode", out var m) && Enum.TryParse<Mode>(m.GetString(), true, out var mv) ? mv : Mode.Learn,
                });
            if (root.TryGetProperty("networkMap", out var map))
                foreach (var kv in map.EnumerateObject()) NetworkMap[kv.Name] = kv.Value.GetString() ?? "";
        }
        catch { /* corrupt file — start fresh */ }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            var obj = new Dictionary<string, object?>
            {
                ["profiles"] = Profiles.Select(p => new { name = p.Name, mode = ModeNames.Of(p.Mode) }).ToArray(),
                ["networkMap"] = NetworkMap,
            };
            File.WriteAllText(Path, JsonSerializer.Serialize(obj));
        }
        catch { /* persistence is best-effort */ }
    }

    public void Dispose() => _watcher?.Dispose();
}
