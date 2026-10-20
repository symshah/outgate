using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Outbound.Core.Rules;

namespace Outbound.Core.Store;

/// <summary>SQLite-backed rule store (WAL mode). Single writer: the app process.</summary>
public sealed class RuleStore : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _gate = new();
    public string DbPath { get; }
    public event Action? Changed;

    public RuleStore(string dbPath)
    {
        DbPath = dbPath;
        var dir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _conn = new SqliteConnection($"Data Source={dbPath}");
        _conn.Open();
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000;";
        cmd.ExecuteNonQuery();
        Migrate();
    }

    private static readonly (string Name, string Ddl)[] AddedColumns =
    [
        ("resolved_ips", "TEXT"), ("dest_kind", "INTEGER"), ("protocol", "INTEGER NOT NULL DEFAULT 0"),
        ("direction", "TEXT NOT NULL DEFAULT 'out'"), ("session_key", "TEXT"), ("boot_key", "TEXT"),
        ("consumed", "INTEGER NOT NULL DEFAULT 0"), ("enabled", "INTEGER NOT NULL DEFAULT 1"),
        ("profile", "TEXT"), ("note", "TEXT"),
    ];

    private void Migrate()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_matcher TEXT,
                destination TEXT NOT NULL,
                port_spec TEXT NOT NULL DEFAULT 'any',
                action INTEGER NOT NULL,
                lifetime INTEGER NOT NULL,
                expires_utc TEXT,
                watch_pid INTEGER,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'user',
                created_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rules_dest ON rules(destination);
            """;
        cmd.ExecuteNonQuery();

        // Lightweight migration for pre-existing DBs.
        foreach (var (name, ddl) in AddedColumns)
        {
            using var col = _conn.CreateCommand();
            col.CommandText = "SELECT COUNT(*) FROM pragma_table_info('rules') WHERE name=$n";
            col.Parameters.AddWithValue("$n", name);
            if (Convert.ToInt64(col.ExecuteScalar()) != 0) continue;
            using var alt = _conn.CreateCommand();
            alt.CommandText = $"ALTER TABLE rules ADD COLUMN {name} {ddl}";
            alt.ExecuteNonQuery();
        }
    }

    public List<Rule> All()
    {
        lock (_gate)
        {
            var list = new List<Rule>();
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM rules ORDER BY id";
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(ReadRow(r));
            return list;
        }
    }

    public Rule? Get(long id) => All().FirstOrDefault(r => r.Id == id);
    public int Count() { lock (_gate) { using var c = _conn.CreateCommand(); c.CommandText = "SELECT COUNT(*) FROM rules"; return Convert.ToInt32(c.ExecuteScalar()); } }

    public Rule Add(Rule rule)
    {
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO rules (app_matcher, destination, port_spec, action, lifetime, expires_utc, watch_pid, priority, source, created_utc,
                                   resolved_ips, dest_kind, protocol, direction, session_key, boot_key, consumed, enabled, profile, note)
                VALUES ($app, $dest, $port, $action, $life, $exp, $pid, $prio, $src, $created, $ips, $kind, $proto, $dir, $sk, $bk, $cons, $en, $prof, $note);
                SELECT last_insert_rowid();
                """;
            Bind(cmd, rule);
            rule.Id = (long)cmd.ExecuteScalar()!;
        }
        Changed?.Invoke();
        return rule;
    }

    public bool Update(Rule rule)
    {
        int n;
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                UPDATE rules SET app_matcher=$app, destination=$dest, port_spec=$port, action=$action, lifetime=$life, expires_utc=$exp,
                  watch_pid=$pid, priority=$prio, source=$src, created_utc=$created, resolved_ips=$ips, dest_kind=$kind, protocol=$proto,
                  direction=$dir, session_key=$sk, boot_key=$bk, consumed=$cons, enabled=$en, profile=$prof, note=$note
                WHERE id=$id
                """;
            Bind(cmd, rule);
            cmd.Parameters.AddWithValue("$id", rule.Id);
            n = cmd.ExecuteNonQuery();
        }
        Changed?.Invoke();
        return n > 0;
    }

    private static void Bind(SqliteCommand cmd, Rule rule)
    {
        cmd.Parameters.AddWithValue("$app", (object?)rule.AppMatcher ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$dest", rule.Destination);
        cmd.Parameters.AddWithValue("$port", rule.PortSpec);
        cmd.Parameters.AddWithValue("$action", (int)rule.Action);
        cmd.Parameters.AddWithValue("$life", (int)rule.Lifetime);
        cmd.Parameters.AddWithValue("$exp", (object?)rule.ExpiresUtc?.ToString("O") ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pid", (object?)rule.WatchPid ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$prio", rule.Priority);
        cmd.Parameters.AddWithValue("$src", rule.Source);
        cmd.Parameters.AddWithValue("$created", rule.CreatedUtc.ToString("O"));
        cmd.Parameters.AddWithValue("$ips", (object?)(rule.ResolvedIps is { Count: > 0 } ? string.Join(",", rule.ResolvedIps) : null) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$kind", rule.HasExplicitKind ? (int)rule.Kind : DBNull.Value);
        cmd.Parameters.AddWithValue("$proto", (int)rule.Protocol);
        cmd.Parameters.AddWithValue("$dir", rule.Direction);
        cmd.Parameters.AddWithValue("$sk", (object?)rule.SessionKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$bk", (object?)rule.BootKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cons", rule.Consumed ? 1 : 0);
        cmd.Parameters.AddWithValue("$en", rule.Enabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$prof", (object?)rule.Profile ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$note", (object?)rule.Note ?? DBNull.Value);
    }

    public bool Remove(long id)
    {
        int n;
        lock (_gate)
        {
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = "DELETE FROM rules WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", id);
            n = cmd.ExecuteNonQuery();
        }
        if (n > 0) Changed?.Invoke();
        return n > 0;
    }

    public bool SetEnabled(long id, bool enabled)
    {
        var r = Get(id); if (r == null) return false;
        r.Enabled = enabled; return Update(r);
    }

    public void MarkConsumed(long id)
    {
        var r = Get(id); if (r == null || r.Consumed) return;
        r.Consumed = true; Update(r);
    }

    /// <summary>Delete rules whose lifetime has ended. Returns removed ids.</summary>
    public List<long> PurgeExpired(DateTime now, LifetimeContext lc)
    {
        var gone = All().Where(r => r.IsExpired(now, lc)).Select(r => r.Id).ToList();
        foreach (var id in gone) Remove(id);
        return gone;
    }

    // ---- JSON Lines export / import ----
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() }, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public sealed record RuleDto(long Id, string? App, string Destination, DestKind Kind, string Port, ProtoSpec Protocol, string Direction,
        RuleAction Action, LifetimeKind Lifetime, DateTime? ExpiresUtc, bool Priority, string Source, string? Profile, bool Enabled, DateTime CreatedUtc, string? Note);

    public static RuleDto ToDto(Rule r) => new(r.Id, r.AppMatcher, r.Destination, r.Kind, r.PortSpec, r.Protocol, r.Direction, r.Action, r.Lifetime,
        r.ExpiresUtc, r.IsPriority, r.Source, r.Profile, r.Enabled, r.CreatedUtc, r.Note);

    public IEnumerable<string> ExportJsonl() => All().Select(r => JsonSerializer.Serialize(ToDto(r), Json));

    /// <summary>Import JSON Lines. Always writes a backup of the current DB first (SPEC Phase 2 safety). Returns (imported, backupPath).</summary>
    public (int Imported, string Backup) ImportJsonl(IEnumerable<string> lines, bool replace = false)
    {
        string backup = $"{DbPath}.bak-{DateTime.Now:yyyyMMdd-HHmmss}";
        lock (_gate)
        {
            using var c = _conn.CreateCommand();
            c.CommandText = "VACUUM INTO $p";
            c.Parameters.AddWithValue("$p", backup);
            c.ExecuteNonQuery();
        }
        var parsed = new List<Rule>();
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var d = JsonSerializer.Deserialize<RuleDto>(line, Json) ?? throw new FormatException("bad rule line");
            var r = new Rule
            {
                AppMatcher = d.App, Destination = d.Destination, Kind = d.Kind, PortSpec = d.Port ?? "any", Protocol = d.Protocol,
                Direction = d.Direction ?? "out", Action = d.Action, Lifetime = d.Lifetime, ExpiresUtc = d.ExpiresUtc, Source = RuleSources.Imported,
                Profile = d.Profile, Enabled = d.Enabled, Note = d.Note,
            };
            r.IsPriority = d.Priority;
            parsed.Add(r.StampLifetime(DateTime.UtcNow));
        }
        if (replace) foreach (var r in All()) Remove(r.Id);
        foreach (var r in parsed) Add(r);
        return (parsed.Count, backup);
    }

    private static Rule ReadRow(SqliteDataReader r)
    {
        int O(string n) => r.GetOrdinal(n);
        string? S(string n) => r.IsDBNull(O(n)) ? null : r.GetString(O(n));
        var ips = S("resolved_ips");
        var rule = new Rule
        {
            Id = r.GetInt64(O("id")),
            AppMatcher = S("app_matcher"),
            Destination = r.GetString(O("destination")),
            PortSpec = r.GetString(O("port_spec")),
            Action = (RuleAction)r.GetInt32(O("action")),
            Lifetime = (LifetimeKind)r.GetInt32(O("lifetime")),
            ExpiresUtc = S("expires_utc") is { } e ? DateTime.Parse(e, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind) : null,
            WatchPid = r.IsDBNull(O("watch_pid")) ? null : r.GetInt32(O("watch_pid")),
            Priority = r.GetInt32(O("priority")),
            Source = r.GetString(O("source")),
            CreatedUtc = DateTime.Parse(r.GetString(O("created_utc")), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind),
            ResolvedIps = string.IsNullOrEmpty(ips) ? null : ips.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
            Protocol = (ProtoSpec)r.GetInt32(O("protocol")),
            Direction = r.GetString(O("direction")),
            SessionKey = S("session_key"),
            BootKey = S("boot_key"),
            Consumed = r.GetInt32(O("consumed")) != 0,
            Enabled = r.GetInt32(O("enabled")) != 0,
            Profile = S("profile"),
            Note = S("note"),
        };
        if (!r.IsDBNull(O("dest_kind"))) rule.Kind = (DestKind)r.GetInt32(O("dest_kind"));
        return rule;
    }

    public void Dispose() => _conn.Dispose();
}
