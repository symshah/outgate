using Microsoft.Data.Sqlite;
using Outbound.Core.Engine;

namespace Outbound.Core.Store;

/// <summary>Traffic history in the same SQLite file as rules: apps, destinations (bytes, allowed/blocked, first/last seen), 5 s samples, connection log.</summary>
public sealed class TrafficStore : IDisposable
{
    private readonly SqliteConnection _c;
    private readonly object _gate = new();

    public TrafficStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _c = new SqliteConnection($"Data Source={dbPath}");
        _c.Open();
        Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=3000;");
        Exec("""
            CREATE TABLE IF NOT EXISTS apps (app_key TEXT PRIMARY KEY, name TEXT, exe TEXT, signer TEXT, signer_kind INTEGER, pfn TEXT, services TEXT, first_seen TEXT, last_seen TEXT);
            CREATE TABLE IF NOT EXISTS destinations (
                app_key TEXT NOT NULL, remote_ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL,
                host TEXT, domain TEXT, bytes_sent INTEGER NOT NULL DEFAULT 0, bytes_recv INTEGER NOT NULL DEFAULT 0,
                allowed INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, country TEXT, city TEXT, lat REAL, lon REAL,
                PRIMARY KEY (app_key, remote_ip, port, proto));
            CREATE TABLE IF NOT EXISTS samples (ts INTEGER NOT NULL, app_key TEXT NOT NULL, bytes_sent INTEGER NOT NULL, bytes_recv INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
            CREATE TABLE IF NOT EXISTS connections (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, pid INTEGER, app_key TEXT, remote_ip TEXT, port INTEGER, proto TEXT, host TEXT, decision TEXT, rule_id INTEGER);
            CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts);
            """);
    }

    private void Exec(string sql) { using var c = _c.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }

    public void RecordNewFlow(FlowStats f)
    {
        lock (_gate)
        {
            using var c = _c.CreateCommand();
            c.CommandText = """
                INSERT INTO apps(app_key,name,exe,signer,signer_kind,pfn,services,first_seen,last_seen) VALUES($k,$n,$e,$s,$sk,$p,$sv,$t,$t)
                  ON CONFLICT(app_key) DO UPDATE SET last_seen=$t;
                INSERT INTO connections(ts,pid,app_key,remote_ip,port,proto,host,decision,rule_id) VALUES($t,$pid,$k,$ip,$port,$proto,$h,$d,$r);
                """;
            c.Parameters.AddWithValue("$k", f.App.Key); c.Parameters.AddWithValue("$n", f.App.DisplayName);
            c.Parameters.AddWithValue("$e", (object?)f.App.ExePath ?? DBNull.Value); c.Parameters.AddWithValue("$s", f.App.Signer.Display);
            c.Parameters.AddWithValue("$sk", (int)f.App.Signer.Kind); c.Parameters.AddWithValue("$p", (object?)f.App.PackageFamily ?? DBNull.Value);
            c.Parameters.AddWithValue("$sv", (object?)f.App.Services ?? DBNull.Value); c.Parameters.AddWithValue("$t", f.FirstSeenUtc.ToString("O"));
            c.Parameters.AddWithValue("$pid", f.Pid); c.Parameters.AddWithValue("$ip", f.RemoteIp); c.Parameters.AddWithValue("$port", (int)f.RemotePort);
            c.Parameters.AddWithValue("$proto", f.Proto.ToString()); c.Parameters.AddWithValue("$h", (object?)f.Host ?? DBNull.Value);
            c.Parameters.AddWithValue("$d", (object?)f.Decision ?? DBNull.Value); c.Parameters.AddWithValue("$r", (object?)f.DecidingRuleId ?? DBNull.Value);
            c.ExecuteNonQuery();
        }
    }

    /// <summary>Flush byte deltas since the last flush and write one 5 s sample per app.</summary>
    public void Flush(IEnumerable<FlowStats> flows, DateTime nowUtc)
    {
        lock (_gate)
        {
            using var tx = _c.BeginTransaction();
            var perApp = new Dictionary<string, (long S, long R)>();
            foreach (var f in flows)
            {
                long s = Interlocked.Read(ref f.BytesSent), r = Interlocked.Read(ref f.BytesRecv);
                long ds = s - f.StoredSent, dr = r - f.StoredRecv;
                bool isNew = f.StoredSent == 0 && f.StoredRecv == 0 && f.LastSeenUtc >= nowUtc.AddSeconds(-10);
                if (ds == 0 && dr == 0 && !isNew) continue;
                using var c = _c.CreateCommand();
                c.Transaction = tx;
                c.CommandText = """
                    INSERT INTO destinations(app_key,remote_ip,port,proto,host,domain,bytes_sent,bytes_recv,allowed,blocked,first_seen,last_seen,country,city,lat,lon)
                    VALUES($k,$ip,$port,$proto,$h,$dom,$ds,$dr,$al,$bl,$fs,$ls,$cc,$city,$lat,$lon)
                    ON CONFLICT(app_key,remote_ip,port,proto) DO UPDATE SET
                      bytes_sent=bytes_sent+$ds, bytes_recv=bytes_recv+$dr, last_seen=$ls,
                      host=COALESCE($h,host), domain=COALESCE($dom,domain), allowed=allowed+$al, blocked=blocked+$bl;
                    """;
                bool first = f.StoredSent == 0 && f.StoredRecv == 0;
                c.Parameters.AddWithValue("$k", f.App.Key); c.Parameters.AddWithValue("$ip", f.RemoteIp); c.Parameters.AddWithValue("$port", (int)f.RemotePort);
                c.Parameters.AddWithValue("$proto", f.Proto.ToString()); c.Parameters.AddWithValue("$h", (object?)f.Host ?? DBNull.Value);
                c.Parameters.AddWithValue("$dom", (object?)f.Domain ?? DBNull.Value); c.Parameters.AddWithValue("$ds", ds); c.Parameters.AddWithValue("$dr", dr);
                c.Parameters.AddWithValue("$al", first && f.Decision != "deny" ? 1 : 0); c.Parameters.AddWithValue("$bl", first && f.Decision == "deny" ? 1 : 0);
                c.Parameters.AddWithValue("$fs", f.FirstSeenUtc.ToString("O")); c.Parameters.AddWithValue("$ls", f.LastSeenUtc.ToString("O"));
                c.Parameters.AddWithValue("$cc", (object?)f.Geo.CountryCode ?? DBNull.Value); c.Parameters.AddWithValue("$city", (object?)f.Geo.City ?? DBNull.Value);
                c.Parameters.AddWithValue("$lat", (object?)f.Geo.Lat ?? DBNull.Value); c.Parameters.AddWithValue("$lon", (object?)f.Geo.Lon ?? DBNull.Value);
                c.ExecuteNonQuery();
                f.StoredSent = s == 0 && r == 0 ? -1 : s; // -1 marks "row exists" for zero-byte flows
                f.StoredRecv = r;
                if (f.StoredSent == -1) { f.StoredSent = 0; f.StoredRecv = 0; }
                perApp[f.App.Key] = perApp.TryGetValue(f.App.Key, out var a) ? (a.S + ds, a.R + dr) : (ds, dr);
            }
            long ts = new DateTimeOffset(nowUtc).ToUnixTimeSeconds();
            foreach (var (k, v) in perApp)
            {
                if (v.S == 0 && v.R == 0) continue;
                using var c = _c.CreateCommand(); c.Transaction = tx;
                c.CommandText = "INSERT INTO samples(ts,app_key,bytes_sent,bytes_recv) VALUES($t,$k,$s,$r)";
                c.Parameters.AddWithValue("$t", ts); c.Parameters.AddWithValue("$k", k); c.Parameters.AddWithValue("$s", v.S); c.Parameters.AddWithValue("$r", v.R);
                c.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    public List<Dictionary<string, object?>> Query(string sql, params (string, object?)[] args)
    {
        lock (_gate)
        {
            using var c = _c.CreateCommand(); c.CommandText = sql;
            foreach (var (k, v) in args) c.Parameters.AddWithValue(k, v ?? DBNull.Value);
            using var r = c.ExecuteReader();
            var list = new List<Dictionary<string, object?>>();
            while (r.Read())
            {
                var d = new Dictionary<string, object?>();
                for (int i = 0; i < r.FieldCount; i++) d[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
                list.Add(d);
            }
            return list;
        }
    }

    public void Dispose() => _c.Dispose();
}
