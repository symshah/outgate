using Microsoft.Data.Sqlite;

namespace Outbound.Core.Policy;

public enum ReviewAction { Pending, Allowed, Blocked, Dismissed, Learned }
public static class ReviewActionNames { public static string Of(ReviewAction a) => a switch { ReviewAction.Allowed => "allowed", ReviewAction.Blocked => "blocked", ReviewAction.Dismissed => "dismissed", ReviewAction.Learned => "learned", _ => "pending" }; }

public sealed record ReviewItem(long Id, string AppKey, string AppName, string? Host, string RemoteIp, ushort Port, string Proto, string Reason, ReviewAction Action, DateTime SeenUtc, DateTime? ExpiresUtc);

public sealed class ReviewStore
{
    private readonly SqliteConnection _c;
    private readonly object _gate = new();

    public ReviewStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _c = new SqliteConnection($"Data Source={dbPath}");
        _c.Open();
        using var cmd = _c.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000;
            CREATE TABLE IF NOT EXISTS review (
              id INTEGER PRIMARY KEY AUTOINCREMENT, app_key TEXT, app_name TEXT, host TEXT, remote_ip TEXT,
              port INTEGER, proto TEXT, reason TEXT, action INTEGER NOT NULL DEFAULT 0, seen_utc TEXT, expires_utc TEXT);
            CREATE INDEX IF NOT EXISTS idx_rev_action ON review(action);
            """;
        cmd.ExecuteNonQuery();
    }

    private static string DtStr(DateTime t) => t.ToString("O");

    public long Add(string appKey, string appName, string? host, string remoteIp, ushort port, string proto, string reason, ReviewAction action, DateTime seenUtc, DateTime? expiresUtc = null)
    {
        lock (_gate)
        {
            using var cmd = _c.CreateCommand();
            cmd.CommandText = """
                INSERT INTO review(app_key,app_name,host,remote_ip,port,proto,reason,action,seen_utc,expires_utc)
                VALUES($k,$n,$h,$ip,$p,$pr,$r,$a,$s,$e);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$k", appKey); cmd.Parameters.AddWithValue("$n", appName);
            cmd.Parameters.AddWithValue("$h", (object?)host ?? DBNull.Value); cmd.Parameters.AddWithValue("$ip", remoteIp);
            cmd.Parameters.AddWithValue("$p", (int)port); cmd.Parameters.AddWithValue("$pr", proto);
            cmd.Parameters.AddWithValue("$r", reason); cmd.Parameters.AddWithValue("$a", (int)action);
            cmd.Parameters.AddWithValue("$s", DtStr(seenUtc));
            cmd.Parameters.AddWithValue("$e", expiresUtc == null ? DBNull.Value : (object)DtStr(expiresUtc.Value));
            return Convert.ToInt64(cmd.ExecuteScalar());
        }
    }

    public List<ReviewItem> Items(int limit = 500)
    {
        lock (_gate)
        {
            using var cmd = _c.CreateCommand();
            cmd.CommandText = "SELECT id,app_key,app_name,host,remote_ip,port,proto,reason,action,seen_utc,expires_utc FROM review ORDER BY id DESC LIMIT $l";
            cmd.Parameters.AddWithValue("$l", limit);
            using var r = cmd.ExecuteReader();
            var rows = new List<ReviewItem>();
            while (r.Read()) rows.Add(new ReviewItem(
                r.GetInt64(0), r.GetString(1), r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3), r.GetString(4),
                (ushort)r.GetInt32(5), r.GetString(6), r.GetString(7), (ReviewAction)r.GetInt32(8), Dt(r.GetString(9)), r.IsDBNull(10) ? null : Dt(r.GetString(10))));
            return rows;
        }
    }

    public List<ReviewItem> Pending() => Items().Where(i => i.Action == ReviewAction.Pending).ToList();

    public bool SetAction(long id, ReviewAction a)
    {
        lock (_gate)
        {
            using var cmd = _c.CreateCommand();
            cmd.CommandText = "UPDATE review SET action=$a WHERE id=$id";
            cmd.Parameters.AddWithValue("$a", (int)a); cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() > 0;
        }
    }

    public void Prune(DateTime now)
    {
        lock (_gate)
            using (var cmd = _c.CreateCommand())
            {
                cmd.CommandText = "DELETE FROM review WHERE expires_utc IS NOT NULL AND expires_utc < $n";
                cmd.Parameters.AddWithValue("$n", DtStr(now));
                cmd.ExecuteNonQuery();
            }
    }

    private static DateTime Dt(string s)
    {
        try { return DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind); } catch { return DateTime.UtcNow; }
    }

    public void Dispose() => _c.Dispose();
}
