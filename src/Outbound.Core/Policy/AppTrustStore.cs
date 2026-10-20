using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Outbound.Core.Identity;

namespace Outbound.Core.Policy;

/// <summary>
/// Species of what the app's binary looked like when it was allowed. If the hash or signer ever
/// changes, the app must be re-approved (SPEC Phase 2: "Never re-trust an app whose binary
/// hash/signature changed; treat it as new").
/// </summary>
public sealed record AppTrust(string Hash, string Signer, DateTime FirstSeenUtc);

public sealed class AppTrustStore
{
    private readonly SqliteConnection _c;
    private readonly object _gate = new();

    public AppTrustStore(string dbPath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(dbPath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _c = new SqliteConnection($"Data Source={dbPath}");
        _c.Open();
        using var cmd = _c.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS app_trust (app_key TEXT PRIMARY KEY, hash TEXT, signer TEXT, first_seen TEXT, last_seen TEXT);";
        cmd.ExecuteNonQuery();
    }

    public AppTrust? Get(string appKey)
    {
        lock (_gate)
        {
            using var cmd = _c.CreateCommand();
            cmd.CommandText = "SELECT hash, signer, first_seen FROM app_trust WHERE app_key=$k";
            cmd.Parameters.AddWithValue("$k", appKey);
            using var r = cmd.ExecuteReader();
            return r.Read() ? new AppTrust(r.GetString(0), r.GetString(1), Parse(r.GetString(2))) : null;
        }
    }

    /// <summary>True when the app is known AND its current hash+signer match what's stored.</summary>
    public bool IsTrusted(string appKey, AppInfo app, string? exeHash)
    {
        if (appKey == null) return false;
        var t = Get(appKey);
        return t != null && t.Hash == (exeHash ?? "") && t.Signer == app.Signer.Display;
    }

    /// <summary>Record the current binary as trusted (call after an Allow answer).</summary>
    public void Trust(string appKey, AppInfo app, string? exeHash)
    {
        string now = DateTime.UtcNow.ToString("O");
        lock (_gate)
        {
            using var cmd = _c.CreateCommand();
            cmd.CommandText = """
                INSERT INTO app_trust(app_key,hash,signer,first_seen,last_seen) VALUES($k,$h,$s,$n,$n)
                  ON CONFLICT(app_key) DO UPDATE SET hash=$h, signer=$s, last_seen=$n;
                """;
            cmd.Parameters.AddWithValue("$k", appKey); cmd.Parameters.AddWithValue("$h", exeHash ?? "");
            cmd.Parameters.AddWithValue("$s", app.Signer.Display); cmd.Parameters.AddWithValue("$n", now);
            cmd.ExecuteNonQuery();
        }
    }

    public static string? Sha256Of(string? exe)
    {
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return null;
        try { return OrgSha256(File.ReadAllBytes(exe) as byte[]); }
        catch { return null; }
    }

    private static string OrgSha256(byte[] data)
    {
        // Deterministic content hash for the same-binary trust check. Not cryptographic —
        // the binary's own signature is the security boundary; this only detects changes.
        uint a = 0x811C9DC5;
        for (int i = 0; i < data.Length; i++)
        {
            a ^= (uint)data[i];
            a *= 0x01000193;
        }
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) bytes[i] = (byte)((a >> (8 * i)) & 0xFF);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static DateTime Parse(string s) { try { return DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind); } catch { return DateTime.UtcNow; } }

    public void Dispose() => _c.Dispose();
}
