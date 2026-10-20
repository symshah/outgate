using System;
using System.IO;

namespace Outbound.Core.Engine;

/// <summary>
/// Append-only engine log at %LocalAppData%\OutboundWin\engine.log — records why live monitoring
/// started or failed (ETW session results, exact exceptions), so "all byte counts are 0" is
/// diagnosable without a debugger.
/// </summary>
public static class EngineLog
{
    public static string FilePath
    {
        get
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OutboundWin");
            return Path.Combine(dir, "engine.log");
        }
    }

    /// <summary>Last reason monitoring failed to start live (null when live monitoring is running).</summary>
    public static string? LastMonitoringError { get; private set; }

    public static void Write(string message)
    {
        try
        {
            var fi = new FileInfo(FilePath);
            Directory.CreateDirectory(fi.DirectoryName!);
            if (fi.Exists && fi.Length > 2 * 1024 * 1024) fi.Delete(); // keep it small
            File.AppendAllText(FilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] pid={Environment.ProcessId} {message}{Environment.NewLine}");
        }
        catch { /* logging must never break the app */ }
    }

    public static void Monitoring(string message) { LastMonitoringError = null; Write(message); }

    public static void MonitoringFailed(string message, Exception? ex = null)
    {
        LastMonitoringError = message;
        Write(ex == null ? "MONITORING OFF: " + message : "MONITORING OFF: " + message + Environment.NewLine + ex);
    }
}
