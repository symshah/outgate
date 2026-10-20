using System.Runtime.InteropServices;

namespace Outbound.Core.Rules;

/// <summary>
/// Keys for session-bound lifetimes. Until Restart = boot key (kernel BootId, else boot time);
/// Until Logout = WTS session id + that session's logon time (same for elevated and normal tokens).
/// </summary>
public static class SystemKeys
{
    public static string BootKey()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (k?.GetValue("BootId") is int id) return $"bootid:{id}";
        }
        catch { }
        var boot = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        return $"boot:{boot:yyyyMMddHHmm}";
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr p);
    private const int WTSSessionInfo = 24;
    // WTSINFOW: 8 DWORDs (32) + WinStationName[32] (64) + Domain[17] (34) + UserName[21] (42) = 172 → 8-aligned 176:
    // ConnectTime@176, DisconnectTime@184, LastInputTime@192, LogonTime@200.
    private const int LogonTimeOffset = 200;

    public static string SessionKey()
    {
        int sid = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        try
        {
            if (WTSQuerySessionInformationW(IntPtr.Zero, sid, WTSSessionInfo, out var buf, out int bytes) && bytes >= LogonTimeOffset + 8)
            {
                long logon = Marshal.ReadInt64(buf, LogonTimeOffset);
                WTSFreeMemory(buf);
                return $"session:{sid}:{logon}";
            }
        }
        catch { }
        return $"session:{sid}:{BootKey()}";
    }

    public static LifetimeContext Current() => new(PidAlive, SessionKey(), BootKey());

    public static bool PidAlive(int pid)
    {
        try { using var p = System.Diagnostics.Process.GetProcessById(pid); return !p.HasExited; } catch { return false; }
    }
}
