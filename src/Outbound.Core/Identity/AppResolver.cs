using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Outbound.Core.Identity;

/// <summary>One logical app row: helper processes folded together.</summary>
public sealed record AppInfo(string Key, string DisplayName, string? ExePath, string? PackageFamily, string? Services, SignerInfo Signer)
{
    public static AppInfo System(int pid) => new(pid == 4 ? "system" : "system-idle", pid == 4 ? "System" : "System Idle", null, null, null, new SignerInfo(SignerKind.Microsoft, "Microsoft Windows", true));
}

/// <summary>
/// PID → app identity. Fold rules (SPEC Phase 1):
///  · UWP/MSIX → package family name;
///  · svchost.exe → split by hosted service name(s);
///  · otherwise walk the parent chain while the parent is the same exe or the same product (ProductName+CompanyName),
///    so chrome.exe renderers/GPU/utility processes all become "Google Chrome".
/// </summary>
public static class AppResolver
{
    private static readonly ConcurrentDictionary<int, AppInfo> Cache = new();
    private static Dictionary<int, int> _parents = new();
    private static Dictionary<int, string> _svcByPid = new();
    private static DateTime _parentsAt, _svcAt;
    private static readonly object Gate = new();

    public static AppInfo Resolve(int pid)
    {
        if (pid is 0 or 4) return AppInfo.System(pid);
        return Cache.GetOrAdd(pid, ResolveUncached);
    }

    /// <summary>Resolve an app row from a known exe path (review rows have no live PID).</summary>
    public static AppInfo ResolveByExe(string exe)
    {
        if (string.IsNullOrEmpty(exe)) return new AppInfo("unknown", "Unknown", null, null, null, SignerInfo.None);
        return new AppInfo("exe:" + exe.ToLowerInvariant(), Describe(exe), exe, null, null, Signer.Get(exe));
    }

    /// <summary>
    /// Resolve an --app value to a stored app key ("exe:&lt;lower&gt;"). A rooted path or an "exe:"
    /// prefix passes through unchanged; a BARE name (e.g. "chrome.exe") is resolved against the apps
    /// the engine has seen, matched on the exe file name (case-insensitive, extension optional):
    /// exactly one match → its full path; several → list them and require the full path; none → clear error.
    /// </summary>
    public static string NormalizeAppKey(string app, IEnumerable<string>? knownExePaths = null)
    {
        if (app.StartsWith("exe:", StringComparison.OrdinalIgnoreCase)) return app.ToLowerInvariant();
        if (Path.IsPathRooted(app)) return "exe:" + app.ToLowerInvariant();

        string name = Path.GetFileName(app);
        string stem = Path.GetFileNameWithoutExtension(name);
        var seen = (knownExePaths ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrEmpty(p))
            .Where(p =>
                Path.GetFileName(p).Equals(name, StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(stem) && Path.GetFileNameWithoutExtension(p).Equals(stem, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (seen.Count == 0)
            throw new ArgumentException($"no running app matches '{app}' — pass the full exe path (e.g. exe:C:\\...\\{name})");
        if (seen.Count > 1)
            throw new ArgumentException($"'{app}' matches several apps — pass the full path to disambiguate: " + string.Join(", ", seen));
        return "exe:" + seen[0].ToLowerInvariant();
    }

    public static void Forget(int pid) => Cache.TryRemove(pid, out _);

    private static readonly ConcurrentDictionary<int, (string? Exe, int Parent)> Hints = new();

    public static int HintCount => Hints.Count;
    public static string? HintFor(int pid) => Hints.TryGetValue(pid, out var h) ? $"exe={h.Exe ?? "(null)"} parent={h.Parent}" : null;

    /// <summary>Process start / rundown seen by ETW: remember exe + parent so identity survives a fast exit.</summary>
    public static void NoteProcess(int pid, int parent, string? exe, bool isNewStart)
    {
        if (isNewStart) Forget(pid); // PID reuse: drop the stale identity
        Hints[pid] = (exe, parent);
    }

    private static AppInfo ResolveUncached(int pid)
    {
        string? exe = ExePath(pid);
        string? pfn = PackageFamily(pid);
        if (exe == null) return new AppInfo($"pid:{pid}", $"PID {pid}", null, null, null, SignerInfo.None);
        var signer = Signer.Get(exe);

        if (pfn != null)
            return new AppInfo("pkg:" + pfn, Describe(exe), exe, pfn, null, signer);

        if (Path.GetFileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var svcs = ServicesFor(pid) ?? "unknown service";
            return new AppInfo("svc:" + svcs.ToLowerInvariant(), $"Service Host: {svcs}", exe, null, svcs, signer);
        }

        // Fold helper processes into the topmost ancestor of the same product.
        string rootExe = exe;
        var (prod, comp) = Product(exe);
        int cur = pid;
        for (int depth = 0; depth < 16; depth++)
        {
            int parent = ParentOf(cur);
            if (parent <= 4 || parent == cur) break;
            var pExe = ExePath(parent);
            if (pExe == null) break;
            bool sameExe = pExe.Equals(rootExe, StringComparison.OrdinalIgnoreCase);
            var (pp, pc) = Product(pExe);
            bool sameProduct = !string.IsNullOrEmpty(prod) && prod == pp && comp == pc && !IsShell(pExe);
            if (!sameExe && !sameProduct) break;
            rootExe = pExe; cur = parent;
        }
        return new AppInfo("exe:" + rootExe.ToLowerInvariant(), Describe(rootExe), rootExe, null, null, Signer.Get(rootExe));
    }

    private static bool IsShell(string exe)
    {
        var n = Path.GetFileName(exe).ToLowerInvariant();
        return n is "explorer.exe" or "svchost.exe" or "services.exe" or "wininit.exe" or "winlogon.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe" or "conhost.exe";
    }

    public static string Describe(string exe)
    {
        try
        {
            var v = FileVersionInfo.GetVersionInfo(exe);
            var name = !string.IsNullOrWhiteSpace(v.FileDescription) ? v.FileDescription : v.ProductName;
            if (!string.IsNullOrWhiteSpace(name)) return name.Trim();
        }
        catch { }
        return Path.GetFileNameWithoutExtension(exe);
    }

    private static readonly ConcurrentDictionary<string, (string?, string?)> ProductCache = new(StringComparer.OrdinalIgnoreCase);
    private static (string? Product, string? Company) Product(string exe) => ProductCache.GetOrAdd(exe, e =>
    {
        try { var v = FileVersionInfo.GetVersionInfo(e); return (v.ProductName?.Trim(), v.CompanyName?.Trim()); } catch { return (null, null); }
    });

    // ---- native ----
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder buf, ref uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern int GetPackageFamilyName(IntPtr h, ref uint len, StringBuilder? name);

    public static string? ExePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return Hints.TryGetValue(pid, out var hint) ? hint.Exe : null;
        try
        {
            var sb = new StringBuilder(1024); uint size = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString() : (Hints.TryGetValue(pid, out var hint) ? hint.Exe : null);
        }
        finally { CloseHandle(h); }
    }

    private static string? PackageFamily(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            uint len = 0;
            if (GetPackageFamilyName(h, ref len, null) != 122 /*ERROR_INSUFFICIENT_BUFFER*/ || len == 0) return null;
            var sb = new StringBuilder((int)len);
            return GetPackageFamilyName(h, ref len, sb) == 0 ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    // Parent PIDs via Toolhelp32.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);

    public static int ParentOf(int pid)
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _parentsAt > TimeSpan.FromSeconds(3) || !_parents.ContainsKey(pid))
            {
                var map = new Dictionary<int, int>();
                IntPtr snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0);
                if (snap != new IntPtr(-1))
                {
                    var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
                    for (bool ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e))
                        map[(int)e.th32ProcessID] = (int)e.th32ParentProcessID;
                    CloseHandle(snap);
                }
                _parents = map; _parentsAt = DateTime.UtcNow;
            }
            if (_parents.TryGetValue(pid, out var p)) return p;
            return Hints.TryGetValue(pid, out var h) ? h.Parent : 0;
        }
    }

    // Services hosted per PID via EnumServicesStatusExW(SC_ENUM_PROCESS_INFO).
    [DllImport("advapi32.dll", SetLastError = true)] private static extern IntPtr OpenSCManagerW(IntPtr machine, IntPtr db, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusExW(IntPtr scm, int infoLevel, uint type, uint state, IntPtr buf, uint cb, out uint needed, out uint returned, ref uint resume, string? group);

    public static string? ServicesFor(int pid)
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _svcAt > TimeSpan.FromSeconds(10) || !_svcByPid.ContainsKey(pid))
            {
                var map = new Dictionary<int, List<string>>();
                IntPtr scm = OpenSCManagerW(IntPtr.Zero, IntPtr.Zero, 0x0004 /*SC_MANAGER_ENUMERATE_SERVICE*/);
                if (scm != IntPtr.Zero)
                {
                    uint resume = 0;
                    EnumServicesStatusExW(scm, 0, 0x30 /*SERVICE_WIN32*/, 1 /*ACTIVE*/, IntPtr.Zero, 0, out uint need, out _, ref resume, null);
                    IntPtr buf = Marshal.AllocHGlobal((int)need + 4096);
                    resume = 0;
                    if (EnumServicesStatusExW(scm, 0, 0x30, 1, buf, need + 4096, out _, out uint n, ref resume, null))
                    {
                        int sz = IntPtr.Size * 2 + 36; sz = (sz + IntPtr.Size - 1) / IntPtr.Size * IntPtr.Size; // ENUM_SERVICE_STATUS_PROCESSW
                        for (int i = 0; i < n; i++)
                        {
                            IntPtr row = buf + i * sz;
                            string name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(row))!;
                            int spid = Marshal.ReadInt32(row, IntPtr.Size * 2 + 28); // SERVICE_STATUS_PROCESS.dwProcessId
                            if (!map.TryGetValue(spid, out var l)) map[spid] = l = new();
                            l.Add(name);
                        }
                    }
                    Marshal.FreeHGlobal(buf);
                    CloseServiceHandle(scm);
                }
                _svcByPid = map.ToDictionary(k => k.Key, v => string.Join(", ", v.Value.OrderBy(s => s)));
                _svcAt = DateTime.UtcNow;
            }
            return _svcByPid.TryGetValue(pid, out var s) ? s : null;
        }
    }
}
