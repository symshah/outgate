using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Outbound.Core.Network;

/// <summary>
/// Current network identity via Network List Manager (INetworkListManager).
/// Polls every 5 s on a background thread and raises <see cref="Changed"/> when the
/// connected network's name or connectivity changes — that is what "joined a new network" means.
/// </summary>
public sealed class NetworkWatcher : IDisposable
{
    public string Name { get; private set; } = "";
    public bool Connected { get; private set; }

    /// <summary>Raised on the watcher thread when the active network changed (name or connectivity).</summary>
    public event Action<string, bool>? Changed;

    private readonly Thread _thread;
    private volatile bool _stop;

    [DllImport("ole32.dll")]
    private static extern int CoInitializeEx(object pvReserved, uint dwCoInit);
    private const uint COINIT_MULTITHREADED = 0x0;

    [ComImport, Guid("1B6A2965-70E2-4AFC-821F-6A78B3BBB783"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface INetworkListManager
    {
        [PreserveSig] int GetNetworkCount([Out] out uint count);
        [PreserveSig] int GetNetworkAt(uint index, [MarshalAs(UnmanagedType.IUnknown)][Out] out object network);
        [PreserveSig] int get_ConnectedNetwork([MarshalAs(UnmanagedType.IUnknown)][Out] out object? network);
    }

    [ComImport, Guid("50F71C0C-6A9E-44A6-84AA-E2A9B690BECD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface INetwork
    {
        // Full vtable — order must match the COM interface exactly (INetwork has no get_ConnectedNetwork).
        [PreserveSig] int get_IsConnected(out bool connected);
        [PreserveSig] int get_Name([MarshalAs(UnmanagedType.BStr)]out string name);
        [PreserveSig] int get_Description([MarshalAs(UnmanagedType.BStr)]out string description);
        [PreserveSig] int get_Category(out uint category);
        [PreserveSig] int get_IsConnectedToInternet(out bool connected);
        [PreserveSig] int get_IsDomainAuthenticated(out bool domainAuth);
        [PreserveSig] int get_IsAuthenticated(out bool authenticated);
        [PreserveSig] int get_IsConnectedToPublicNetwork(out bool publicNet);
        [PreserveSig] int get_IsConnectedToPrivateNetwork(out bool privateNet);
        [PreserveSig] int get_IsConnectedToDomainNetwork(out bool domainNet);
        [PreserveSig] int get_IsConnectedToInternetSharingNetwork(out bool sharingNet);
        [PreserveSig] int get_NetworkConnectivitySignature(out uint signature);
        [PreserveSig] int get_ConnectedNetworks([MarshalAs(UnmanagedType.LPWStr)]out string networks);
    }

    public NetworkWatcher()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "net-watcher" };
        _thread.Start();
    }

    private void Loop()
    {
        CoInitializeEx(0, COINIT_MULTITHREADED); // raw thread has no COM apartment — NLM needs one
        while (!_stop)
        {
            try
            {
                var (name, connected) = QueryNlm();
                if (name != Name || connected != Connected)
                {
                    Name = name; Connected = connected;
                    Changed?.Invoke(name, connected);
                }
            }
            catch { /* NLM unavailable — keep polling */ }
            Thread.Sleep(5000);
        }
    }

    private static (string Name, bool Connected) QueryNlm()
    {
        if (!OperatingSystem.IsWindows()) return ("", false);
        try
        {
            var mgr = (INetworkListManager)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"))!)!;
            try
            {
                object? net;
                if (mgr.get_ConnectedNetwork(out net) == 0 && net != null)
                {
                    var n = (INetwork)net;
                    string name = "";
                    if (n.get_Name(out name) == 0 && !string.IsNullOrEmpty(name)) return (name, true);
                }
                // Fallback: first connected network in the list.
                uint count; mgr.GetNetworkCount(out count);
                for (uint i = 0; i < count; i++)
                {
                    if (mgr.GetNetworkAt(i, out var obj) != 0) continue;
                    var nn = (INetwork)obj;
                    bool c; string nm = "";
                    if (nn.get_IsConnected(out c) == 0 && c && nn.get_Name(out nm) == 0 && !string.IsNullOrEmpty(nm))
                        return (nm, true);
                }
            }
            finally { Marshal.ReleaseComObject(mgr); }
        }
        catch { /* NLM unavailable on this machine — fall through */ }

        // Fallback: physical adapter via System.Net.NetworkInformation.
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            switch (ni.NetworkInterfaceType)
            {
                case NetworkInterfaceType.Ethernet:
                case NetworkInterfaceType.Wireless80211:
                    return (ni.Name, true);
            }
        }
        return ("", false);
    }

    public void Dispose() => _stop = true;
}
