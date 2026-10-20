using System.Runtime.InteropServices;
using System.Net;

namespace Outbound.Core.Network;

/// <summary>One live socket as seen in the OS network table.</summary>
public sealed record FlowRow(
    int Pid,
    string LocalIp,
    ushort LocalPort,
    string RemoteIp,
    ushort RemotePort,
    Protocol Proto,
    long BytesSent,
    long BytesReceived,
    TcpState State);

public enum Protocol { Unknown = 0, Tcp = 6, Udp = 17 }

// MIB_TCP_STATE values per iphlpapi.h / learn.microsoft.com (tcpmib): CLOSED=1, LISTEN=2,
// SYN_SENT=3, SYN_RCVD=4, ESTAB=5, FIN_WAIT1=6, FIN_WAIT2=7, CLOSE_WAIT=8, CLOSING=9,
// LAST_ACK=10, TIME_WAIT=11, DELETE_TCB=12. Not a flags enum.
public enum TcpState : uint
{
    Unknown = 0,
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12,
}

/// <summary>
/// Reads the OS extended TCP/UDP tables (GetExtendedTcpTable / GetExtendedUdpTable), IPv4 + IPv6.
/// User-mode only — no admin required. Gives PID per row for free.
/// NOTE: MIB rows carry no byte counters; per-flow volume is computed as deltas between
/// successive snapshots by FlowMonitor (phase 1 replaces this with ETW).
/// </summary>
public static class NetworkTable
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;

    // Table classes — must be the OWNER_PID variants or rows carry no PID:
    //   TCP_TABLE_BASIC_LISTENER=0 (no pid, listeners only) vs TCP_TABLE_OWNER_PID_ALL=5.
    //   UDP_TABLE_BASIC=0 (no pid, 8-byte rows) vs UDP_TABLE_OWNER_PID=1.
    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, uint tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, uint tableClass, int reserved);

    // MIB_TCPROW_OWNER_PID (24 bytes) — every field a DWORD; ports in low 16 bits, network order.
    [StructLayout(LayoutKind.Sequential)]
    public struct MibTcpRowOwnerPid
    {
        public uint State;       // MIB_TCP_STATE 1..12
        public uint LocalAddr;   // packed IPv4, network byte order
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    // MIB_UDPROW_OWNER_PID (12 bytes).
    [StructLayout(LayoutKind.Sequential)]
    public struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;   // packed IPv4, network byte order
        public uint LocalPort;
        public uint OwningPid;
    }

    // MIB_TCP6ROW_OWNER_PID (56 bytes) per tcpmib.h — note: State and OwningPid come LAST,
    // and each address is followed by its scope-id DWORD (link-local %N).
    [StructLayout(LayoutKind.Sequential)]
    public struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;       // MIB_TCP_STATE 1..12
        public uint OwningPid;
    }

    // MIB_UDP6ROW_OWNER_PID (28 bytes) per tcpmib.h.
    [StructLayout(LayoutKind.Sequential)]
    public struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    /// <summary>Snapshot of all live TCP + UDP sockets (IPv4 + IPv6), all states, with owning PID.</summary>
    public static List<FlowRow> Snapshot()
    {
        var rows = new List<FlowRow>();
        rows.AddRange(SnapshotTcpV4());
        rows.AddRange(SnapshotUdpV4());
        rows.AddRange(SnapshotTcpV6());
        rows.AddRange(SnapshotUdpV6());
        return rows;
    }

    /// <summary>Port DWORD (low 16 bits, network order) → host-order ushort.</summary>
    public static ushort PortFromDword(uint portDword) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(portDword & 0xFFFF));

    private static string Ip4FromPacked(uint packedNetworkOrder) =>
        new IPAddress(BitConverter.GetBytes(packedNetworkOrder)).ToString();

    /// <summary>IPv6 → netstat-style text; link-local gets the %ifIndex suffix.</summary>
    public static string Ip6WithScope(byte[] addr16, uint scopeId)
    {
        var ip = new IPAddress(addr16);
        if (scopeId != 0 && ip.IsIPv6LinkLocal) return $"{ip}%{scopeId}";
        return ip.ToString();
    }

    private static List<FlowRow> SnapshotTcpV4()
    {
        var result = new List<FlowRow>();
        int len = 65536;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                buf = Marshal.AllocHGlobal(len);
                int outLen = len;
                uint rc = GetExtendedTcpTable(buf, ref outLen, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc == 120) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    len = Math.Max(len * 2, outLen);
                    continue;
                }
                if (rc != 0) return result;

                uint count = (uint)Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>(); // 24 — asserted in tests
                IntPtr rowsPtr = buf + 4; // dwNumEntries header
                for (uint i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowsPtr + (nint)(i * rowSize));
                    result.Add(new FlowRow(
                        (int)r.OwningPid,
                        Ip4FromPacked(r.LocalAddr), PortFromDword(r.LocalPort),
                        Ip4FromPacked(r.RemoteAddr), PortFromDword(r.RemotePort),
                        Protocol.Tcp, 0, 0, (TcpState)r.State));
                }
                return result;
            }
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static List<FlowRow> SnapshotUdpV4()
    {
        var result = new List<FlowRow>();
        int len = 65536;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                buf = Marshal.AllocHGlobal(len);
                int outLen = len;
                uint rc = GetExtendedUdpTable(buf, ref outLen, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
                if (rc == 120) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    len = Math.Max(len * 2, outLen);
                    continue;
                }
                if (rc != 0) return result;

                uint count = (uint)Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>(); // 12 — asserted in tests
                IntPtr rowsPtr = buf + 4;
                for (uint i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowsPtr + (nint)(i * rowSize));
                    result.Add(new FlowRow(
                        (int)r.OwningPid,
                        Ip4FromPacked(r.LocalAddr), PortFromDword(r.LocalPort),
                        "0.0.0.0", 0, // UDP socket table has no remote endpoint
                        Protocol.Udp, 0, 0, TcpState.Unknown)); // UDP sockets have no TCP state
                }
                return result;
            }
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static List<FlowRow> SnapshotTcpV6()
    {
        var result = new List<FlowRow>();
        int len = 65536;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                buf = Marshal.AllocHGlobal(len);
                int outLen = len;
                uint rc = GetExtendedTcpTable(buf, ref outLen, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc == 120) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    len = Math.Max(len * 2, outLen);
                    continue;
                }
                if (rc != 0) return result;

                uint count = (uint)Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>(); // 56 — asserted in tests
                IntPtr rowsPtr = buf + 4;
                for (uint i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowsPtr + (nint)(i * rowSize));
                    result.Add(new FlowRow(
                        (int)r.OwningPid,
                        Ip6WithScope(r.LocalAddr, r.LocalScopeId), PortFromDword(r.LocalPort),
                        Ip6WithScope(r.RemoteAddr, r.RemoteScopeId), PortFromDword(r.RemotePort),
                        Protocol.Tcp, 0, 0, (TcpState)r.State));
                }
                return result;
            }
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static List<FlowRow> SnapshotUdpV6()
    {
        var result = new List<FlowRow>();
        int len = 65536;
        IntPtr buf = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                buf = Marshal.AllocHGlobal(len);
                int outLen = len;
                uint rc = GetExtendedUdpTable(buf, ref outLen, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                if (rc == 120) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    len = Math.Max(len * 2, outLen);
                    continue;
                }
                if (rc != 0) return result;

                uint count = (uint)Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>(); // 28 — asserted in tests
                IntPtr rowsPtr = buf + 4;
                for (uint i = 0; i < count; i++)
                {
                    var r = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(rowsPtr + (nint)(i * rowSize));
                    result.Add(new FlowRow(
                        (int)r.OwningPid,
                        Ip6WithScope(r.LocalAddr, r.LocalScopeId), PortFromDword(r.LocalPort),
                        "::", 0, // UDP socket table has no remote endpoint
                        Protocol.Udp, 0, 0, TcpState.Unknown)); // UDP sockets have no TCP state
                }
                return result;
            }
        }
        finally { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); }
        return result;
    }
}
