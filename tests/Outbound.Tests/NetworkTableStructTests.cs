using System.Runtime.InteropServices;
using Outbound.Core.Network;
using Xunit;

namespace Outbound.Tests;

/// <summary>
/// Phase 0 guard: if these sizes ever change, the P/Invoke row parsing is broken.
/// Sizes per iphlpapi.h — MIB_TCPROW_OWNER_PID=24, MIB_UDPROW_OWNER_PID=12 (all DWORDs).
/// </summary>
public class NetworkTableStructTests
{
    [Fact]
    public void TcpRowOwnerPid_Is_24_Bytes() =>
        Assert.Equal(24, Marshal.SizeOf<NetworkTable.MibTcpRowOwnerPid>());

    [Fact]
    public void UdpRowOwnerPid_Is_12_Bytes() =>
        Assert.Equal(12, Marshal.SizeOf<NetworkTable.MibUdpRowOwnerPid>());

    [Fact]
    public void Tcp6RowOwnerPid_Is_56_Bytes() =>
        Assert.Equal(56, Marshal.SizeOf<NetworkTable.MibTcp6RowOwnerPid>());

    [Fact]
    public void Udp6RowOwnerPid_Is_28_Bytes() =>
        Assert.Equal(28, Marshal.SizeOf<NetworkTable.MibUdp6RowOwnerPid>());

    // MIB_TCP_STATE values per tcpmib.h — a wrong value here silently mislabels every state.
    [Fact]
    public void TcpState_Matches_Iphlpapi_Values()
    {
        Assert.Equal(1u, (uint)TcpState.Closed);
        Assert.Equal(2u, (uint)TcpState.Listen);
        Assert.Equal(3u, (uint)TcpState.SynSent);
        Assert.Equal(4u, (uint)TcpState.SynReceived);
        Assert.Equal(5u, (uint)TcpState.Established);
        Assert.Equal(6u, (uint)TcpState.FinWait1);
        Assert.Equal(7u, (uint)TcpState.FinWait2);
        Assert.Equal(8u, (uint)TcpState.CloseWait);
        Assert.Equal(9u, (uint)TcpState.Closing);
        Assert.Equal(10u, (uint)TcpState.LastAck);
        Assert.Equal(11u, (uint)TcpState.TimeWait);
        Assert.Equal(12u, (uint)TcpState.DeleteTcb);
    }

    [Theory]
    // Port stored network-order (big-endian) in the low 16 bits of a DWORD; on a
    // little-endian host the raw DWORD value is byte-swapped: port 443 → 0xBB01.
    [InlineData(0xBB01u, 443)]
    [InlineData(0x3500u, 53)]
    [InlineData(0x0001u, 256)]
    public void PortFromDword_Strips_High_Bits_And_Swaps_Endian(uint dword, ushort expected) =>
        Assert.Equal(expected, NetworkTable.PortFromDword(dword));

    [Fact]
    public void Snapshot_Returns_Rows_With_Real_Pids()
    {
        // Live check: at least one row must carry a real PID (> 4, i.e. not System/Idle).
        var rows = NetworkTable.Snapshot();
        Assert.NotEmpty(rows);
        Assert.Contains(rows, r => r.Pid > 4);
    }
}
