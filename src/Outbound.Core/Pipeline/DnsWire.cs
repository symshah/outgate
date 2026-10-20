using System.Net;

namespace Outbound.Core.Pipeline;

/// <summary>
/// Minimal DNS response parser for frames from the in-box NDIS-PacketCapture ETW provider.
/// Needed because Chrome/Edge use a built-in resolver that never raises DNS-Client 3008.
/// Only the header, question name and A/AAAA/CNAME answers are read; nothing is stored but name→IP.
/// </summary>
public static class DnsWire
{
    /// <summary>Ethernet (optionally VLAN-tagged) → IPv4/IPv6 → UDP source port 53 → DNS payload.</summary>
    public static bool TryExtractDnsFromEthernet(ReadOnlySpan<byte> f, out ReadOnlySpan<byte> dns)
    {
        dns = default;
        if (f.Length < 14) return false;
        int off = 12; int ethType = f[off] << 8 | f[off + 1]; off += 2;
        if (ethType == 0x8100 && f.Length >= 18) { ethType = f[16] << 8 | f[17]; off = 18; }
        int udp;
        if (ethType == 0x0800)
        {
            if (f.Length < off + 20) return false;
            int ihl = (f[off] & 0x0F) * 4; if (f[off + 9] != 17) return false;
            udp = off + ihl;
        }
        else if (ethType == 0x86DD)
        {
            if (f.Length < off + 40 || f[off + 6] != 17) return false;
            udp = off + 40;
        }
        else return false;
        if (f.Length < udp + 8) return false;
        int sport = f[udp] << 8 | f[udp + 1];
        if (sport != 53) return false;
        dns = f[(udp + 8)..];
        return true;
    }

    /// <summary>Returns (question name, answer IPs) for a successful response, else null.</summary>
    public static (string Name, List<string> Ips)? ParseResponse(ReadOnlySpan<byte> m)
    {
        try
        {
            if (m.Length < 12) return null;
            bool isResponse = (m[2] & 0x80) != 0; int rcode = m[3] & 0x0F;
            int qd = m[4] << 8 | m[5], an = m[6] << 8 | m[7];
            if (!isResponse || rcode != 0 || qd < 1 || an < 1) return null;
            int off = 12;
            string qname = ReadName(m, ref off); off += 4;
            for (int i = 1; i < qd; i++) { ReadName(m, ref off); off += 4; }
            var ips = new List<string>();
            for (int i = 0; i < an && off + 10 <= m.Length; i++)
            {
                ReadName(m, ref off);
                int rtype = m[off] << 8 | m[off + 1]; int rdlen = m[off + 8] << 8 | m[off + 9]; off += 10;
                if (off + rdlen > m.Length) break;
                if (rtype == 1 && rdlen == 4) ips.Add(new IPAddress(m.Slice(off, 4)).ToString());
                else if (rtype == 28 && rdlen == 16) ips.Add(new IPAddress(m.Slice(off, 16)).ToString());
                off += rdlen;
            }
            return ips.Count == 0 || qname.Length == 0 ? null : (qname, ips);
        }
        catch { return null; }
    }

    private static string ReadName(ReadOnlySpan<byte> m, ref int off)
    {
        var sb = new System.Text.StringBuilder();
        int pos = off; bool jumped = false; int guard = 0;
        while (pos < m.Length && guard++ < 128)
        {
            int len = m[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                int ptr = (len & 0x3F) << 8 | m[pos + 1];
                if (!jumped) off = pos + 2;
                jumped = true; pos = ptr; continue;
            }
            if (sb.Length > 0) sb.Append('.');
            sb.Append(System.Text.Encoding.ASCII.GetString(m.Slice(pos + 1, len)));
            pos += len + 1;
        }
        if (!jumped) off = pos;
        return sb.ToString().ToLowerInvariant();
    }
}
