using System.Net;
using Outbound.Core.Domains;
using Outbound.Core.Enforcement;
using Outbound.Core.Etw;
using Outbound.Core.Geo;
using Outbound.Core.Identity;
using Outbound.Core.Pipeline;
using Outbound.Core.Rules;
using Xunit;

namespace Outbound.Tests;

public class Phase1PipelineTests
{
    private static readonly PublicSuffixList Psl = PublicSuffixList.Parse(new[]
    {
        "// comment", "com", "uk", "co.uk", "*.ck", "!www.ck", "github.io", "jp", "*.kawasaki.jp", "!city.kawasaki.jp",
    });

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("www.example.com", "example.com")]
    [InlineData("a.b.bbc.co.uk", "bbc.co.uk")]
    [InlineData("foo.bar.ck", "foo.bar.ck")]   // wildcard *.ck → bar.ck is a suffix
    [InlineData("www.ck", "www.ck")]           // exception !www.ck
    [InlineData("user.github.io", "user.github.io")]
    [InlineData("city.kawasaki.jp", "city.kawasaki.jp")]
    [InlineData("telemetry.zoom.us", "zoom.us")] // default rule "*"
    public void Psl_RegistrableDomain(string host, string expected) => Assert.Equal(expected, Psl.RegistrableDomain(host));

    [Theory]
    [InlineData("co.uk")]
    [InlineData("93.184.215.14")]
    [InlineData("")]
    public void Psl_NoRegistrableDomain(string host) => Assert.Null(Psl.RegistrableDomain(host));

    [Fact]
    public void Psl_BundledList_Loads_And_Handles_Real_Suffixes()
    {
        var psl = PublicSuffixList.Default;
        Assert.NotNull(psl);
        Assert.True(psl!.RuleCount > 5000);
        Assert.Equal("bbc.co.uk", psl.RegistrableDomain("www.bbc.co.uk"));
        Assert.Equal("example.com", psl.RegistrableDomain("example.com"));
    }

    [Fact]
    public void DnsClient3008_Results_Parsing_Maps_V4Mapped_And_Skips_Cnames()
    {
        var ips = EtwNetworkCollector.ParseDnsResults("type:  5 example.cdn.net;::ffff:93.184.215.14;2606:2800:21f:cb07:6820:80da:af6b:8b2c;");
        Assert.Equal(new[] { "93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c" }, ips);
    }

    [Fact]
    public void DnsWire_Parses_Response_With_Compression()
    {
        // Response for example.com A 93.184.215.14 (answer name is a pointer to offset 12).
        byte[] dns = Convert.FromHexString(
            "12348180000100010000000007" + "6578616d706c65" + "03636f6d0000010001" +
            "c00c000100010000012c00045db8d70e");
        var r = DnsWire.ParseResponse(dns);
        Assert.NotNull(r);
        Assert.Equal("example.com", r!.Value.Name);
        Assert.Equal(new[] { "93.184.215.14" }, r.Value.Ips);
    }

    [Fact]
    public void DnsWire_Extracts_Udp53_From_Ethernet_Ipv4()
    {
        var frame = new byte[14 + 20 + 8 + 4];
        frame[12] = 0x08; frame[13] = 0x00;            // IPv4
        frame[14] = 0x45; frame[14 + 9] = 17;          // IHL=5, UDP
        frame[34] = 0; frame[35] = 53;                 // sport 53
        Assert.True(DnsWire.TryExtractDnsFromEthernet(frame, out var payload));
        Assert.Equal(4, payload.Length);
        frame[35] = 54;
        Assert.False(DnsWire.TryExtractDnsFromEthernet(frame, out _));
    }

    [Fact]
    public void DnsMap_PrefersPerProcessName_ThenGlobal()
    {
        var m = new DnsMap();
        m.Add(100, "example.com", new[] { "1.2.3.4" }, DateTime.UtcNow);
        m.Add(200, "cdn.other.net", new[] { "1.2.3.4" }, DateTime.UtcNow);
        Assert.Equal("example.com", m.Lookup(100, "1.2.3.4"));
        Assert.Equal("cdn.other.net", m.Lookup(200, "1.2.3.4"));
        Assert.Equal("cdn.other.net", m.Lookup(999, "1.2.3.4")); // global = most recent
        Assert.Null(m.Lookup(100, "9.9.9.9"));
    }

    [Theory]
    [InlineData("10.1.2.3", true)] [InlineData("192.168.31.1", true)] [InlineData("172.20.0.1", true)]
    [InlineData("fe80::1", true)] [InlineData("fd00::1", true)] [InlineData("8.8.8.8", false)] [InlineData("2606:4700::1", false)]
    public void Geo_IsLocal(string ip, bool local) => Assert.Equal(local, GeoIp.IsLocal(IPAddress.Parse(ip)));

    [Fact]
    public void Geo_Bundled_DbIp_Resolves_Public_Ip()
    {
        using var g = GeoIp.TryOpenDefault();
        Assert.NotNull(g);
        var info = g!.Lookup("8.8.8.8");
        Assert.Equal("US", info.CountryCode);
        Assert.True(g.Lookup("192.168.1.1").IsLocal);
    }

    [Fact]
    public void Signer_CatalogSigned_Windows_Binary_Is_Microsoft_Windows()
    {
        var s = Signer.Get(Path.Combine(Environment.SystemDirectory, "notepad.exe"));
        Assert.Equal(SignerKind.Microsoft, s.Kind);
        Assert.Equal("Microsoft Windows", s.Display);
    }

    [Fact]
    public void Signer_Unsigned_File_Is_Unsigned()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"ob_unsigned_{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tmp, new byte[] { 0x4D, 0x5A, 0, 0 });
        try { Assert.Equal(SignerKind.Unsigned, Signer.Get(tmp).Kind); } finally { File.Delete(tmp); }
    }

    [Fact]
    public void Enforcer_Hostname_Uses_Resolved_Ips_Never_The_Name()
    {
        var r = new Rule { Id = 7, Destination = "example.com", Action = RuleAction.Deny, AppMatcher = @"C:\Windows\System32\curl.exe", ResolvedIps = new() { "1.2.3.4", "5.6.7.8" } };
        var cmd = new FirewallEnforcer().BuildCommands(new[] { r }).Single();
        Assert.Contains("remoteip=1.2.3.4,5.6.7.8", cmd);
        Assert.DoesNotContain("example.com", cmd);
        r.ResolvedIps = null;
        Assert.Empty(new FirewallEnforcer().BuildCommands(new[] { r }));
    }

    [Fact]
    public void Enforcer_Defaults_To_DryRun() => Assert.True(new FirewallEnforcer().DryRun);
}
