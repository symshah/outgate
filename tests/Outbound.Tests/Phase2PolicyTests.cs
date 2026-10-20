using Outbound.Core.Policy;
using Outbound.Core.Rules;
using Outbound.Core.Store;
using Xunit;

namespace Outbound.Tests;

public class Phase2PolicyTests
{
    private static FlowContext Ctx(string ip = "93.184.216.34", int port = 443, string exe = @"C:\Apps\app.exe", string? host = null, ProtoSpec proto = ProtoSpec.Tcp)
        => new(42, "app", exe, ip, (ushort)port, host, proto);

    [Fact]
    public void Once_IsConsumed_AfterFirstMatch()
    {
        var lc = new LifetimeContext(null, "s", "b");
        var r = new Rule { Destination = "any", Action = RuleAction.Deny, Lifetime = LifetimeKind.Once, SessionKey = "s", BootKey = "b" };
        Assert.False(r.IsExpired(DateTime.UtcNow, lc));
        r.Consumed = true;
        Assert.True(r.IsExpired(DateTime.UtcNow, lc));
    }

    [Fact]
    public void Hours_Expires()
    {
        var r = new Rule { Destination = "any", Lifetime = LifetimeKind.Hours, ExpiresUtc = DateTime.UtcNow.AddSeconds(-1) };
        Assert.True(r.IsExpired(DateTime.UtcNow, new LifetimeContext()));
    }

    [Fact]
    public void UntilQuit_Expires_WhenPidGone() =>
        Assert.True(new Rule { Destination = "any", Lifetime = LifetimeKind.UntilQuit, WatchPid = 9 }.IsExpired(DateTime.UtcNow, new LifetimeContext(pid => false)));

    [Fact]
    public void UntilLogout_Expires_OnSessionChange()
    {
        var r = new Rule { Destination = "any", Lifetime = LifetimeKind.UntilLogout, SessionKey = "s1", BootKey = "b" };
        Assert.False(r.IsExpired(DateTime.UtcNow, new LifetimeContext(null, "s1", "b")));
        Assert.True(r.IsExpired(DateTime.UtcNow, new LifetimeContext(null, "s2", "b")));   // next logon
        Assert.True(r.IsExpired(DateTime.UtcNow, new LifetimeContext(null, "s1", "b2")));  // restart also ends it
    }

    [Fact]
    public void UntilRestart_Expires_OnBootChange()
    {
        var r = new Rule { Destination = "any", Lifetime = LifetimeKind.UntilRestart, BootKey = "b1" };
        Assert.False(r.IsExpired(DateTime.UtcNow, new LifetimeContext(null, "s", "b1")));
        Assert.True(r.IsExpired(DateTime.UtcNow, new LifetimeContext(null, "s", "b2")));
    }

    [Fact]
    public void Forever_NeverExpires() => Assert.False(new Rule { Destination = "any", Lifetime = LifetimeKind.Forever }.IsExpired(DateTime.MaxValue));

    [Fact]
    public void DisabledRule_IsSkipped()
    {
        var r = new Rule { Destination = "any", Action = RuleAction.Deny, Enabled = false };
        Assert.Empty(RuleMatcher.Matching([r], Ctx(), DateTime.UtcNow, new LifetimeContext()));
    }

    [Fact]
    public void HostnameRule_Matches_Subdomains_And_ResolvedIps()
    {
        var rule = new Rule { Destination = "example.com", Action = RuleAction.Deny, ResolvedIps = ["93.184.216.34"] };
        Assert.Equal(1, RuleMatcher.Matching([rule], Ctx(host: "www.example.com"), DateTime.UtcNow, new LifetimeContext()).Count);
        Assert.Equal(1, RuleMatcher.Matching([rule], Ctx(ip: "93.184.216.34"), DateTime.UtcNow, new LifetimeContext()).Count);
        Assert.Empty(RuleMatcher.Matching([rule], Ctx(ip: "1.2.3.4", host: "example.net"), DateTime.UtcNow, new LifetimeContext()));
    }

    [Fact]
    public void ProtocolFilter_Applies()
    {
        var rule = new Rule { Destination = "any", Action = RuleAction.Deny, Protocol = ProtoSpec.Udp };
        Assert.Empty(RuleMatcher.Matching([rule], Ctx(proto: ProtoSpec.Tcp), DateTime.UtcNow, new LifetimeContext()));
        Assert.Equal(1, RuleMatcher.Matching([rule], Ctx(proto: ProtoSpec.Udp), DateTime.UtcNow, new LifetimeContext()).Count);
    }

    [Fact]
    public void PriorityFlag_Outranks_Specificity()
    {
        var prio = new Rule { Id = 1, Destination = "any", Action = RuleAction.Allow, IsPriority = true };
        var exact = new Rule { Id = 2, Destination = "93.184.216.34", Action = RuleAction.Deny };
        var (m, _) = RuleMatcher.Decide([exact, prio], Ctx(), DateTime.UtcNow, new LifetimeContext());
        Assert.Equal(1, m!.Id); // priority beats the more-specific deny
    }

    [Fact]
    public void Strict_Blocks_NoRule_Flow()
    {
        var e = new PolicyEngine(); e.Settings.Mode = Mode.Strict;
        var d = e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext());
        Assert.False(d.Allow); Assert.True(d.Review);
    }

    [Fact]
    public void Learn_Allows_NoRule_Flow_IntoReview()
    {
        var e = new PolicyEngine(); e.Settings.Mode = Mode.Learn;
        var d = e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext());
        Assert.True(d.Allow); Assert.True(d.Review);
    }

    [Fact]
    public void Ask_Prompts_NoRule_Flow()
    {
        var e = new PolicyEngine(); e.Settings.Mode = Mode.Ask;
        var d = e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext());
        Assert.False(d.Allow); Assert.True(d.Prompt);
    }

    [Fact]
    public void DnsDhcp_AlwaysAllowed_SafetyNet()
    {
        var e = new PolicyEngine(); e.Settings.Mode = Mode.Strict;
        var d = e.Evaluate(Ctx(ip: "8.8.8.8", port: 53, exe: @"C:\Windows\System32\dns.exe", proto: ProtoSpec.Udp), true, DateTime.UtcNow, new LifetimeContext());
        Assert.True(d.Allow);
        Assert.DoesNotContain("rule", d.Reason);
    }

    [Fact]
    public void Enforce_Deny_ExampleCom_ForCurl_Plans_ResolvedIps()
    {
        var r = new Rule { Destination = "example.com", Action = RuleAction.Deny, AppMatcher = @"C:\Windows\System32\curl.exe", ResolvedIps = ["93.184.216.34", "2606:2800::1"] };
        var plan = EnforcementPlanner.Plan([r], installed: []);
        Assert.Equal(1, plan.AddCommands.Count);
        Assert.Contains("program=\"C:\\Windows\\System32\\curl.exe\"", plan.AddCommands[0]);
        Assert.Contains("remoteip=93.184.216.34,2606:2800::1", plan.AddCommands[0]);
        Assert.DoesNotContain("example.com", plan.AddCommands[0]);
    }

    [Fact]
    public void Enforce_IsIdempotent_And_Removes_Stale()
    {
        var r = new Rule { Id = 5, Destination = "1.2.3.4", Action = RuleAction.Deny };
        var plan1 = EnforcementPlanner.Plan([r], installed: []);
        Assert.Equal(1, plan1.AddCommands.Count);
        var plan2 = EnforcementPlanner.Plan([r], installed: ["OutboundWin 5"]);
        Assert.Equal(0, plan2.AddCommands.Count);
        var plan3 = EnforcementPlanner.Plan([], installed: ["OutboundWin 1", "OutboundWin 5"]);
        Assert.Equal(2, plan3.RemoveCommands.Count);
    }

    [Fact]
    public void Enforce_Skips_DenyAny_And_Unresolved_Hostnames()
    {
        var any = new Rule { Destination = "any", Action = RuleAction.Deny, AppMatcher = @"C:\x.exe" };
        var unres = new Rule { Destination = "unresolvable.local", Action = RuleAction.Deny, AppMatcher = @"C:\x.exe" };
        Assert.Empty(EnforcementPlanner.Desired([any, unres]));
    }

    [Fact]
    public void ProfileFilter_UntaggedRule_AlwaysApplies()
    {
        var svc = new ProfileService(Path.Combine(Path.GetTempPath(), $"ob_prof_{Guid.NewGuid():N}.json"), startWatcher: false);
        try
        {
            var e = new PolicyEngine(); e.Profiles = svc; e.Settings.Mode = Mode.Strict;
            e.Rules = [new Rule { Destination = "any", Action = RuleAction.Deny }]; // untagged → applies on every profile
            Assert.False(e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext()).Allow);
        }
        finally { svc.Dispose(); }
    }

    [Fact]
    public void ProfileFilter_TaggedRule_OnlyOnItsProfile()
    {
        var svc = new ProfileService(Path.Combine(Path.GetTempPath(), $"ob_prof_{Guid.NewGuid():N}.json"), startWatcher: false);
        try
        {
            svc.Profiles.Add(new Profile { Name = "work", Mode = Mode.Strict });
            var e = new PolicyEngine(); e.Profiles = svc; e.Settings.Mode = Mode.Learn;
            e.Rules = [new Rule { Destination = "any", Action = RuleAction.Deny, Profile = "work" }];

            // No active profile → tagged rule is skipped (Learn allows).
            Assert.True(e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext()).Allow);

            // Active profile matches the tag → deny applies.
            svc.SetActive("work");
            Assert.False(e.Evaluate(Ctx(), true, DateTime.UtcNow, new LifetimeContext()).Allow);

            // Profile persistence round-trips through profiles.json.
            var reloaded = new ProfileService(svc.Path, startWatcher: false);
            try { Assert.Contains(reloaded.Profiles, p => p.Name == "work"); }
            finally { reloaded.Dispose(); }
        }
        finally { svc.Dispose(); }
    }

    [Fact]
    public void Blocklist_Denies_ListedHost_ExactAndSubdomain()
    {
        var bl = new BlocklistService(Path.Combine(Path.GetTempPath(), $"ob_bl_{Guid.NewGuid():N}.json"));
        try
        {
            int n = bl.ParseText("127.0.0.1 ads.example.com\n# comment line\nmalware.net", "test");
            Assert.Equal(2, n);
            Assert.Equal("test", bl.WhichList("ads.example.com"));      // exact
            Assert.Equal("test", bl.WhichList("x.ads.example.com"));    // subdomain of a listed entry
            Assert.Null(bl.WhichList("example.com"));                   // parent is NOT blocked by child entry

            var e = new PolicyEngine(); e.Blocklists = bl; e.Settings.Mode = Mode.Learn; // Learn would allow — blocklist must deny
            var d = e.Evaluate(Ctx(host: "ads.example.com"), true, DateTime.UtcNow, new LifetimeContext());
            Assert.False(d.Allow);
            Assert.Contains("blocklist", d.Reason);
        }
        finally { bl.Dispose(); }
    }

    [Fact]
    public void Blocklist_ExplicitAllowRule_Wins()
    {
        var bl = new BlocklistService(Path.Combine(Path.GetTempPath(), $"ob_bl_{Guid.NewGuid():N}.json"));
        try
        {
            bl.ParseText("127.0.0.1 ads.example.com", "test");
            var e = new PolicyEngine(); e.Blocklists = bl; e.Settings.Mode = Mode.Strict;
            e.Rules = [new Rule { Destination = "ads.example.com", Action = RuleAction.Allow }]; // explicit allow beats the list
            Assert.True(e.Evaluate(Ctx(host: "ads.example.com"), true, DateTime.UtcNow, new LifetimeContext()).Allow);
        }
        finally { bl.Dispose(); }
    }

    [Fact]
    public void Blocklist_FailedFetch_KeepsLastGoodList()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"ob_bl_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(dir, "lists"));
        try
        {
            // Seed the per-sub cache file (what a previous successful fetch would have written).
            File.WriteAllText(Path.Combine(dir, "lists", "test.txt"), "127.0.0.1 ads.example.com\nmalware.net");
            var bl = new BlocklistService(Path.Combine(dir, "blocklists.json"));
            try
            {
                bl.Subs.Add(new BlocklistSub { Name = "test", Url = "http://127.0.0.1:9/" }); // unreachable → fetch fails
                bl.RefreshAsync().GetAwaiter().GetResult();
                Assert.NotNull(bl.Subs[0].LastError);                       // failure recorded…
                Assert.Equal(2, bl.TotalEntries);                          // …but the last good list is still active
                Assert.Equal("test", bl.WhichList("ads.example.com"));
            }
            finally { bl.Dispose(); }
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void Blocklist_WhichList_Attributes_CorrectSub()
    {
        var bl = new BlocklistService(Path.Combine(Path.GetTempPath(), $"ob_bl_{Guid.NewGuid():N}.json"));
        try
        {
            bl.ParseText("127.0.0.1 a.example.com\nshared.example.com", "one");
            bl.ParseText("127.0.0.1 b.example.com\nshared.example.com", "two"); // shared entry in both lists
            Assert.Equal("one", bl.WhichList("a.example.com"));
            Assert.Equal("two", bl.WhichList("b.example.com"));
            Assert.NotNull(bl.WhichList("shared.example.com"));               // attributed to one of them (first)
        }
        finally { bl.Dispose(); }
    }

    [Fact]
    public void Blocklist_Subs_Persist_RoundTrip()
    {
        string path = Path.Combine(Path.GetTempPath(), $"ob_bl_{Guid.NewGuid():N}.json");
        try
        {
            var bl = new BlocklistService(path);
            bl.AddSub("testlist", "http://127.0.0.1:9/"); // unreachable — persistence is what's under test
            Thread.Sleep(300); // let Save() land
            bl.Dispose();

            var reloaded = new BlocklistService(path);
            try
            {
                Assert.Single(reloaded.Subs);
                Assert.Equal("testlist", reloaded.Subs[0].Name);   // camelCase round-trip (was: empty name)
                Assert.Equal("http://127.0.0.1:9/", reloaded.Subs[0].Url);
            }
            finally { reloaded.Dispose(); }
        }
        finally { try { File.Delete(path); } catch { } }
    }

    [Fact]
    public void Pending_ReviewAndAnswer_Flow()
    {
        var db = Path.Combine(Path.GetTempPath(), $"ob_p2_{Guid.NewGuid():N}.db");
        try
        {
            var svc = new PolicyService(db);
            svc.Engine.Settings.Mode = Mode.Ask;
            var appTrust = new AppTrustStore(db);
            appTrust.Trust("exe:c:\\apps\\app.exe", new Outbound.Core.Identity.AppInfo("exe:c:\\apps\\app.exe", "App", @"C:\Apps\app.exe", null, null, new Outbound.Core.Identity.SignerInfo(Outbound.Core.Identity.SignerKind.Named, "Acme", false)), "deadbeef");
            new ReviewStore(db).Add("exe:c:\\apps\\app.exe", "App", "example.com", "93.184.216.34", 443, "Tcp", "ask: awaiting", ReviewAction.Pending, DateTime.UtcNow);
            var item = new ReviewStore(db).Pending().First();
            var rule = svc.Answer(item.Id, RuleAction.Allow, LifetimeKind.Forever, "port", null);
            Assert.NotNull(rule);
            Assert.True(rule!.Destination == "example.com");
            Assert.False(new ReviewStore(db).Pending().Any()); // answered
        }
        finally { }
        try { File.Delete(db); } catch { }
    }
}
