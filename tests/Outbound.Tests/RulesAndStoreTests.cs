using Outbound.Core.Rules;
using Outbound.Core.Store;
using Xunit;

namespace Outbound.Tests;

public class PortSpecTests
{
    [Theory]
    [InlineData("any", 443, true)]
    [InlineData("any", 1, true)]
    [InlineData("443", 443, true)]
    [InlineData("443", 80, false)]
    [InlineData("53-80", 67, true)]
    [InlineData("53-80", 52, false)]
    [InlineData("53-80", 81, false)]
    [InlineData("bad-spec", 443, false)]
    public void PortMatches(string spec, ushort port, bool expected)
        => Assert.Equal(expected, RuleMatcher.PortMatches(spec, port));
}

public class DestinationTests
{
    [Theory]
    [InlineData("any", "1.2.3.4", true)]
    [InlineData("93.184.216.34", "93.184.216.34", true)]
    [InlineData("93.184.216.34", "93.184.216.35", false)]
    [InlineData("10.0.0.0/8", "10.255.1.2", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/24", "192.168.1.77", true)]
    [InlineData("192.168.1.0/24", "192.168.2.77", false)]
    public void DestMatches_IpAndCidr(string dest, string remoteIp, bool expected)
        => Assert.Equal(expected, RuleMatcher.DestMatches(dest, remoteIp));

    [Fact]
    public void Hostname_MatchesCachedResolvedIp()
    {
        var rule = new Rule { Destination = "example.com", ResolvedIps = ["93.184.216.34"] };
        Assert.True(RuleMatcher.DestMatches(rule, "93.184.216.34"));
        Assert.False(RuleMatcher.DestMatches(rule, "93.184.216.35"));
    }

    [Fact]
    public void Hostname_SubdomainMatch_WhenRemoteIsHostname()
    {
        // Phase-2 path: flow carries a hostname (SNI/DNS correlation).
        Assert.True(RuleMatcher.DestMatches("example.com", "www.example.com"));
        Assert.True(RuleMatcher.DestMatches("example.com", "a.b.example.com."));
        Assert.False(RuleMatcher.DestMatches("example.com", "notexample.com"));
        // A bare IP remote never matches a hostname rule without cached IPs.
        Assert.False(RuleMatcher.DestMatches("example.com", "93.184.216.34"));
    }

    [Fact]
    public void HostMatchesDomain_CaseInsensitive()
    {
        Assert.True(RuleMatcher.HostMatchesDomain("WWW.Example.COM", "example.com"));
        Assert.False(RuleMatcher.HostMatchesDomain("evil-example.com", "example.com"));
    }
}

public class AppMatchTests
{
    private static FlowContext Ctx(string name = "chrome", string exe = @"C:\Program Files\Google\Chrome\Application\chrome.exe")
        => new(1234, name, exe, "93.184.216.34", 443);

    [Fact] public void NullMatcher_MatchesAny() => Assert.True(RuleMatcher.AppMatches(null, Ctx()));
    [Fact] public void EmptyMatcher_MatchesAny() => Assert.True(RuleMatcher.AppMatches("", Ctx()));
    [Fact] public void ExePath_CaseInsensitive() => Assert.True(RuleMatcher.AppMatches(@"c:\program files\google\chrome\application\CHROME.EXE", Ctx()));
    [Fact] public void ProcessName_Matches() => Assert.True(RuleMatcher.AppMatches("Chrome", Ctx()));
    [Fact] public void WrongApp_DoesNotMatch() => Assert.False(RuleMatcher.AppMatches("notepad.exe", Ctx()));
}

public class DecideTests
{
    private static FlowContext Ctx(string exe = @"C:\Apps\app.exe")
        => new(42, "app", exe, "93.184.216.34", 443);

    [Fact] public void NoRules_NoMatch()
    {
        var (m, reason) = RuleMatcher.Decide([], Ctx(), DateTime.UtcNow);
        Assert.Null(m);
        Assert.Contains("no matching rule", reason);
    }

    [Fact] public void HigherPriority_Wins()
    {
        var low = new Rule { Id = 1, Destination = "any", Action = RuleAction.Allow, Priority = 50 };
        var high = new Rule { Id = 2, Destination = "93.184.216.34", Action = RuleAction.Deny, Priority = 200 };
        var (m, _) = RuleMatcher.Decide([low, high], Ctx(), DateTime.UtcNow);
        Assert.Equal(2, m!.Id);
    }

    [Fact] public void Tie_DenyWins()
    {
        var allow = new Rule { Id = 1, Destination = "any", Action = RuleAction.Allow };
        var deny = new Rule { Id = 2, Destination = "any", Action = RuleAction.Deny };
        var (m, _) = RuleMatcher.Decide([allow, deny], Ctx(), DateTime.UtcNow);
        Assert.Equal(2, m!.Id); // same priority+specificity → deny wins
    }

    [Fact] public void Tie_MostSpecificDestinationWins()
    {
        var broad = new Rule { Id = 1, Destination = "any", Action = RuleAction.Allow };
        var specific = new Rule { Id = 2, Destination = "93.184.216.34", Action = RuleAction.Deny };
        var (m, _) = RuleMatcher.Decide([broad, specific], Ctx(), DateTime.UtcNow);
        Assert.Equal(2, m!.Id);
    }

    [Fact] public void ExpiredRule_IsSkipped()
    {
        var expired = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, Lifetime = LifetimeKind.Hours, ExpiresUtc = DateTime.UtcNow.AddHours(-1) };
        var (m, _) = RuleMatcher.Decide([expired], Ctx(), DateTime.UtcNow);
        Assert.Null(m);
    }

    // Regression: explain listed an EXPIRED rule under "matching #N" while deciding "(default)".
    // The matching list must use the same live predicate as Decide — expired rules never appear.
    [Fact] public void LiveMatch_ExcludesExpiredRule()
    {
        var now = DateTime.UtcNow;
        var lc = new LifetimeContext();
        var expired = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, Lifetime = LifetimeKind.Hours, ExpiresUtc = now.AddHours(-1) };
        Assert.False(RuleMatcher.LiveMatch(expired, Ctx(), now, lc));
        Assert.Empty(RuleMatcher.Matching([expired], Ctx(), now, lc)); // what explain's matchingRules is built from
    }

    [Fact] public void LiveMatch_IncludesLiveRule()
    {
        var now = DateTime.UtcNow;
        var lc = new LifetimeContext();
        var live = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny };
        Assert.True(RuleMatcher.LiveMatch(live, Ctx(), now, lc));
        Assert.Single(RuleMatcher.Matching([live], Ctx(), now, lc));
    }

    [Fact] public void LiveMatch_ExcludesDisabledRule()
    {
        var off = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, Enabled = false };
        Assert.False(RuleMatcher.LiveMatch(off, Ctx(), DateTime.UtcNow, new LifetimeContext()));
    }

    [Fact] public void UntilQuit_ExpiresWhenPidDies()
    {
        var rule = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, Lifetime = LifetimeKind.UntilQuit, WatchPid = 42 };
        Assert.False(rule.IsExpired(DateTime.UtcNow, pid => true));   // alive → not expired
        Assert.True(rule.IsExpired(DateTime.UtcNow, pid => false));   // dead → expired
        var (m, _) = RuleMatcher.Decide([rule], Ctx(), DateTime.UtcNow, pid => false);
        Assert.Null(m);
    }

    [Fact] public void PortMismatch_NoMatch()
    {
        var rule = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, PortSpec = "80" };
        var (m, _) = RuleMatcher.Decide([rule], Ctx(), DateTime.UtcNow); // ctx is port 443
        Assert.Null(m);
    }

    [Fact] public void AppMismatch_NoMatch()
    {
        var rule = new Rule { Id = 1, Destination = "any", Action = RuleAction.Deny, AppMatcher = "other.exe" };
        var (m, _) = RuleMatcher.Decide([rule], Ctx(), DateTime.UtcNow);
        Assert.Null(m);
    }
}

public class LifetimeTests
{
    [Fact] public void Forever_NeverExpires()
    {
        var r = new Rule { Destination = "any", Lifetime = LifetimeKind.Forever };
        Assert.False(r.IsExpired(DateTime.MaxValue));
    }

    [Fact] public void Hours_RespectsExpiry()
    {
        var now = DateTime.UtcNow;
        var future = new Rule { Destination = "any", Lifetime = LifetimeKind.Hours, ExpiresUtc = now.AddHours(1) };
        var past = new Rule { Destination = "any", Lifetime = LifetimeKind.Hours, ExpiresUtc = now.AddSeconds(-1) };
        Assert.False(future.IsExpired(now));
        Assert.True(past.IsExpired(now));
    }

    [Fact] public void UntilQuit_WithoutPid_Expires()
    {
        var r = new Rule { Destination = "any", Lifetime = LifetimeKind.UntilQuit, WatchPid = null };
        Assert.True(r.IsExpired(DateTime.UtcNow));
    }
}

[CollectionDefinition("store", DisableParallelization = true)]
public class StoreCollection : ICollectionFixture<StoreFixture>;

public sealed class StoreFixture;

[Collection("store")]
public class RuleStoreTests : IDisposable
{
    private readonly string _dbPath;
    public RuleStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"outbound-test-{Guid.NewGuid():N}.db");
    }

    [Fact]
    public void AddAndReadBack_RoundTripsAllFields()
    {
        using var store = new RuleStore(_dbPath);
        var rule = new Rule
        {
            AppMatcher = @"C:\Apps\app.exe",
            Destination = "example.com",
            PortSpec = "443-8080",
            Action = RuleAction.Deny,
            Lifetime = LifetimeKind.Hours,
            ExpiresUtc = DateTime.UtcNow.AddHours(2),
            WatchPid = 1234,
            Priority = 75,
            Source = "user",
            CreatedUtc = new DateTime(2026, 10, 11, 12, 0, 0, DateTimeKind.Utc),
            ResolvedIps = ["93.184.216.34", "93.184.216.35"],
        };
        var saved = store.Add(rule);
        Assert.True(saved.Id > 0);

        var loaded = store.All().Single();
        Assert.Equal(rule.AppMatcher, loaded.AppMatcher);
        Assert.Equal("example.com", loaded.Destination);
        Assert.Equal("443-8080", loaded.PortSpec);
        Assert.Equal(RuleAction.Deny, loaded.Action);
        Assert.Equal(LifetimeKind.Hours, loaded.Lifetime);
        Assert.NotNull(loaded.ExpiresUtc);
        Assert.True(Math.Abs((loaded.ExpiresUtc!.Value - rule.ExpiresUtc!.Value).TotalSeconds) < 1);
        Assert.Equal(1234, loaded.WatchPid);
        Assert.Equal(75, loaded.Priority);
        Assert.Equal("user", loaded.Source);
        Assert.Equal(rule.CreatedUtc, loaded.CreatedUtc);
        Assert.Equal(["93.184.216.34", "93.184.216.35"], loaded.ResolvedIps);
    }

    [Fact]
    public void Remove_DeletesRule()
    {
        using var store = new RuleStore(_dbPath);
        var saved = store.Add(new Rule { Destination = "any" });
        Assert.True(store.Remove(saved.Id));
        Assert.Empty(store.All());
        Assert.False(store.Remove(saved.Id)); // second remove is a no-op
    }

    [Fact]
    public void NullOptionalFields_RoundTripAsNull()
    {
        using var store = new RuleStore(_dbPath);
        store.Add(new Rule { Destination = "any" }); // AppMatcher/ExpiresUtc/WatchPid/ResolvedIps all null
        var loaded = store.All().Single();
        Assert.Null(loaded.AppMatcher);
        Assert.Null(loaded.ExpiresUtc);
        Assert.Null(loaded.WatchPid);
        Assert.Null(loaded.ResolvedIps);
    }

    public void Dispose()
    {
        // SQLite may briefly hold WAL/SHM handles on Windows even after connection close;
        // retry once, then give up silently (files live in temp).
        foreach (var attempt in new[] { 0, 1 })
        {
            bool allGone = true;
            foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
                if (File.Exists(f))
                    try { File.Delete(f); } catch (IOException) { allGone = false; }
            if (allGone) return;
            GC.Collect(); GC.WaitForPendingFinalizers();
            Thread.Sleep(300);
        }
    }
}
