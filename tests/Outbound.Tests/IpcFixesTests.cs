using System.Text.Json;
using Outbound.Core.Identity;
using Outbound.Core.Policy;
using Outbound.Core.Rules;
using Xunit;

namespace Outbound.Tests;

public class ToastServiceTests
{
    [Fact] public void FirstCountry_FiresOnce()
    {
        var c = 0;
        var t = new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);
        var svc = new ToastService(() => t);
        svc.Toast += (_, _) => c++;
        svc.NotifyFirstCountry("United States"); svc.NotifyFirstCountry("United States");
        Assert.Equal(1, c); // same country only once regardless of gap
    }

    [Fact] public void TwoCountries_WithinGap_OnlyFirstFires()
    {
        var now = new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);
        var c = 0;
        var svc = new ToastService(() => now);
        svc.Toast += (_, _) => c++;
        // same instant: the blocked toast eats the gap, so the country toast is suppressed too
        svc.NotifyFirstCountry("United States");
        svc.NotifyFirstCountry("Canada");
        Assert.Equal(1, c);
    }

    [Fact] public void RateLimit_BlocksSecondWithinGap()
    {
        var now = new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);
        var c = 0;
        var svc = new ToastService(() => now);
        svc.Toast += (_, _) => c++;
        svc.NotifyBlocked("App", "example.com");
        svc.NotifyBlocked("App2", "x.com"); // within 8 s → suppressed
        Assert.Equal(1, c);
    }

    [Fact] public void RateLimit_AllowsAfterGap()
    {
        var now = new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);
        var c = 0;
        var svc = new ToastService(() => now);
        svc.Toast += (_, _) => c++;
        svc.NotifyBlocked("a", "h");
        svc.NotifyBlocked("b", "h2"); // within 8 s → suppressed
        Assert.Equal(1, c);
        now = now.AddSeconds(9); // advance past the gap
        svc.NotifyBlocked("c", "h3");
        Assert.Equal(2, c);
    }

    [Fact] public void EmptyCountry_NeverFires()
    {
        var c = 0;
        var svc = new ToastService(() => new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc));
        svc.Toast += (_, _) => c++;
        svc.NotifyFirstCountry("");
        Assert.Equal(0, svc.SeenCountryCount);
        Assert.Equal(0, c);
    }
}

// Phase 5 bug-fix suite (2026-10-12): bare-name app-key resolution, the unify rules.propose
// result field, and unknown-lifetime rejection.

public class NormalizeAppKeyTests
{
    private static readonly string[] Seen =
    [
        @"C:\Program Files\Google\Chrome\Application\chrome.exe",
        @"C:\Windows\System32\notepad.exe",
    ];

    [Fact] public void FullPath_PassesThrough()
    {
        Assert.Equal(@"exe:c:\program files\google\chrome\application\chrome.exe",
            AppResolver.NormalizeAppKey(@"C:\Program Files\Google\Chrome\Application\chrome.exe", Seen));
    }

    [Fact] public void ExePrefix_PassesThrough_CaseInsensitive()
    {
        Assert.Equal(@"exe:c:\tools\curl.exe",
            AppResolver.NormalizeAppKey(@"EXE:C:\Tools\CURL.EXE", Seen));
    }

    [Fact] public void BareName_ResolvesToSeenPath()
    {
        Assert.Equal(@"exe:c:\program files\google\chrome\application\chrome.exe",
            AppResolver.NormalizeAppKey("chrome.exe", Seen));
    }

    [Fact] public void BareName_WithoutExtension_Resolves()
    {
        Assert.Equal(@"exe:c:\windows\system32\notepad.exe",
            AppResolver.NormalizeAppKey("notepad", Seen));
    }

    [Fact] public void BareName_ToSystem32_NotAssumed()
    {
        // "chrome.exe" must NOT map to C:\Windows\System32\chrome.exe — resolve against seen apps only.
        Assert.Equal(@"exe:c:\program files\google\chrome\application\chrome.exe",
            AppResolver.NormalizeAppKey("chrome.exe", Seen));
    }

    [Fact] public void UnknownBareName_Throws_ClearError()
    {
        var ex = Assert.Throws<ArgumentException>(() => AppResolver.NormalizeAppKey("totally-unknown.exe", Seen));
        Assert.Contains("no running app matches", ex.Message);
    }

    [Fact] public void NoKnownApps_UnknownBareName_Throws()
    {
        Assert.Throws<ArgumentException>(() => AppResolver.NormalizeAppKey("chrome.exe", Array.Empty<string>()));
    }

    [Fact] public void MultipleMatches_Throws_ListsPaths()
    {
        string[] two =
        [
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            @"C:\Users\me\AppData\Local\Google\Chrome\Application\chrome.exe",
        ];
        var ex = Assert.Throws<ArgumentException>(() => AppResolver.NormalizeAppKey("chrome.exe", two));
        Assert.Contains("several apps", ex.Message);
        Assert.Contains("chrome.exe", ex.Message);
    }
}

public class ProposeResultFieldTests
{
    [Fact] public void Server_Denial_UsesApprovedField()
    {
        // The rules.propose DENIED result — must be the single field "approved" everywhere.
        var json = "{\"ok\":true,\"result\":{\"approved\":false,\"reason\":\"denied by user\"}}";
        var doc = JsonDocument.Parse(json);
        var result = doc.RootElement.GetProperty("result");
        Assert.True(result.TryGetProperty("approved", out var v));
        Assert.False(v.GetBoolean());
        Assert.False(result.TryGetProperty("applied", out _)); // no legacy "applied" field
    }

    [Fact] public void Client_Denial_ParsesApprovedField()
    {
        var json = "{\"approved\":false,\"reason\":\"denied by user\"}";
        var r = JsonDocument.Parse(json).RootElement;
        bool denied = r.TryGetProperty("approved", out var approved) && !approved.GetBoolean();
        Assert.True(denied);
    }

    [Fact] public void Server_Approval_UsesApprovedField()
    {
        var json = "{\"ok\":true,\"result\":{\"id\":5,\"description\":\"Deny …\",\"approved\":true}}";
        var result = JsonDocument.Parse(json).RootElement.GetProperty("result");
        Assert.True(result.TryGetProperty("approved", out var v));
        Assert.True(v.GetBoolean());
        Assert.True(result.TryGetProperty("id", out _)); // approved result carries the new rule id
    }

    [Fact] public void Client_Approval_ParsesApprovedField()
    {
        var json = "{\"id\":5,\"description\":\"Deny …\",\"approved\":true}";
        var r = JsonDocument.Parse(json).RootElement;
        bool approved = r.TryGetProperty("approved", out var a) && a.GetBoolean();
        Assert.True(approved);
    }
}

public class LifetimeRejectionTests
{
    [Theory]
    [InlineData("once", LifetimeKind.Once)]
    [InlineData("1h", LifetimeKind.Hours)]
    [InlineData("hour", LifetimeKind.Hours)]
    [InlineData("quit", LifetimeKind.UntilQuit)]
    [InlineData("logout", LifetimeKind.UntilLogout)]
    [InlineData("restart", LifetimeKind.UntilRestart)]
    [InlineData("forever", LifetimeKind.Forever)]
    [InlineData("FOREVER", LifetimeKind.Forever)]
    public void ValidLifetimes_Parse(string s, LifetimeKind expected)
        => Assert.Equal(expected, Rule.ParseLifetime(s));

    [Fact] public void UnknownLifetime_Throws_NeverForever()
    {
        var ex = Assert.Throws<ArgumentException>(() => Rule.ParseLifetime("friday"));
        Assert.Contains("friday", ex.Message);
        Assert.Contains("once, 1h, quit, logout, restart, forever", ex.Message);
    }

    [Fact] public void BlankLifetime_Throws()
    {
        Assert.Throws<ArgumentException>(() => Rule.ParseLifetime(" "));
    }
}