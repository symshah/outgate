namespace Outbound.Core.Identity;

/// <summary>Code-signing identity of a running process's executable.</summary>
public sealed record SigningIdentity(
    string? Publisher,      // e.g. "Microsoft Windows" / "Google LLC"
    string? TeamId,         // not applicable on Windows — kept for parity with macOS design
    bool Signed,
    bool ChainValid,
    string? ExePath);

/// <summary>Legacy facade kept for existing callers; delegates to <see cref="Signer"/> (embedded + catalog).</summary>
public static class ProcessIdentity
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, SigningIdentity> Cache = new();

    public static SigningIdentity Resolve(int pid) => Cache.GetOrAdd(pid, _ =>
    {
        var exe = AppResolver.ExePath(pid);
        if (exe == null) return new SigningIdentity(null, null, false, false, null);
        var (signed, valid, pub) = VerifyAuthenticode(exe);
        return new SigningIdentity(pub, null, signed, valid, exe);
    });

    public static (bool Signed, bool ChainValid, string? Publisher) VerifyAuthenticode(string filePath)
    {
        var s = Signer.Get(filePath);
        bool signed = s.Kind != SignerKind.Unsigned;
        return (signed, signed, signed ? s.Display : null);
    }

    public static void Forget(int pid) => Cache.TryRemove(pid, out _);
}
