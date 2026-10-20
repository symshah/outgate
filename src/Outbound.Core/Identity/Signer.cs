using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Outbound.Core.Identity;

public enum SignerKind { Unsigned, Named, Microsoft }

public sealed record SignerInfo(SignerKind Kind, string? Publisher, bool CatalogSigned)
{
    public static readonly SignerInfo None = new(SignerKind.Unsigned, null, false);
    public string Display => Kind switch
    {
        SignerKind.Microsoft => CatalogSigned ? "Microsoft Windows" : (Publisher ?? "Microsoft"),
        SignerKind.Named => Publisher!,
        _ => "Unsigned",
    };
}

/// <summary>
/// Authenticode via WinVerifyTrust (wintrust.h): embedded signature first, then catalog signature
/// (CryptCATAdminAcquireContext2 / CalcHashFromFileHandle2 / EnumCatalogFromHash, WTD_CHOICE_CATALOG),
/// so in-box Windows binaries report "Microsoft Windows" instead of "unsigned".
/// </summary>
public static class Signer
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SignerInfo> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static SignerInfo Get(string? path) =>
        string.IsNullOrEmpty(path) || !File.Exists(path) ? SignerInfo.None : Cache.GetOrAdd(path, Verify);

    private static SignerInfo Verify(string path)
    {
        // Catalog first, like Get-AuthenticodeSignature: in-box binaries carry both and the catalog
        // signer ("Microsoft Windows") is the one Windows itself reports.
        var pub = VerifyCatalog(path);
        bool catalog = pub != null;
        pub ??= VerifyEmbedded(path);
        if (pub == null) return SignerInfo.None;
        return new SignerInfo(IsMicrosoft(pub) ? SignerKind.Microsoft : SignerKind.Named, pub, catalog);
    }

    public static bool IsMicrosoft(string publisher) =>
        publisher.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase) || publisher.Equals("Microsoft", StringComparison.OrdinalIgnoreCase);

    // ---- wintrust.h ----
    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO { public uint cbStruct; public IntPtr pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct; public uint dwCatalogVersion; public IntPtr pcwszCatalogFilePath; public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath; public IntPtr hMemberFile; public IntPtr pbCalculatedFileHash; public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext; public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice;
        public uint fdwRevocationChecks; public uint dwUnionChoice; public IntPtr pInfo; public uint dwStateAction;
        public IntPtr hWVTStateData; public IntPtr pwszURLReference; public uint dwProvFlags; public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, bool fCounterSigner, uint idxCounterSigner);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);
    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)] private static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint cbHash, byte[]? pbHash, uint dwFlags);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    private static string? VerifyEmbedded(string path)
    {
        IntPtr pPath = Marshal.StringToHGlobalUni(path);
        var fi = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pPath };
        IntPtr pFi = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fi, pFi, false);
            return RunTrust(WTD_CHOICE_FILE, pFi);
        }
        finally { Marshal.FreeHGlobal(pFi); Marshal.FreeHGlobal(pPath); }
    }

    private static string? VerifyCatalog(string path)
    {
        foreach (var alg in new[] { "SHA256", null }) // null = SHA1 (older catalogs)
        {
            if (!CryptCATAdminAcquireContext2(out var hAdmin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
            IntPtr hCat = IntPtr.Zero;
            try
            {
                byte[] hash;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    uint cb = 0;
                    CryptCATAdminCalcHashFromFileHandle2(hAdmin, fs.SafeFileHandle, ref cb, null, 0);
                    if (cb == 0) continue;
                    hash = new byte[cb];
                    if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin, fs.SafeFileHandle, ref cb, hash, 0)) continue;
                }
                hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, (uint)hash.Length, 0, IntPtr.Zero);
                if (hCat == IntPtr.Zero) continue;
                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCat, ref ci, 0)) continue;

                string tag = Convert.ToHexString(hash);
                IntPtr pCatFile = Marshal.StringToHGlobalUni(ci.wszCatalogFile), pTag = Marshal.StringToHGlobalUni(tag), pMember = Marshal.StringToHGlobalUni(path);
                IntPtr pHash = Marshal.AllocHGlobal(hash.Length);
                IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                try
                {
                    Marshal.Copy(hash, 0, pHash, hash.Length);
                    var info = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), pcwszCatalogFilePath = pCatFile, pcwszMemberTag = pTag,
                        pcwszMemberFilePath = pMember, pbCalculatedFileHash = pHash, cbCalculatedFileHash = (uint)hash.Length, hCatAdmin = hAdmin,
                    };
                    Marshal.StructureToPtr(info, pInfo, false);
                    var pub = RunTrust(WTD_CHOICE_CATALOG, pInfo);
                    if (pub != null) return pub;
                }
                finally
                {
                    Marshal.FreeHGlobal(pInfo); Marshal.FreeHGlobal(pHash);
                    Marshal.FreeHGlobal(pCatFile); Marshal.FreeHGlobal(pTag); Marshal.FreeHGlobal(pMember);
                }
            }
            catch { }
            finally
            {
                if (hCat != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
                CryptCATAdminReleaseContext(hAdmin, 0);
            }
        }
        return null;
    }

    /// <summary>WinVerifyTrust with STATEACTION_VERIFY, read the leaf signer cert, then STATEACTION_CLOSE.</summary>
    private static string? RunTrust(uint unionChoice, IntPtr pInfo)
    {
        var wd = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice, pInfo = pInfo, dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        };
        int rc = WinVerifyTrust(new IntPtr(-1) /* INVALID_HANDLE_VALUE: no UI */, ref GenericVerifyV2, ref wd);
        string? publisher = null;
        try
        {
            if (rc == 0 && wd.hWVTStateData != IntPtr.Zero)
            {
                IntPtr prov = WTHelperProvDataFromStateData(wd.hWVTStateData);
                IntPtr sgnr = prov == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                IntPtr provCert = sgnr == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvCertFromChain(sgnr, 0);
                if (provCert != IntPtr.Zero)
                {
                    // CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... } — pCert is pointer-aligned.
                    IntPtr pCert = Marshal.ReadIntPtr(provCert, IntPtr.Size);
                    using var cert = new X509Certificate2(pCert);
                    publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
                }
                publisher ??= "(signed)";
            }
        }
        catch { publisher ??= rc == 0 ? "(signed)" : null; }
        finally
        {
            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref GenericVerifyV2, ref wd);
        }
        return publisher;
    }
}
