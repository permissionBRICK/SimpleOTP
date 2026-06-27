using System.Runtime.InteropServices;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Picks the right release asset for the running platform, CPU architecture and install channel from a
/// release's asset list. Matching is by filename substrings so it tolerates small naming changes, never
/// selects a wrong-architecture asset, and falls back to a sensible per-OS default when the channel is
/// unknown.
/// </summary>
public static class UpdateAssetSelector
{
    /// <summary>Selects the asset for this machine (OS from <see cref="OperatingSystem"/>, <paramref name="arch"/> from the runtime).</summary>
    public static ReleaseAsset? Select(IReadOnlyList<ReleaseAsset> assets, InstallChannel channel, Architecture arch)
        => Select(assets, channel, arch, OperatingSystem.IsWindows());

    internal static ReleaseAsset? Select(IReadOnlyList<ReleaseAsset> assets, InstallChannel channel, Architecture arch, bool isWindows)
    {
        if (assets is null || assets.Count == 0) return null;

        // SimpleOTP ships only x64 and arm64 builds. On any other architecture (x86, arm32, …) there is
        // no compatible asset at all — not even an arch-less one — so report none rather than risk
        // handing back a build that cannot run.
        if (arch is not (Architecture.X64 or Architecture.Arm64)) return null;

        // Extension / keyword sets to look for, most specific first.
        string[] wants = channel switch
        {
            InstallChannel.Inno => [".exe"],
            InstallChannel.Portable => ["portable.zip", ".zip"],
            InstallChannel.Tarball => [".tar.gz", ".tgz"],
            InstallChannel.Deb => [".deb"],
            InstallChannel.Rpm => [".rpm"],
            _ => isWindows ? [".exe", ".zip"] : [".tar.gz", ".deb", ".rpm"],
        };

        foreach (string want in wants)
        {
            ReleaseAsset? archlessMatch = null;
            foreach (ReleaseAsset a in assets)
            {
                if (!MatchesKind(a.Name, want)) continue;
                if (ArchMatches(a.Name, arch)) return a;          // exact kind + arch wins immediately
                if (!HasAnyArchToken(a.Name)) archlessMatch ??= a; // single-arch release: kind match with no arch token
            }
            if (archlessMatch is not null) return archlessMatch;
        }
        return null;
    }

    private static bool MatchesKind(string name, string want)
        => want.StartsWith('.')
            ? name.EndsWith(want, StringComparison.OrdinalIgnoreCase)
            : name.Contains(want, StringComparison.OrdinalIgnoreCase);

    private static bool ArchMatches(string name, Architecture arch) => arch switch
    {
        Architecture.X64 => Has(name, "x64") || Has(name, "amd64") || Has(name, "x86_64"),
        Architecture.Arm64 => Has(name, "arm64") || Has(name, "aarch64"),
        // SimpleOTP only ships x64 and arm64 builds. For any other architecture (x86, arm32, …)
        // no asset matches, so the selector reports no installable asset rather than the wrong one.
        _ => false,
    };

    private static bool HasAnyArchToken(string name)
        => Has(name, "x64") || Has(name, "amd64") || Has(name, "x86_64") || Has(name, "arm64") || Has(name, "aarch64");

    private static bool Has(string haystack, string needle) => haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
