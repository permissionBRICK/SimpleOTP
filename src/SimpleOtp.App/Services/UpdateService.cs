using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.Services;

/// <summary>
/// App-facing wrapper over the <see cref="SimpleOtp.Core.Update"/> module. Resolves the running
/// version and install channel, applies the dev-build and auto-update-disabled guards, checks GitHub,
/// and drives the download + platform-specific apply/restart. Constructor dependencies are injectable
/// for testing; production uses the defaults (GitHub + this app's assembly + the on-disk marker/prefs).
/// </summary>
public sealed class UpdateService
{
    public const string RepoOwner = "permissionBRICK";
    public const string RepoName = "SimpleOTP";

    private readonly ReleaseVersion _current;
    private readonly InstallInfo _install;
    private readonly UpdatePreferences _prefs;
    private readonly IReleaseSource _source;

    public UpdateService(
        IReleaseSource? source = null,
        ReleaseVersion? current = null,
        InstallInfo? install = null,
        UpdatePreferences? prefs = null)
    {
        _current = current ?? CurrentVersion();
        _install = install ?? InstallInfo.Load();
        _prefs = prefs ?? new UpdatePreferences();
        _source = source ?? new GitHubReleaseSource(RepoOwner, RepoName);
    }

    public ReleaseVersion CurrentAppVersion => _current;
    public InstallChannel Channel => _install.Channel;

    /// <summary>Effective auto-update setting: the user's in-app override wins, else the installer's initial choice.</summary>
    public bool AutoUpdateEnabled => _prefs.GetAutoUpdateOverride() ?? _install.AutoUpdate;

    /// <summary>Records the user's auto-update on/off choice (overrides the installer's initial value).</summary>
    public void SetAutoUpdate(bool enabled) => _prefs.SetAutoUpdate(enabled);

    /// <summary>
    /// Checks GitHub for a newer release. Returns null (no update / don't bother) when this is an
    /// unstamped dev build, when auto-update is disabled, on any network/parse error, or when already
    /// current. Never throws — a failed check must not disrupt startup.
    /// </summary>
    public async Task<UpdateInfo?> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (_current.IsZero) return null;     // unstamped local/dev build
        if (!AutoUpdateEnabled) return null;  // disabled by the user or at install time
        try
        {
            var checker = new UpdateChecker(_source, _current, _install.Channel, RuntimeInformation.ProcessArchitecture);
            UpdateInfo info = await checker.CheckAsync(cancellationToken).ConfigureAwait(false);
            return info.UpdateAvailable ? info : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Whether a found update should pop up (vs. only show the indicator); see <see cref="UpdatePreferences"/>.</summary>
    public bool ShouldPrompt(ReleaseVersion latest) => _prefs.ShouldPrompt(latest);

    /// <summary>Marks the version as ignored so it stops prompting (the indicator stays until the user updates).</summary>
    public void Ignore(ReleaseVersion version) => _prefs.Ignore(version);

    /// <summary>True if a one-click in-app update is possible for this platform/channel (a matching asset exists).</summary>
    public static bool CanSelfUpdate(UpdateInfo info) => info.Asset is not null;

    /// <summary>
    /// Downloads the update asset to a temp folder and launches the platform updater (silent installer
    /// re-run / file swap / package install). On return the caller MUST shut the app down so the updater
    /// can replace files and relaunch.
    /// </summary>
    public async Task DownloadAndApplyAsync(UpdateInfo info, IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        if (info.Asset is null)
            throw new InvalidOperationException("No downloadable asset is available for this platform.");

        string dir = Path.Combine(Path.GetTempPath(), "SimpleOtpUpdate");
        Directory.CreateDirectory(dir);
        // The asset name is attacker-influenceable release metadata; never let it steer the write path.
        string dest = SafeDownloadPath(dir, info.Asset.Name);

        await new UpdateDownloader().DownloadAsync(info.Asset.DownloadUrl, dest, progress, cancellationToken).ConfigureAwait(false);
        UpdateApplier.Launch(_install, dest);
    }

    /// <summary>
    /// Resolves the local download path for an asset, reducing the (untrusted) asset name to a bare
    /// filename and verifying the result stays inside <paramref name="updateDir"/>. Rejects empty,
    /// rooted, or traversal names so a malicious release cannot write outside the update directory.
    /// </summary>
    internal static string SafeDownloadPath(string updateDir, string assetName)
    {
        string fileName = Path.GetFileName(assetName);
        if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or "..")
            throw new InvalidOperationException("The update asset has an invalid file name.");

        string root = Path.GetFullPath(updateDir);
        string full = Path.GetFullPath(Path.Combine(root, fileName));
        if (full != root && !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidOperationException("The update asset path escapes the update directory.");
        return full;
    }

    /// <summary>Reads this app's version from its assembly metadata (stamped by CI via -p:Version=).</summary>
    private static ReleaseVersion CurrentVersion()
    {
        Assembly asm = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        string? informational = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (informational is not null && ReleaseVersion.TryParse(informational, out ReleaseVersion v))
            return v;
        Version? assemblyVersion = asm.GetName().Version;
        return assemblyVersion is not null
            ? new ReleaseVersion(assemblyVersion.Major, assemblyVersion.Minor, Math.Max(0, assemblyVersion.Build))
            : default;
    }
}
