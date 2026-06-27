using System.Runtime.InteropServices;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Compares the running version against the latest release from an <see cref="IReleaseSource"/> and,
/// when newer, selects the asset to download for this platform and install channel. Transport/parsing
/// is delegated to the source; callers typically catch exceptions and treat a failed check as "no
/// update" so a network hiccup never blocks startup.
/// </summary>
public sealed class UpdateChecker
{
    private readonly IReleaseSource _source;
    private readonly ReleaseVersion _current;
    private readonly InstallChannel _channel;
    private readonly Architecture _arch;

    public UpdateChecker(IReleaseSource source, ReleaseVersion current, InstallChannel channel, Architecture arch)
    {
        _source = source;
        _current = current;
        _channel = channel;
        _arch = arch;
    }

    public async Task<UpdateInfo> CheckAsync(CancellationToken cancellationToken = default)
    {
        ReleaseInfo? release = await _source.GetLatestAsync(cancellationToken).ConfigureAwait(false);
        if (release is null || release.Version <= _current)
            return UpdateInfo.None(_current);

        ReleaseAsset? asset = UpdateAssetSelector.Select(release.Assets, _channel, _arch);
        return new UpdateInfo
        {
            UpdateAvailable = true,
            CurrentVersion = _current,
            LatestVersion = release.Version,
            ReleaseName = release.Name,
            ReleaseNotes = release.Body,
            ReleaseUrl = release.Url,
            Asset = asset,
        };
    }
}
