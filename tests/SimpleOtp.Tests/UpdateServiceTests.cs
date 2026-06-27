using System.Net.Http;
using SimpleOtp.App.Services;
using SimpleOtp.Core.Update;

namespace SimpleOtp.Tests;

public class UpdateServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _prefsPath;

    public UpdateServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-svc-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
        _prefsPath = Path.Combine(_dir, "update.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    // A release carrying assets for every shipped platform/arch, so the host arch always matches one.
    private static ReleaseInfo Release(string ver) => new(
        ReleaseVersion.Parse(ver), "v" + ver, ver, "release notes", "https://github.com/x/y/releases/tag/v" + ver,
        [
            new ReleaseAsset($"SimpleOTP-{ver}-linux-x64.tar.gz", "https://dl/x64.tgz", 1),
            new ReleaseAsset($"SimpleOTP-{ver}-linux-arm64.tar.gz", "https://dl/arm64.tgz", 1),
            new ReleaseAsset($"SimpleOTP-Setup-{ver}-win-x64.exe", "https://dl/x64.exe", 1),
            new ReleaseAsset($"SimpleOTP-Setup-{ver}-win-arm64.exe", "https://dl/arm64.exe", 1),
        ]);

    private UpdateService Make(ReleaseVersion current, ReleaseInfo? release,
        InstallChannel channel = InstallChannel.Tarball, bool installAutoUpdate = true)
        => new(new FakeSource(release), current,
            new InstallInfo { Channel = channel, AutoUpdate = installAutoUpdate, InstallDir = _dir },
            new UpdatePreferences(_prefsPath));

    [Fact]
    public async Task DevBuild_SkipsCheck()
        => Assert.Null(await Make(new ReleaseVersion(0, 0, 0), Release("1.2.0")).CheckAsync());

    [Fact]
    public async Task Disabled_SkipsCheck()
    {
        UpdateService svc = Make(new ReleaseVersion(1, 0, 0), Release("1.2.0"), installAutoUpdate: false);
        Assert.False(svc.AutoUpdateEnabled);
        Assert.Null(await svc.CheckAsync());
    }

    [Fact]
    public async Task Enabled_NewerRelease_ReturnsInfoWithHostArchAsset()
    {
        UpdateService svc = Make(new ReleaseVersion(1, 0, 0), Release("1.2.0"));
        UpdateInfo? info = await svc.CheckAsync();

        Assert.NotNull(info);
        Assert.True(info!.UpdateAvailable);
        Assert.Equal(new ReleaseVersion(1, 2, 0), info.LatestVersion);
        Assert.NotNull(info.Asset);                  // an asset for the test host's arch was selected
        Assert.True(UpdateService.CanSelfUpdate(info));
    }

    [Fact]
    public async Task UpToDate_ReturnsNull()
        => Assert.Null(await Make(new ReleaseVersion(1, 2, 0), Release("1.2.0")).CheckAsync());

    [Fact]
    public void AutoUpdateOverride_WinsOverInstallerChoice()
    {
        UpdateService svc = Make(new ReleaseVersion(1, 0, 0), null, installAutoUpdate: true);
        Assert.True(svc.AutoUpdateEnabled);
        svc.SetAutoUpdate(false);
        Assert.False(svc.AutoUpdateEnabled);
        svc.SetAutoUpdate(true);
        Assert.True(svc.AutoUpdateEnabled);
    }

    [Fact]
    public async Task FailedCheck_ReturnsNull()
    {
        var svc = new UpdateService(new ThrowingSource(), new ReleaseVersion(1, 0, 0),
            new InstallInfo { Channel = InstallChannel.Tarball, AutoUpdate = true, InstallDir = _dir },
            new UpdatePreferences(_prefsPath));
        Assert.Null(await svc.CheckAsync());
    }

    [Theory]
    [InlineData("../evil.exe", "evil.exe")]
    [InlineData("/etc/passwd", "passwd")]
    [InlineData("a/b/c/payload.zip", "payload.zip")]
    [InlineData("normal.tar.gz", "normal.tar.gz")]
    public void SafeDownloadPath_ReducesToFilenameInsideUpdateDir(string assetName, string expectedFile)
    {
        string updateDir = Path.Combine(_dir, "SimpleOtpUpdate");
        string resolved = UpdateService.SafeDownloadPath(updateDir, assetName);

        Assert.Equal(Path.GetFullPath(updateDir), Path.GetDirectoryName(resolved));
        Assert.Equal(expectedFile, Path.GetFileName(resolved));
        Assert.StartsWith(Path.GetFullPath(updateDir) + Path.DirectorySeparatorChar, resolved);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("/")]
    public void SafeDownloadPath_RejectsInvalidNames(string assetName)
        => Assert.Throws<InvalidOperationException>(() => UpdateService.SafeDownloadPath(Path.Combine(_dir, "u"), assetName));

    private sealed class FakeSource(ReleaseInfo? release) : IReleaseSource
    {
        public Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken = default) => Task.FromResult(release);
    }

    private sealed class ThrowingSource : IReleaseSource
    {
        public Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken = default)
            => throw new HttpRequestException("boom");
    }
}
