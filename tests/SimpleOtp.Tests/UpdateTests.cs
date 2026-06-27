using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SimpleOtp.Core.Update;

namespace SimpleOtp.Tests;

public class UpdateTests : IDisposable
{
    private readonly string _dir;

    public UpdateTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-upd-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    // --- ReleaseVersion -----------------------------------------------------

    [Theory]
    [InlineData("1.2.3", 1, 2, 3)]
    [InlineData("v1.2.3", 1, 2, 3)]
    [InlineData("V10.0.9", 10, 0, 9)]
    [InlineData("1.2", 1, 2, 0)]
    [InlineData("v2", 2, 0, 0)]
    [InlineData("1.2.3-beta+build", 1, 2, 3)]
    public void Version_Parses(string text, int major, int minor, int patch)
    {
        Assert.True(ReleaseVersion.TryParse(text, out ReleaseVersion v));
        Assert.Equal(new ReleaseVersion(major, minor, patch), v);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abc")]
    [InlineData("v")]
    [InlineData("1.x.3")]
    public void Version_RejectsGarbage(string text) => Assert.False(ReleaseVersion.TryParse(text, out _));

    [Fact]
    public void Version_Compares_PatchAndMissingComponents()
    {
        Assert.True(ReleaseVersion.Parse("1.2.4") > ReleaseVersion.Parse("1.2.3"));
        Assert.True(ReleaseVersion.Parse("1.3.0") > ReleaseVersion.Parse("1.2.9"));
        Assert.True(ReleaseVersion.Parse("2.0.0") > ReleaseVersion.Parse("1.9.9"));
        // "1.2" must equal "1.2.0", not sort below it (the System.Version trap).
        Assert.Equal(ReleaseVersion.Parse("1.2.0"), ReleaseVersion.Parse("1.2"));
        Assert.True(ReleaseVersion.Parse("1.2.0") <= ReleaseVersion.Parse("1.2"));
        Assert.True(ReleaseVersion.Parse("0.0.0").IsZero);
    }

    // --- GitHubReleaseSource ------------------------------------------------

    private const string SampleJson = """
    {
      "tag_name": "v1.2.0",
      "name": "SimpleOTP 1.2.0",
      "draft": false,
      "prerelease": false,
      "body": "release notes here",
      "html_url": "https://github.com/permissionBRICK/SimpleOTP/releases/tag/v1.2.0",
      "assets": [
        { "name": "SimpleOTP-Setup-1.2.0-win-x64.exe", "browser_download_url": "https://dl/win-x64.exe", "size": 1111 },
        { "name": "SimpleOTP-Setup-1.2.0-win-arm64.exe", "browser_download_url": "https://dl/win-arm64.exe", "size": 1112 },
        { "name": "SimpleOTP-1.2.0-win-x64-portable.zip", "browser_download_url": "https://dl/win-x64.zip", "size": 2221 },
        { "name": "SimpleOTP-1.2.0-linux-x64.tar.gz", "browser_download_url": "https://dl/linux-x64.tgz", "size": 3331 },
        { "name": "SimpleOTP-1.2.0-linux-arm64.tar.gz", "browser_download_url": "https://dl/linux-arm64.tgz", "size": 3332 },
        { "name": "simpleotp_1.2.0_amd64.deb", "browser_download_url": "https://dl/amd64.deb", "size": 4441 },
        { "name": "simpleotp_1.2.0_arm64.deb", "browser_download_url": "https://dl/arm64.deb", "size": 4442 },
        { "name": "simpleotp-1.2.0-1.x86_64.rpm", "browser_download_url": "https://dl/x86_64.rpm", "size": 5551 },
        { "name": "simpleotp-1.2.0-1.aarch64.rpm", "browser_download_url": "https://dl/aarch64.rpm", "size": 5552 }
      ]
    }
    """;

    [Fact]
    public async Task GitHub_ParsesRelease_AndSendsUserAgent()
    {
        string? ua = null;
        var handler = new StubHandler(req =>
        {
            ua = req.Headers.TryGetValues("User-Agent", out var v) ? string.Join("", v) : null;
            return Json(HttpStatusCode.OK, SampleJson);
        });

        ReleaseInfo? r = await new GitHubReleaseSource("permissionBRICK", "SimpleOTP", handler).GetLatestAsync();

        Assert.NotNull(r);
        Assert.Equal(new ReleaseVersion(1, 2, 0), r!.Version);
        Assert.Equal("release notes here", r.Body);
        Assert.Equal(9, r.Assets.Count);
        Assert.False(string.IsNullOrEmpty(ua));
    }

    [Fact]
    public async Task GitHub_ReturnsNull_On404()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        ReleaseInfo? r = await new GitHubReleaseSource("o", "r", handler).GetLatestAsync();
        Assert.Null(r);
    }

    [Fact]
    public void GitHub_Parse_SkipsDraftAndUnparsableTag()
    {
        using var draft = JsonDocument.Parse("""{ "tag_name": "v1.0.0", "draft": true }""");
        Assert.Null(GitHubReleaseSource.Parse(draft.RootElement));

        using var noTag = JsonDocument.Parse("""{ "name": "nightly" }""");
        Assert.Null(GitHubReleaseSource.Parse(noTag.RootElement));
    }

    // --- UpdateAssetSelector ------------------------------------------------

    private static IReadOnlyList<ReleaseAsset> SampleAssets()
        => GitHubReleaseSource.Parse(JsonDocument.Parse(SampleJson).RootElement)!.Assets;

    [Theory]
    [InlineData(InstallChannel.Inno, Architecture.X64, "SimpleOTP-Setup-1.2.0-win-x64.exe")]
    [InlineData(InstallChannel.Inno, Architecture.Arm64, "SimpleOTP-Setup-1.2.0-win-arm64.exe")]
    [InlineData(InstallChannel.Portable, Architecture.X64, "SimpleOTP-1.2.0-win-x64-portable.zip")]
    [InlineData(InstallChannel.Tarball, Architecture.X64, "SimpleOTP-1.2.0-linux-x64.tar.gz")]
    [InlineData(InstallChannel.Tarball, Architecture.Arm64, "SimpleOTP-1.2.0-linux-arm64.tar.gz")]
    [InlineData(InstallChannel.Deb, Architecture.X64, "simpleotp_1.2.0_amd64.deb")]
    [InlineData(InstallChannel.Deb, Architecture.Arm64, "simpleotp_1.2.0_arm64.deb")]
    [InlineData(InstallChannel.Rpm, Architecture.X64, "simpleotp-1.2.0-1.x86_64.rpm")]
    [InlineData(InstallChannel.Rpm, Architecture.Arm64, "simpleotp-1.2.0-1.aarch64.rpm")]
    public void Selector_PicksCorrectAsset(InstallChannel channel, Architecture arch, string expected)
    {
        bool isWindows = channel is InstallChannel.Inno or InstallChannel.Portable;
        ReleaseAsset? a = UpdateAssetSelector.Select(SampleAssets(), channel, arch, isWindows);
        Assert.Equal(expected, a?.Name);
    }

    [Fact]
    public void Selector_NeverPicksWrongArch()
    {
        // Only an arm64 tarball present, but we are x64 -> no match (do NOT fall back to arm64).
        var assets = new[] { new ReleaseAsset("SimpleOTP-1.2.0-linux-arm64.tar.gz", "u", 1) };
        Assert.Null(UpdateAssetSelector.Select(assets, InstallChannel.Tarball, Architecture.X64, isWindows: false));
    }

    [Fact]
    public void Selector_UnsupportedArch_ReturnsNull()
    {
        // SimpleOTP ships only x64 + arm64. An x86 (or arm32) machine must NOT get an x64 asset.
        ReleaseAsset? a = UpdateAssetSelector.Select(SampleAssets(), InstallChannel.Inno, Architecture.X86, isWindows: true);
        Assert.Null(a);
    }

    [Fact]
    public void Selector_UnsupportedArch_RejectsEvenArchlessAsset()
    {
        // Even an arch-less ("universal-looking") asset must not be handed to an unsupported arch.
        var assets = new[] { new ReleaseAsset("SimpleOTP-1.2.0.zip", "u", 1) };
        Assert.Null(UpdateAssetSelector.Select(assets, InstallChannel.Portable, Architecture.X86, isWindows: true));
        // ...but a supported arch still accepts it as a single-arch release.
        Assert.NotNull(UpdateAssetSelector.Select(assets, InstallChannel.Portable, Architecture.X64, isWindows: true));
    }

    [Fact]
    public void Selector_FallsBackToArchlessAsset()
    {
        var assets = new[] { new ReleaseAsset("SimpleOTP-1.2.0.tar.gz", "u", 1) };
        ReleaseAsset? a = UpdateAssetSelector.Select(assets, InstallChannel.Tarball, Architecture.X64, isWindows: false);
        Assert.Equal("SimpleOTP-1.2.0.tar.gz", a?.Name);
    }

    [Fact]
    public void Selector_UnknownChannel_UsesOsDefault()
    {
        Assert.Equal("SimpleOTP-Setup-1.2.0-win-x64.exe",
            UpdateAssetSelector.Select(SampleAssets(), InstallChannel.Unknown, Architecture.X64, isWindows: true)?.Name);
        Assert.Equal("SimpleOTP-1.2.0-linux-x64.tar.gz",
            UpdateAssetSelector.Select(SampleAssets(), InstallChannel.Unknown, Architecture.X64, isWindows: false)?.Name);
    }

    // --- UpdateChecker ------------------------------------------------------

    private sealed class FakeSource(ReleaseInfo? release) : IReleaseSource
    {
        public Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken = default) => Task.FromResult(release);
    }

    [Fact]
    public async Task Checker_ReportsUpdate_WhenNewer_AndSelectsAsset()
    {
        ReleaseInfo release = GitHubReleaseSource.Parse(JsonDocument.Parse(SampleJson).RootElement)!;
        var checker = new UpdateChecker(new FakeSource(release), new ReleaseVersion(1, 1, 0), InstallChannel.Tarball, Architecture.X64);

        UpdateInfo info = await checker.CheckAsync();

        Assert.True(info.UpdateAvailable);
        Assert.Equal(new ReleaseVersion(1, 2, 0), info.LatestVersion);
        Assert.Equal("SimpleOTP-1.2.0-linux-x64.tar.gz", info.Asset?.Name);
    }

    [Theory]
    [InlineData("1.2.0")] // same
    [InlineData("1.3.0")] // newer than release
    public async Task Checker_NoUpdate_WhenNotNewer(string current)
    {
        ReleaseInfo release = GitHubReleaseSource.Parse(JsonDocument.Parse(SampleJson).RootElement)!;
        var checker = new UpdateChecker(new FakeSource(release), ReleaseVersion.Parse(current), InstallChannel.Tarball, Architecture.X64);
        Assert.False((await checker.CheckAsync()).UpdateAvailable);
    }

    [Fact]
    public async Task Checker_NoUpdate_WhenSourceEmpty()
    {
        var checker = new UpdateChecker(new FakeSource(null), new ReleaseVersion(1, 0, 0), InstallChannel.Tarball, Architecture.X64);
        Assert.False((await checker.CheckAsync()).UpdateAvailable);
    }

    // --- UpdatePreferences --------------------------------------------------

    [Fact]
    public void Preferences_IgnoreSuppressesSameAndOlder_NotNewer()
    {
        var prefs = new UpdatePreferences(Path.Combine(_dir, "update.json"));
        Assert.Null(prefs.GetIgnoredVersion());
        Assert.True(prefs.ShouldPrompt(new ReleaseVersion(1, 2, 0)));

        prefs.Ignore(new ReleaseVersion(1, 2, 0));

        Assert.Equal(new ReleaseVersion(1, 2, 0), prefs.GetIgnoredVersion());
        Assert.False(prefs.ShouldPrompt(new ReleaseVersion(1, 2, 0))); // dismissed -> indicator only
        Assert.False(prefs.ShouldPrompt(new ReleaseVersion(1, 1, 0))); // older -> never
        Assert.True(prefs.ShouldPrompt(new ReleaseVersion(1, 3, 0)));  // strictly newer -> prompt once
    }

    [Fact]
    public void Preferences_AutoUpdateOverride_RoundTrips_AndKeepsIgnoredVersion()
    {
        var prefs = new UpdatePreferences(Path.Combine(_dir, "update.json"));
        Assert.Null(prefs.GetAutoUpdateOverride()); // unset until the user changes it

        prefs.Ignore(new ReleaseVersion(1, 2, 0));
        prefs.SetAutoUpdate(false);

        Assert.False(prefs.GetAutoUpdateOverride());
        Assert.Equal(new ReleaseVersion(1, 2, 0), prefs.GetIgnoredVersion()); // not clobbered by SetAutoUpdate

        prefs.SetAutoUpdate(true);
        Assert.True(prefs.GetAutoUpdateOverride());
    }

    // --- InstallInfo --------------------------------------------------------

    [Fact]
    public void InstallInfo_ReadsMarker()
    {
        File.WriteAllText(Path.Combine(_dir, InstallInfo.MarkerFileName),
            """{ "channel": "Inno", "scope": "machine", "installDir": "C:/Program Files/SimpleOTP", "autoUpdate": false }""");

        InstallInfo info = InstallInfo.Load(_dir);

        Assert.Equal(InstallChannel.Inno, info.Channel);
        Assert.Equal("machine", info.Scope);
        Assert.True(info.RequiresElevation);
        Assert.Equal("C:/Program Files/SimpleOTP", info.InstallDir);
        Assert.False(info.AutoUpdate);
    }

    [Fact]
    public void InstallInfo_AutoUpdate_DefaultsTrue_WhenOmitted()
    {
        File.WriteAllText(Path.Combine(_dir, InstallInfo.MarkerFileName), """{ "channel": "Inno" }""");
        Assert.True(InstallInfo.Load(_dir).AutoUpdate);
    }

    [Fact]
    public void InstallInfo_MissingMarker_FallsBackToOsDefault()
    {
        InstallInfo info = InstallInfo.Load(_dir); // empty dir
        Assert.Equal(OperatingSystem.IsWindows() ? InstallChannel.Portable : InstallChannel.Tarball, info.Channel);
        Assert.False(info.RequiresElevation);
        Assert.True(info.AutoUpdate);
        Assert.Equal(_dir, info.InstallDir);
    }

    // --- UpdateDownloader ---------------------------------------------------

    [Fact]
    public async Task Downloader_WritesFile_AndReportsProgress()
    {
        byte[] payload = Encoding.UTF8.GetBytes(new string('x', 100_000));
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload),
        });

        string dest = Path.Combine(_dir, "asset.bin");
        // Progress<T> posts callbacks asynchronously, so capture synchronously via a custom IProgress.
        var sync = new SyncProgress();

        string path = await new UpdateDownloader(handler).DownloadAsync("https://dl/asset.bin", dest, sync);

        Assert.Equal(dest, path);
        Assert.Equal(payload, await File.ReadAllBytesAsync(dest));
        Assert.Equal(1.0, sync.Last, 3);
    }

    private sealed class SyncProgress : IProgress<double>
    {
        public double Last { get; private set; }
        public void Report(double value) => Last = value;
    }

    // --- helpers ------------------------------------------------------------

    private static HttpResponseMessage Json(HttpStatusCode code, string body)
        => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }
}
