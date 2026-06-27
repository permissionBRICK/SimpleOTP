namespace SimpleOtp.Core.Update;

/// <summary>Result of an update check.</summary>
public sealed record UpdateInfo
{
    /// <summary>True when the latest release is newer than the running version.</summary>
    public required bool UpdateAvailable { get; init; }

    public required ReleaseVersion CurrentVersion { get; init; }
    public ReleaseVersion LatestVersion { get; init; }
    public string? ReleaseName { get; init; }
    public string? ReleaseNotes { get; init; }
    public string? ReleaseUrl { get; init; }

    /// <summary>The asset matched for this platform/channel. Null means an update exists but no installable asset was found (offer the release page instead).</summary>
    public ReleaseAsset? Asset { get; init; }

    public static UpdateInfo None(ReleaseVersion current) => new() { UpdateAvailable = false, CurrentVersion = current };
}
