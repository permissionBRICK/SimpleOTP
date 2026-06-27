namespace SimpleOtp.Core.Update;

/// <summary>A published release as reported by an <see cref="IReleaseSource"/>.</summary>
public sealed record ReleaseInfo(
    ReleaseVersion Version,
    string TagName,
    string Name,
    string Body,
    string Url,
    IReadOnlyList<ReleaseAsset> Assets);

/// <summary>A downloadable file attached to a release.</summary>
public sealed record ReleaseAsset(string Name, string DownloadUrl, long Size);

/// <summary>
/// Source of the latest published release. Abstracted from the concrete GitHub implementation so the
/// <see cref="UpdateChecker"/> is unit-testable without HTTP.
/// </summary>
public interface IReleaseSource
{
    /// <summary>
    /// Returns the latest stable release, or null when there is none / the tag is unparsable. Throws on
    /// transport errors (callers typically treat a thrown check as "no update" so a network hiccup never
    /// blocks startup).
    /// </summary>
    Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken = default);
}
