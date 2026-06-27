using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Reads the latest stable release of a public GitHub repository via the REST API
/// (<c>/repos/{owner}/{repo}/releases/latest</c>, which excludes drafts and pre-releases). No auth
/// token is required for public repos. The <see cref="HttpMessageHandler"/> is injectable for tests.
/// </summary>
public sealed class GitHubReleaseSource : IReleaseSource
{
    private readonly string _owner;
    private readonly string _repo;
    private readonly HttpMessageHandler? _handler;

    public GitHubReleaseSource(string owner, string repo, HttpMessageHandler? handler = null)
    {
        _owner = owner;
        _repo = repo;
        _handler = handler;
    }

    public async Task<ReleaseInfo?> GetLatestAsync(CancellationToken cancellationToken = default)
    {
        bool ownsHandler = _handler is null;
        HttpMessageHandler handler = _handler ?? new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All };
        var client = new HttpClient(handler, disposeHandler: ownsHandler) { Timeout = TimeSpan.FromSeconds(15) };
        try
        {
            string url = $"https://api.github.com/repos/{_owner}/{_repo}/releases/latest";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            // GitHub requires a User-Agent; the other two headers pin the API behaviour/version.
            request.Headers.TryAddWithoutValidation("User-Agent", "SimpleOTP-Updater");
            request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");

            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return null; // repo has no published (non-draft, non-prerelease) release yet
            response.EnsureSuccessStatusCode();

            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return Parse(doc.RootElement);
        }
        finally
        {
            client.Dispose();
        }
    }

    /// <summary>Maps a GitHub release JSON object to <see cref="ReleaseInfo"/>; null if it is a draft or has no parsable tag.</summary>
    internal static ReleaseInfo? Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        if (root.TryGetProperty("draft", out JsonElement draft) && draft.ValueKind == JsonValueKind.True) return null;

        string tag = GetString(root, "tag_name");
        if (!ReleaseVersion.TryParse(tag, out ReleaseVersion version)) return null;

        string name = root.TryGetProperty("name", out JsonElement n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : tag;
        string body = GetString(root, "body");
        string htmlUrl = GetString(root, "html_url");

        var assets = new List<ReleaseAsset>();
        if (root.TryGetProperty("assets", out JsonElement arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement a in arr.EnumerateArray())
            {
                string an = GetString(a, "name");
                string ad = GetString(a, "browser_download_url");
                long size = a.TryGetProperty("size", out JsonElement se) && se.TryGetInt64(out long sz) ? sz : 0;
                if (an.Length > 0 && ad.Length > 0)
                    assets.Add(new ReleaseAsset(an, ad, size));
            }
        }
        return new ReleaseInfo(version, tag, name, body, htmlUrl, assets);
    }

    private static string GetString(JsonElement obj, string prop)
        => obj.TryGetProperty(prop, out JsonElement e) && e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
}
