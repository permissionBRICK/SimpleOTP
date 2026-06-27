using System.Net.Http;

namespace SimpleOtp.Core.Update;

/// <summary>
/// Downloads a release asset to a local file, reporting 0..1 progress. Follows redirects (GitHub asset
/// URLs redirect to a CDN). The <see cref="HttpMessageHandler"/> is injectable for tests.
/// </summary>
public sealed class UpdateDownloader
{
    private readonly HttpMessageHandler? _handler;

    public UpdateDownloader(HttpMessageHandler? handler = null) => _handler = handler;

    /// <summary>
    /// Downloads <paramref name="url"/> to <paramref name="destinationPath"/>, reporting fractional
    /// progress when the server sends a Content-Length. Returns the destination path. Throws on any
    /// HTTP/IO failure (the partial file is deleted).
    /// </summary>
    public async Task<string> DownloadAsync(string url, string destinationPath,
        IProgress<double>? progress = null, CancellationToken cancellationToken = default)
    {
        bool ownsHandler = _handler is null;
        HttpMessageHandler handler = _handler ?? new HttpClientHandler();
        var client = new HttpClient(handler, disposeHandler: ownsHandler) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("User-Agent", "SimpleOTP-Updater");

            using HttpResponseMessage response = await client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            long? total = response.Content.Headers.ContentLength;

            string? dir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            try
            {
                await using (FileStream file = File.Create(destinationPath))
                await using (Stream net = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
                {
                    byte[] buffer = new byte[81920];
                    long received = 0;
                    int read;
                    while ((read = await net.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        received += read;
                        if (total is > 0)
                            progress?.Report(Math.Clamp((double)received / total.Value, 0, 1));
                    }
                }
                progress?.Report(1);
                return destinationPath;
            }
            catch
            {
                TryDelete(destinationPath);
                throw;
            }
        }
        finally
        {
            client.Dispose();
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }
}
