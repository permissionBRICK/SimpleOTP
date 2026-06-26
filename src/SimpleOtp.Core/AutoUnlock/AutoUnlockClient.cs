using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.AutoUnlock;

/// <summary>
/// Fetches the auto-unlock secret from a user-operated webservice (BitLocker-Network-Unlock style).
///
/// Contract for the webservice (which the user implements):
///   * The app sends an HTTP request (method/headers per <see cref="AutoUnlockConfig"/>) to the URL,
///     including the app key in the configured header (default <c>X-App-Key</c>).
///   * On success the service responds <c>200 OK</c> with the auto-unlock secret as the response
///     body (UTF-8 text; trailing whitespace is trimmed). Those bytes are the TPM auth value.
///   * Any non-2xx response, network failure, or empty body means auto-unlock is unavailable; the
///     app falls back to the PIN.
/// </summary>
public static class AutoUnlockClient
{
    /// <summary>
    /// Calls the configured webservice and returns the auto-unlock secret bytes. The caller is
    /// responsible for zeroing the returned buffer. Throws on any failure.
    /// </summary>
    /// <param name="handler">Test seam: inject an <see cref="HttpMessageHandler"/>; null builds one.</param>
    public static async Task<byte[]> FetchKeyAsync(
        AutoUnlockConfig config, HttpMessageHandler? handler = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(config.Url);

        bool ownsHandler = handler is null;
        HttpMessageHandler effectiveHandler = handler ?? CreateHandler(config);
        var client = new HttpClient(effectiveHandler, disposeHandler: ownsHandler)
        {
            Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds > 0 ? config.TimeoutSeconds : 5),
        };
        try
        {
            var method = new HttpMethod(string.IsNullOrWhiteSpace(config.Method) ? "POST" : config.Method.ToUpperInvariant());
            using var request = new HttpRequestMessage(method, config.Url);
            string header = string.IsNullOrWhiteSpace(config.AppKeyHeader) ? "X-App-Key" : config.AppKeyHeader;
            if (!string.IsNullOrEmpty(config.AppKey))
                request.Headers.TryAddWithoutValidation(header, config.AppKey);
            request.Headers.TryAddWithoutValidation("Accept", "text/plain");

            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            byte[] secret = Encoding.UTF8.GetBytes(body.Trim());
            if (secret.Length == 0)
                throw new InvalidOperationException("The auto-unlock service returned an empty key.");
            return secret;
        }
        finally
        {
            client.Dispose();
        }
    }

    private static HttpClientHandler CreateHandler(AutoUnlockConfig config)
    {
        var handler = new HttpClientHandler();
        bool isHttps = config.Url.StartsWith("https", StringComparison.OrdinalIgnoreCase);
        bool wantsCustomValidation = isHttps &&
            (config.AllowUntrustedServerCert || !string.IsNullOrWhiteSpace(config.PinnedServerCertSha256));

        if (wantsCustomValidation)
        {
            string? pinned = NormalizeThumbprint(config.PinnedServerCertSha256);
            bool allowAny = config.AllowUntrustedServerCert;
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            {
                if (allowAny) return true;
                if (cert is null) return false;
                if (pinned is null)
                    return errors == System.Net.Security.SslPolicyErrors.None;
                string actual = Convert.ToHexString(SHA256.HashData(cert.RawData));
                return string.Equals(actual, pinned, StringComparison.OrdinalIgnoreCase);
            };
        }
        return handler;
    }

    private static string? NormalizeThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            if (Uri.IsHexDigit(c)) sb.Append(c);
        return sb.Length == 0 ? null : sb.ToString();
    }
}
