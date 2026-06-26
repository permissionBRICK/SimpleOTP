namespace SimpleOtp.Core.Model;

/// <summary>
/// Configuration for network auto-unlock (BitLocker-Network-Unlock style, without certificates).
/// The app calls <see cref="Url"/> with the <see cref="AppKey"/> in a header; the response body is
/// the auto-unlock secret used to unseal a second copy of the vault key from the TPM.
///
/// This object is persisted in the vault file. It deliberately does NOT contain the auto-unlock
/// secret itself — that lives only in the (user-operated) webservice and is fetched at unlock time.
/// </summary>
public sealed class AutoUnlockConfig
{
    public bool Enabled { get; set; }

    /// <summary>Full http:// or https:// URL of the unlock webservice.</summary>
    public string Url { get; set; } = "";

    /// <summary>Opaque token sent to the webservice to authenticate this app.</summary>
    public string AppKey { get; set; } = "";

    /// <summary>HTTP header the app key is sent in (default <c>X-App-Key</c>).</summary>
    public string AppKeyHeader { get; set; } = "X-App-Key";

    /// <summary>HTTP method to use (GET or POST; default POST).</summary>
    public string Method { get; set; } = "POST";

    /// <summary>
    /// Optional: for an https URL with a self-signed/local cert, pin the server certificate by its
    /// SHA-256 thumbprint (hex). When set, the cert must match exactly. Ignored for http URLs.
    /// </summary>
    public string? PinnedServerCertSha256 { get; set; }

    /// <summary>
    /// Optional, insecure: accept any server certificate for an https URL (skip validation).
    /// Only for local development; prefer pinning.
    /// </summary>
    public bool AllowUntrustedServerCert { get; set; }

    /// <summary>Request timeout in seconds.</summary>
    public int TimeoutSeconds { get; set; } = 5;
}
