using SimpleOtp.Core.Crypto;

namespace SimpleOtp.Core.Model;

/// <summary>
/// One TOTP account. All metadata is stored in cleartext so the list can render without unlocking;
/// only the shared seed is protected. How it is protected depends on the vault's
/// <see cref="SecurityMode"/>:
///   * Simple — <see cref="Secret"/> holds AES-GCM ciphertext under the vault DEK.
///   * Advanced — <see cref="HmacKey"/> holds the non-exportable TPM HMAC key; <see cref="ExportCopy"/>
///     holds an optional recoverable copy (present only when a master password is set).
/// </summary>
public sealed class Account
{
    public string Id { get; init; } = Guid.NewGuid().ToString("n");

    /// <summary>Service / provider name, e.g. "GitHub". May be empty.</summary>
    public string Issuer { get; set; } = "";

    /// <summary>Account identifier within the issuer, e.g. "alice@example.com".</summary>
    public string Label { get; set; } = "";

    /// <summary>
    /// Id of the <see cref="Folder"/> this account is filed under, or null for the top-level
    /// (uncategorized) list. Organizational only — it does not change how the secret is protected,
    /// but the UI only generates codes for the open folder, so foldering keeps large vaults responsive.
    /// </summary>
    public string? FolderId { get; set; }

    public OtpAlgorithm Algorithm { get; set; } = OtpAlgorithm.Sha1;

    /// <summary>Number of digits in the generated code (commonly 6, sometimes 8).</summary>
    public int Digits { get; set; } = 6;

    /// <summary>Time step in seconds (commonly 30).</summary>
    public int Period { get; set; } = 30;

    /// <summary>Simple mode: the AES-GCM encrypted shared secret (under the vault DEK). Null in Advanced mode.</summary>
    public EncryptedSecret? Secret { get; set; }

    /// <summary>Advanced mode: the non-exportable TPM HMAC key for this account. Null in Simple mode.</summary>
    public SealedBlob? HmacKey { get; set; }

    /// <summary>
    /// Advanced mode + master password: a recoverable copy of the secret, encrypted to the vault's
    /// export public key. Null when no master password is set (then the secret cannot be exported).
    /// </summary>
    public ExportCopy? ExportCopy { get; set; }

    /// <summary>A friendly one-line title for display.</summary>
    public string DisplayName =>
        string.IsNullOrWhiteSpace(Issuer) ? (string.IsNullOrWhiteSpace(Label) ? "(unnamed)" : Label)
        : string.IsNullOrWhiteSpace(Label) ? Issuer
        : $"{Issuer} ({Label})";
}
