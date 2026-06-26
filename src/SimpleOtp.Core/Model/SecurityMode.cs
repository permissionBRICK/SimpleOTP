namespace SimpleOtp.Core.Model;

/// <summary>
/// How a vault protects its TOTP secrets.
/// </summary>
public enum SecurityMode
{
    /// <summary>
    /// Simple Security: a TPM-sealed data-encryption key (DEK) protects per-account secrets that are
    /// AES-GCM ciphertext on disk. The DEK is unsealed into memory to generate codes, so a secret is
    /// briefly in RAM and can be exported freely. Device-bound and optionally PIN-gated.
    /// </summary>
    Simple,

    /// <summary>
    /// Advanced Security: each TOTP secret is imported into the TPM as a non-exportable HMAC key, and
    /// the HMAC is computed inside the chip — only the code comes out, never the seed. Codes and new
    /// accounts need no secret. Exporting the seeds is only possible if a master password was set (a
    /// recoverable copy is then kept, encrypted to a key sealed under that password).
    /// </summary>
    Advanced,
}
