namespace SimpleOtp.Core.Model;

/// <summary>
/// A recoverable copy of a TOTP secret kept in Advanced Security mode when a master password is set.
/// The secret is encrypted with ECIES (ephemeral ECDH P-256 → SHA-256 KDF → AES-256-GCM) to the
/// vault's export public key. Encrypting needs only the public key (so adding accounts never prompts
/// for the password); decrypting needs the matching private key, which is TPM-sealed under the master
/// password and recovered only when the user explicitly exports.
/// </summary>
/// <param name="EphemeralPublicKey">The sender's one-time ECDH public key (SubjectPublicKeyInfo DER).</param>
/// <param name="Nonce">12-byte AES-GCM nonce.</param>
/// <param name="Tag">16-byte AES-GCM authentication tag.</param>
/// <param name="Ciphertext">The encrypted secret bytes.</param>
public sealed record ExportCopy(byte[] EphemeralPublicKey, byte[] Nonce, byte[] Tag, byte[] Ciphertext);
