namespace SimpleOtp.Core.Model;

/// <summary>
/// A TOTP shared secret encrypted with AES-256-GCM under the vault's data-encryption key (DEK).
/// The DEK itself never leaves the TPM unsealed except transiently in memory. None of these three
/// fields reveals the secret without the TPM-sealed DEK.
/// </summary>
/// <param name="Nonce">12-byte AES-GCM nonce (unique per secret).</param>
/// <param name="Tag">16-byte AES-GCM authentication tag.</param>
/// <param name="Ciphertext">The encrypted secret bytes.</param>
public sealed record EncryptedSecret(byte[] Nonce, byte[] Tag, byte[] Ciphertext);
