using System.Security.Cryptography;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Crypto;

/// <summary>
/// Envelope-encryption vault. A single random 32-byte data-encryption key (DEK) is sealed to the
/// TPM (optionally behind a PIN). Each account's secret is encrypted with AES-256-GCM under that
/// DEK. The DEK is only held in memory while the vault is unlocked, and is zeroed on lock/dispose.
///
/// Device binding: the sealed DEK can only be unsealed by the TPM that created it, so a copied
/// vault file is inert on any other machine.
/// </summary>
public sealed class Vault : IDisposable
{
    private const int DekSize = 32;     // AES-256
    private const int NonceSize = 12;   // AES-GCM standard nonce
    private const int TagSize = 16;     // AES-GCM tag

    private readonly ISecretSealer _sealer;
    private byte[]? _dek;               // null when locked

    private Vault(ISecretSealer sealer, SealedBlob sealedDek, bool pinProtected)
    {
        _sealer = sealer;
        SealedDek = sealedDek;
        PinProtected = pinProtected;
    }

    /// <summary>The TPM-sealed DEK blob; persisted in the vault file.</summary>
    public SealedBlob SealedDek { get; private set; }

    /// <summary>Whether a non-empty PIN is required to unlock.</summary>
    public bool PinProtected { get; private set; }

    public bool IsUnlocked => _dek is not null;

    /// <summary>
    /// Creates a brand-new vault: generates a fresh DEK and seals it behind <paramref name="pin"/>
    /// (empty = no PIN). The returned vault is already unlocked.
    /// </summary>
    public static Vault Create(ISecretSealer sealer, ReadOnlySpan<byte> pin)
    {
        byte[] dek = sealer.GetRandomBytes(DekSize);
        try
        {
            SealedBlob sealed_ = sealer.Seal(dek, pin);
            var vault = new Vault(sealer, sealed_, pin.Length > 0)
            {
                _dek = (byte[])dek.Clone(),
            };
            return vault;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    /// <summary>Reopens an existing (locked) vault from a persisted sealed DEK.</summary>
    public static Vault Open(ISecretSealer sealer, SealedBlob sealedDek, bool pinProtected)
        => new(sealer, sealedDek, pinProtected);

    /// <summary>
    /// Unlocks the vault by unsealing the DEK with <paramref name="pin"/> (empty when no PIN).
    /// </summary>
    /// <exception cref="WrongPinException">PIN was wrong.</exception>
    /// <exception cref="WrongDeviceException">Vault belongs to a different TPM.</exception>
    public void Unlock(ReadOnlySpan<byte> pin) => UnlockFrom(SealedDek, pin);

    /// <summary>
    /// Unlocks the vault by unsealing a specific sealed blob with <paramref name="auth"/>. Used for
    /// the auto-unlock blob, which holds the same DEK sealed under the auto-unlock secret.
    /// </summary>
    public void UnlockFrom(SealedBlob blob, ReadOnlySpan<byte> auth)
    {
        byte[] dek = _sealer.Unseal(blob, auth);
        if (dek.Length != DekSize)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new SealerException($"Unsealed DEK had unexpected length {dek.Length}.");
        }
        Lock();
        _dek = dek;
    }

    /// <summary>
    /// Seals the current (unlocked) DEK under a different auth value, producing an additional sealed
    /// blob. Used to add an auto-unlock copy alongside the PIN copy. Requires the vault to be unlocked.
    /// </summary>
    public SealedBlob SealCurrentUnder(ReadOnlySpan<byte> auth)
    {
        EnsureUnlocked();
        return _sealer.Seal(_dek!, auth);
    }

    public void Lock()
    {
        if (_dek is not null)
        {
            CryptographicOperations.ZeroMemory(_dek);
            _dek = null;
        }
    }

    /// <summary>
    /// "Unlocks" a legacy Advanced vault that predates the vault-key gate: it has no sealed key and its
    /// HMAC keys were created with empty auth, so the in-memory key is empty and HMAC operations present
    /// empty auth. There is nothing to unseal, so this can't fail.
    /// </summary>
    public void UnlockLegacy()
    {
        Lock();
        _dek = Array.Empty<byte>();
    }

    /// <summary>
    /// Advanced mode: imports a TOTP secret into the TPM as a non-exportable HMAC key, locked under the
    /// vault key. Requires the vault to be unlocked.
    /// </summary>
    public SealedBlob ImportHmacKey(ReadOnlySpan<byte> secret, OtpAlgorithm algorithm)
    {
        EnsureUnlocked();
        return _sealer.ImportHmacKey(secret, algorithm, _dek!);
    }

    /// <summary>
    /// Advanced mode: computes a TOTP HMAC inside the TPM from a key produced by
    /// <see cref="ImportHmacKey"/>, presenting the vault key as auth. Requires the vault to be unlocked.
    /// </summary>
    public byte[] ComputeHmac(SealedBlob hmacKey, ReadOnlySpan<byte> data, OtpAlgorithm algorithm)
    {
        EnsureUnlocked();
        return _sealer.ComputeHmac(hmacKey, data, algorithm, _dek!);
    }

    /// <summary>Encrypts a plaintext secret under the DEK. Requires the vault to be unlocked.</summary>
    public EncryptedSecret Encrypt(ReadOnlySpan<byte> plaintext)
    {
        EnsureUnlocked();
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] tag = new byte[TagSize];
        byte[] ciphertext = new byte[plaintext.Length];
        using var gcm = new AesGcm(_dek!, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);
        return new EncryptedSecret(nonce, tag, ciphertext);
    }

    /// <summary>
    /// Decrypts a secret. The returned buffer is the caller's responsibility to zero after use
    /// (see <see cref="VaultService"/>).
    /// </summary>
    public byte[] Decrypt(EncryptedSecret secret)
    {
        EnsureUnlocked();
        byte[] plaintext = new byte[secret.Ciphertext.Length];
        using var gcm = new AesGcm(_dek!, TagSize);
        try
        {
            gcm.Decrypt(secret.Nonce, secret.Ciphertext, secret.Tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new SealerException("Secret failed authenticated decryption (tampered or corrupt vault).", ex);
        }
        return plaintext;
    }

    /// <summary>
    /// Re-seals the existing DEK under a new PIN (empty = remove PIN). The DEK value is unchanged so
    /// all existing account ciphertexts remain valid. Requires the vault to be unlocked.
    /// </summary>
    public void ChangePin(ReadOnlySpan<byte> newPin)
    {
        EnsureUnlocked();
        SealedDek = _sealer.Seal(_dek!, newPin);
        PinProtected = newPin.Length > 0;
    }

    private void EnsureUnlocked()
    {
        if (_dek is null)
            throw new InvalidOperationException("Vault is locked.");
    }

    public void Dispose() => Lock();
}
