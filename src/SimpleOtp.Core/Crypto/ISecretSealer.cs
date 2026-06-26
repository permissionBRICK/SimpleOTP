using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Crypto;

/// <summary>
/// Abstraction over a hardware-bound sealer. The only production implementation is the TPM 2.0
/// backend (<c>SimpleOtp.Tpm.TpmSecretSealer</c>); tests use an in-memory fake. Keeping this
/// interface in Core lets the rest of the app stay free of any TPM dependency.
/// </summary>
public interface ISecretSealer
{
    /// <summary>True if a usable sealer (TPM) is present and responsive.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Stable identifier for this backend, recorded in the vault file so we can detect when a vault
    /// was created by a different backend (e.g. "tpm2" vs the test fake).
    /// </summary>
    string BackendId { get; }

    /// <summary>Cryptographically strong random bytes (sourced from the TPM where possible).</summary>
    byte[] GetRandomBytes(int count);

    /// <summary>
    /// Seals <paramref name="data"/> so it can only be recovered on this device, optionally gated by
    /// <paramref name="auth"/> (the PIN). Pass an empty span for no PIN.
    /// </summary>
    SealedBlob Seal(ReadOnlySpan<byte> data, ReadOnlySpan<byte> auth);

    /// <summary>
    /// Recovers data previously sealed by <see cref="Seal"/>.
    /// </summary>
    /// <exception cref="WrongPinException">The auth/PIN was wrong.</exception>
    /// <exception cref="WrongDeviceException">The blob does not belong to this TPM.</exception>
    /// <exception cref="TpmLockedException">The TPM is in dictionary-attack lockout.</exception>
    byte[] Unseal(SealedBlob blob, ReadOnlySpan<byte> auth);

    /// <summary>
    /// Imports a TOTP <paramref name="secret"/> as a <b>non-exportable</b> HMAC key bound to this
    /// device, returning the wrapped key blob to persist. The raw secret cannot be recovered from the
    /// blob — it can only be used to compute HMACs via <see cref="ComputeHmac"/>, inside the sealer.
    /// This backs Advanced Security mode.
    /// </summary>
    /// <param name="secret">The raw shared-secret key bytes.</param>
    /// <param name="algorithm">The HMAC hash the resulting key is permanently bound to.</param>
    SealedBlob ImportHmacKey(ReadOnlySpan<byte> secret, OtpAlgorithm algorithm);

    /// <summary>
    /// Computes <c>HMAC(key, data)</c> using a key previously produced by <see cref="ImportHmacKey"/>,
    /// entirely inside the sealer. Only the MAC is returned; the key never leaves the device.
    /// </summary>
    /// <param name="hmacKey">A blob from <see cref="ImportHmacKey"/>.</param>
    /// <param name="data">The message to authenticate (the TOTP time counter).</param>
    /// <param name="algorithm">The HMAC hash the key was imported with.</param>
    /// <exception cref="WrongDeviceException">The blob does not belong to this TPM.</exception>
    byte[] ComputeHmac(SealedBlob hmacKey, ReadOnlySpan<byte> data, OtpAlgorithm algorithm);
}
