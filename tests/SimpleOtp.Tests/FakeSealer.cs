using System.Security.Cryptography;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Tests;

/// <summary>
/// In-memory <see cref="ISecretSealer"/> for tests. Faithfully models the two TPM properties we
/// rely on:
///   * device binding — each instance has its own random "device key"; a blob sealed by one
///     instance cannot be unsealed by another (decryption fails → <see cref="WrongDeviceException"/>);
///   * PIN — the auth value is bound into the sealed payload; a wrong auth → <see cref="WrongPinException"/>.
/// </summary>
public sealed class FakeSealer : ISecretSealer
{
    private readonly byte[] _deviceKey;

    public FakeSealer(byte[]? deviceKey = null)
        => _deviceKey = deviceKey ?? RandomNumberGenerator.GetBytes(32);

    /// <summary>A clone bound to the same "device" (same device key) — used to test reopen-after-restart.</summary>
    public FakeSealer CloneSameDevice() => new(_deviceKey);

    public bool IsAvailable => true;
    public string BackendId => "fake";

    public byte[] GetRandomBytes(int count) => RandomNumberGenerator.GetBytes(count);

    public SealedBlob Seal(ReadOnlySpan<byte> data, ReadOnlySpan<byte> auth)
    {
        byte[] authHash = SHA256.HashData(auth);
        byte[] payload = [.. authHash, .. data];
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] ct = new byte[payload.Length];
        using var gcm = new AesGcm(_deviceKey, 16);
        gcm.Encrypt(nonce, payload, ct, tag);
        return new SealedBlob(Public: nonce, Private: [.. tag, .. ct]);
    }

    public byte[] Unseal(SealedBlob blob, ReadOnlySpan<byte> auth)
    {
        byte[] nonce = blob.Public;
        byte[] tag = blob.Private[..16];
        byte[] ct = blob.Private[16..];
        byte[] payload = new byte[ct.Length];
        using var gcm = new AesGcm(_deviceKey, 16);
        try
        {
            gcm.Decrypt(nonce, ct, tag, payload);
        }
        catch (CryptographicException ex)
        {
            throw new WrongDeviceException("Blob does not belong to this (fake) device.", ex);
        }

        byte[] authHash = payload[..32];
        byte[] data = payload[32..];
        if (!CryptographicOperations.FixedTimeEquals(authHash, SHA256.HashData(auth)))
            throw new WrongPinException("Wrong PIN (fake).");
        return data;
    }

    // Models the TPM HMAC key as a device-bound blob holding the key bytes (never returned to the
    // caller) plus the bound hash algorithm, locked under the auth value (the vault key). ComputeHmac
    // decrypts it internally — requiring the same auth — and HMACs in software, so the API contract
    // ("only the MAC comes out, and only with the right auth") matches the real backend; codes match.
    public SealedBlob ImportHmacKey(ReadOnlySpan<byte> secret, OtpAlgorithm algorithm, ReadOnlySpan<byte> auth)
    {
        byte[] tagged = [(byte)algorithm, .. secret];
        SealedBlob blob = Seal(tagged, auth);
        CryptographicOperations.ZeroMemory(tagged);
        return blob;
    }

    public byte[] ComputeHmac(SealedBlob hmacKey, ReadOnlySpan<byte> data, OtpAlgorithm algorithm, ReadOnlySpan<byte> auth)
    {
        byte[] tagged = Unseal(hmacKey, auth); // wrong auth -> WrongPinException, like the TPM
        try
        {
            if (tagged.Length == 0 || (OtpAlgorithm)tagged[0] != algorithm)
                throw new SealerException("HMAC key algorithm mismatch (fake).");
            byte[] key = tagged[1..];
            using HMAC hmac = algorithm switch
            {
                OtpAlgorithm.Sha256 => new HMACSHA256(key),
                OtpAlgorithm.Sha512 => new HMACSHA512(key),
                _ => new HMACSHA1(key),
            };
            return hmac.ComputeHash(data.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tagged);
        }
    }
}
