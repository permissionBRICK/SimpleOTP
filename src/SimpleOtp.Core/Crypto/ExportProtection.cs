using System.Security.Cryptography;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Core.Crypto;

/// <summary>
/// ECIES (ephemeral ECDH P-256 → SHA-256 KDF → AES-256-GCM) used for the recoverable export copies
/// kept in Advanced Security mode when a master password is set.
///
/// The asymmetry is the whole point: a new account is encrypted with only the <i>public</i> key, so
/// adding accounts never needs the password. The <i>private</i> scalar is TPM-sealed under the master
/// password and recovered only when the user explicitly exports — at which point every copy can be
/// decrypted. This gives exactly the requested behaviour: codes and new accounts need no secret;
/// the password is entered once, for export.
/// </summary>
public static class ExportProtection
{
    private static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256;
    private const int DekSize = 32;     // AES-256
    private const int NonceSize = 12;
    private const int TagSize = 16;

    /// <summary>The 32-byte private scalar (sealed under the password) and the public key (clear, DER).</summary>
    public sealed record KeyPair(byte[] PrivateScalar, byte[] PublicKey);

    /// <summary>Generates a fresh export key pair.</summary>
    public static KeyPair GenerateKeyPair()
    {
        using var ecdh = ECDiffieHellman.Create(Curve);
        ECParameters p = ecdh.ExportParameters(includePrivateParameters: true);
        return new KeyPair(p.D!, ecdh.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Encrypts <paramref name="secret"/> to <paramref name="publicKey"/> (no private key needed).</summary>
    public static ExportCopy Encrypt(byte[] publicKey, ReadOnlySpan<byte> secret)
    {
        using var ephemeral = ECDiffieHellman.Create(Curve);
        using var recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo(publicKey, out _);

        byte[] key = DeriveKey(ephemeral, recipient.PublicKey);
        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] tag = new byte[TagSize];
            byte[] ciphertext = new byte[secret.Length];
            using var gcm = new AesGcm(key, TagSize);
            gcm.Encrypt(nonce, secret, ciphertext, tag);
            return new ExportCopy(ephemeral.ExportSubjectPublicKeyInfo(), nonce, tag, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Recovers a secret from <paramref name="copy"/> using the (unsealed) private scalar.</summary>
    public static byte[] Decrypt(byte[] privateScalar, byte[] publicKey, ExportCopy copy)
    {
        using var pubOnly = ECDiffieHellman.Create();
        pubOnly.ImportSubjectPublicKeyInfo(publicKey, out _);
        ECPoint q = pubOnly.ExportParameters(false).Q;

        using var stat = ECDiffieHellman.Create();
        stat.ImportParameters(new ECParameters { Curve = Curve, D = privateScalar, Q = q });
        using var ephemeral = ECDiffieHellman.Create();
        ephemeral.ImportSubjectPublicKeyInfo(copy.EphemeralPublicKey, out _);

        byte[] key = DeriveKey(stat, ephemeral.PublicKey);
        try
        {
            byte[] plaintext = new byte[copy.Ciphertext.Length];
            using var gcm = new AesGcm(key, TagSize);
            try
            {
                gcm.Decrypt(copy.Nonce, copy.Ciphertext, copy.Tag, plaintext);
            }
            catch (CryptographicException ex)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new SealerException("Export copy failed authenticated decryption (tampered or corrupt vault).", ex);
            }
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // Hash-based ECDH KDF: SHA-256 of the shared point gives a 32-byte AES-256 key. Both parties
    // derive the same value from (their private, the other's public).
    private static byte[] DeriveKey(ECDiffieHellman self, ECDiffieHellmanPublicKey other)
        => self.DeriveKeyFromHash(other, HashAlgorithmName.SHA256);
}
