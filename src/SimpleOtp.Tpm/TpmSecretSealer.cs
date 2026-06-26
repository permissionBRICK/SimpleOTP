using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using Tpm2Lib;

namespace SimpleOtp.Tpm;

/// <summary>
/// TPM 2.0 implementation of <see cref="ISecretSealer"/> using Microsoft TSS.NET (Microsoft.TSS).
///
/// Design (matches the proven prototype):
///   * A storage root key (SRK) is recreated deterministically each operation via CreatePrimary on
///     the Owner hierarchy with a fixed template. Because primary derivation is a pure function of
///     the (per-chip, non-extractable) hierarchy seed and the template, the same SRK is obtained on
///     every run — so we never need to write a persistent handle / touch TPM NV storage.
///   * Secrets are sealed as keyed-hash data objects under that SRK, optionally behind a PIN
///     (the object's auth value). The marshalled public+private blobs are stored in the vault file.
///   * Every object is transient and flushed; nothing is left in the TPM between operations.
///
/// Device binding: the sealed private blob is wrapped under the SRK, which a different TPM cannot
/// reproduce, so a copied vault file cannot be unsealed elsewhere.
/// </summary>
public sealed class TpmSecretSealer : ISecretSealer
{
    public string BackendId => "tpm2";

    private const string LinuxTpmResourceManager = "/dev/tpmrm0";
    private const string LinuxTpmRaw = "/dev/tpm0";

    // Stable forever: changing this would orphan every previously sealed blob.
    private static readonly byte[] SrkOutsideInfo = Encoding.UTF8.GetBytes("SimpleOtp SRK v1");

    public bool IsAvailable
    {
        get
        {
            try
            {
                using var dev = ConnectDevice();
                using var tpm = new Tpm2(dev);
                _ = tpm.GetRandom(8); // cheap liveness probe; creates nothing
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public byte[] GetRandomBytes(int count)
    {
        if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
        using var dev = ConnectDevice();
        using var tpm = new Tpm2(dev);
        var result = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            byte[] chunk = tpm.GetRandom((ushort)Math.Min(count - offset, 32));
            if (chunk.Length == 0) throw new SealerException("TPM returned no random bytes.");
            Buffer.BlockCopy(chunk, 0, result, offset, chunk.Length);
            offset += chunk.Length;
        }
        return result;
    }

    public SealedBlob Seal(ReadOnlySpan<byte> data, ReadOnlySpan<byte> auth)
    {
        byte[] dataArr = data.ToArray();
        byte[] authArr = NormalizeAuth(auth);
        try
        {
            using var dev = ConnectDevice();
            using var tpm = new Tpm2(dev);
            TpmHandle srk = CreateSrk(tpm);
            try
            {
                TpmPrivate priv = tpm.Create(
                    srk,
                    new SensitiveCreate(authArr, dataArr),
                    SealTemplate(),
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out TpmPublic pub, out _, out _, out _);
                return new SealedBlob(pub.GetTpmRepresentation(), priv.GetTpmRepresentation());
            }
            finally
            {
                tpm.FlushContext(srk);
            }
        }
        catch (TpmException ex)
        {
            throw new SealerException($"TPM seal failed: {ex.Message}", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataArr);
            CryptographicOperations.ZeroMemory(authArr);
        }
    }

    public byte[] Unseal(SealedBlob blob, ReadOnlySpan<byte> auth)
    {
        byte[] authArr = NormalizeAuth(auth);
        try
        {
            using var dev = ConnectDevice();
            using var tpm = new Tpm2(dev);
            TpmHandle srk = CreateSrk(tpm);
            try
            {
                var pub = Marshaller.FromTpmRepresentation<TpmPublic>(blob.Public);
                var priv = Marshaller.FromTpmRepresentation<TpmPrivate>(blob.Private);

                TpmHandle loaded = tpm._AllowErrors().Load(srk, priv, pub);
                TpmRc loadRc = tpm._GetLastResponseCode();
                if (loadRc != TpmRc.Success || loaded is null)
                    throw new WrongDeviceException(
                        $"The TPM could not load this vault's sealed key (rc={loadRc}). " +
                        "The vault was likely created on a different device, or the TPM was cleared/reset.");

                try
                {
                    byte[] data = tpm[authArr]._AllowErrors().Unseal(loaded);
                    TpmRc rc = tpm._GetLastResponseCode();
                    if (rc != TpmRc.Success)
                        throw MapAuthFailure(rc);
                    return data;
                }
                finally
                {
                    tpm.FlushContext(loaded);
                }
            }
            finally
            {
                tpm.FlushContext(srk);
            }
        }
        catch (SealerException)
        {
            throw;
        }
        catch (TpmException ex)
        {
            throw new SealerException($"TPM unseal failed: {ex.Message}", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authArr);
        }
    }

    public SealedBlob ImportHmacKey(ReadOnlySpan<byte> secret, OtpAlgorithm algorithm)
    {
        if (secret.IsEmpty) throw new ArgumentException("Secret is empty.", nameof(secret));
        byte[] keyArr = secret.ToArray();
        TpmAlgId hashAlg = ToTpmHash(algorithm);
        try
        {
            using var dev = ConnectDevice();
            using var tpm = new Tpm2(dev);
            TpmHandle srk = CreateSrk(tpm);
            try
            {
                // Externally-supplied key bytes (SensitiveDataOrigin clear) created directly under the
                // SRK as a FixedTPM/FixedParent HMAC key: the seed can never be unsealed or duplicated,
                // only used for HMAC. This is stronger than the reference design (totpm), which had to
                // leave FixedTPM clear because it used TPM2_Import.
                TpmPrivate priv = tpm._AllowErrors().Create(
                    srk,
                    new SensitiveCreate(Array.Empty<byte>(), keyArr),
                    HmacTemplate(hashAlg),
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out TpmPublic pub, out _, out _, out _);
                TpmRc rc = tpm._GetLastResponseCode();
                if (rc == TpmRc.Hash)
                    throw new UnsupportedAlgorithmException(
                        $"This TPM cannot create a {algorithm} HMAC key (the chip does not support that hash). " +
                        $"Keep {algorithm}-based accounts in Simple Security mode.");
                if (rc != TpmRc.Success || priv is null)
                    throw new SealerException($"TPM rejected the HMAC-key import (rc={rc}).");
                return new SealedBlob(pub.GetTpmRepresentation(), priv.GetTpmRepresentation());
            }
            finally
            {
                tpm.FlushContext(srk);
            }
        }
        catch (SealerException)
        {
            throw;
        }
        catch (TpmException ex)
        {
            throw new SealerException($"TPM HMAC-key import failed: {ex.Message}", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyArr);
        }
    }

    public byte[] ComputeHmac(SealedBlob hmacKey, ReadOnlySpan<byte> data, OtpAlgorithm algorithm)
    {
        byte[] dataArr = data.ToArray();
        TpmAlgId hashAlg = ToTpmHash(algorithm);
        try
        {
            using var dev = ConnectDevice();
            using var tpm = new Tpm2(dev);
            TpmHandle srk = CreateSrk(tpm);
            try
            {
                var pub = Marshaller.FromTpmRepresentation<TpmPublic>(hmacKey.Public);
                var priv = Marshaller.FromTpmRepresentation<TpmPrivate>(hmacKey.Private);

                TpmHandle loaded = tpm._AllowErrors().Load(srk, priv, pub);
                TpmRc loadRc = tpm._GetLastResponseCode();
                if (loadRc != TpmRc.Success || loaded is null)
                    throw new WrongDeviceException(
                        $"The TPM could not load this account's HMAC key (rc={loadRc}). " +
                        "The vault was likely created on a different device, or the TPM was cleared/reset.");
                try
                {
                    // The counter is 8 bytes, well within one HMAC buffer, so a single TPM2_HMAC suffices
                    // (no HMAC sequence needed). The MAC is computed inside the TPM; the key never leaves.
                    return tpm.Hmac(loaded, dataArr, hashAlg);
                }
                finally
                {
                    tpm.FlushContext(loaded);
                }
            }
            finally
            {
                tpm.FlushContext(srk);
            }
        }
        catch (SealerException)
        {
            throw;
        }
        catch (TpmException ex)
        {
            throw new SealerException($"TPM HMAC computation failed: {ex.Message}", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataArr);
        }
    }

    private static TpmAlgId ToTpmHash(OtpAlgorithm algorithm) => algorithm switch
    {
        OtpAlgorithm.Sha256 => TpmAlgId.Sha256,
        OtpAlgorithm.Sha512 => TpmAlgId.Sha512,
        OtpAlgorithm.Sha1 => TpmAlgId.Sha1,
        _ => throw new SealerException($"Unsupported HMAC algorithm {algorithm}."),
    };

    // TPM auth values are limited to the object's nameAlg digest size (32 bytes for SHA256). Hash any
    // non-empty secret (PIN or auto-unlock key) to a fixed 32 bytes so arbitrary-length inputs are
    // accepted; keep empty as empty so "no PIN" remains a genuine empty auth value.
    private static byte[] NormalizeAuth(ReadOnlySpan<byte> auth)
        => auth.IsEmpty ? Array.Empty<byte>() : SHA256.HashData(auth);

    private static SealerException MapAuthFailure(TpmRc rc) => rc switch
    {
        TpmRc.AuthFail => new WrongPinException("Wrong PIN."),
        TpmRc.BadAuth => new WrongPinException("Wrong PIN."),
        TpmRc.Lockout => new TpmLockedException(
            "The TPM is locked due to too many incorrect PIN attempts. Wait for it to recover or reboot."),
        _ => new SealerException($"TPM rejected the operation (rc={rc})."),
    };

    // --- TPM templates -------------------------------------------------------

    // SRK: RSA-2048 restricted decryption (storage) parent. Must stay identical forever.
    private static TpmPublic SrkTemplate() => new(
        TpmAlgId.Sha256,
        ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.FixedTPM | ObjectAttr.FixedParent
            | ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth | ObjectAttr.NoDA,
        Array.Empty<byte>(),
        new RsaParms(new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb), new NullAsymScheme(), 2048, 0),
        new Tpm2bPublicKeyRsa());

    // Sealed data object: a keyed-hash object holding externally-supplied data (no SensitiveDataOrigin).
    // UserWithAuth means the auth value (PIN) gates Unseal. FixedTPM/FixedParent => non-duplicable.
    private static TpmPublic SealTemplate() => new(
        TpmAlgId.Sha256,
        ObjectAttr.UserWithAuth | ObjectAttr.FixedTPM | ObjectAttr.FixedParent,
        Array.Empty<byte>(),
        new KeyedhashParms(new NullSchemeKeyedhash()),
        new Tpm2bDigestKeyedhash());

    // HMAC key (Advanced mode): a keyed-hash signing object holding externally-supplied key bytes
    // (no SensitiveDataOrigin). Restricted is CLEAR so TPM2_HMAC may sign arbitrary data (the time
    // counter); FixedTPM/FixedParent => the seed is non-duplicable and can never be read back out.
    private static TpmPublic HmacTemplate(TpmAlgId hashAlg) => new(
        TpmAlgId.Sha256,
        ObjectAttr.Sign | ObjectAttr.UserWithAuth | ObjectAttr.FixedTPM | ObjectAttr.FixedParent,
        Array.Empty<byte>(),
        new KeyedhashParms(new SchemeHmac(hashAlg)),
        new Tpm2bDigestKeyedhash());

    private static TpmHandle CreateSrk(Tpm2 tpm) => tpm.CreatePrimary(
        TpmRh.Owner,
        new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
        SrkTemplate(),
        SrkOutsideInfo,
        Array.Empty<PcrSelection>(),
        out _, out _, out _, out _);

    // --- Device connection ---------------------------------------------------

    private static Tpm2Device ConnectDevice()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var dev = new TbsDevice();
            dev.Connect();
            return dev;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            string path = File.Exists(LinuxTpmResourceManager) ? LinuxTpmResourceManager : LinuxTpmRaw;
            var dev = new LinuxTpmDevice(path);
            dev.Connect();
            return dev;
        }

        throw new SealerUnavailableException("No TPM access is available on this operating system.");
    }
}
