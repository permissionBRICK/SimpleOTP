using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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
            throw WrapTpmException(ex, "TPM seal failed");
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

            // If the chip is already in dictionary-attack lockout, bail out cleanly before issuing any
            // command: some TPMs fault the very next auth-bearing operation (which would otherwise
            // surface as an opaque, uncaught error). This makes lockout a typed, actionable exception.
            LockoutStatus? pre = TryReadLockoutStatus(tpm);
            if (pre is { InLockout: true } locked)
                throw new TpmLockedException(LockoutMessage, recoverySeconds: locked.RecoverySeconds);

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
                        throw MapAuthFailure(tpm, rc);
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
            throw WrapTpmException(ex, "TPM unseal failed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authArr);
        }
    }

    public SealedBlob ImportHmacKey(ReadOnlySpan<byte> secret, OtpAlgorithm algorithm, ReadOnlySpan<byte> auth)
    {
        if (secret.IsEmpty) throw new ArgumentException("Secret is empty.", nameof(secret));
        byte[] keyArr = secret.ToArray();
        byte[] authArr = NormalizeAuth(auth);
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
                // leave FixedTPM clear because it used TPM2_Import. The object's auth value (the vault
                // key) gates every HMAC, so a stolen machine still can't mint codes without it.
                TpmPrivate priv = tpm._AllowErrors().Create(
                    srk,
                    new SensitiveCreate(authArr, keyArr),
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
            throw WrapTpmException(ex, "TPM HMAC-key import failed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyArr);
            CryptographicOperations.ZeroMemory(authArr);
        }
    }

    public byte[] ComputeHmac(SealedBlob hmacKey, ReadOnlySpan<byte> data, OtpAlgorithm algorithm, ReadOnlySpan<byte> auth)
    {
        byte[] dataArr = data.ToArray();
        byte[] authArr = NormalizeAuth(auth);
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
                    // (no HMAC sequence needed). The auth value (vault key) is presented for the operation;
                    // the MAC is computed inside the TPM and the key never leaves.
                    byte[] mac = tpm[authArr]._AllowErrors().Hmac(loaded, dataArr, hashAlg);
                    TpmRc rc = tpm._GetLastResponseCode();
                    if (rc != TpmRc.Success)
                        throw MapAuthFailure(tpm, rc);
                    return mac;
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
            throw WrapTpmException(ex, "TPM HMAC computation failed");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataArr);
            CryptographicOperations.ZeroMemory(authArr);
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

    private const string LockoutMessage =
        "The TPM is locked because of too many incorrect PIN attempts. Wait for it to recover, or reboot.";

    // Translate a failed auth response into a typed exception, enriching it with live dictionary-attack
    // state so the UI can show the attempts left / recovery countdown. The state is read on the same
    // connection right after the failure; reading capabilities needs no auth and isn't DA-gated.
    private static SealerException MapAuthFailure(Tpm2 tpm, TpmRc rc)
    {
        LockoutStatus? status = TryReadLockoutStatus(tpm);

        // A failed attempt can be the one that trips lockout: the chip may answer AuthFail yet now be
        // locked. Treat "locked" as authoritative over the raw rc so the user gets the lockout flow.
        if (rc == TpmRc.Lockout || status is { InLockout: true })
            return new TpmLockedException(LockoutMessage, recoverySeconds: status?.RecoverySeconds);

        if (rc is TpmRc.AuthFail or TpmRc.BadAuth)
            return new WrongPinException("Wrong PIN.", remainingAttempts: status?.RemainingAttempts);

        return new SealerException($"TPM rejected the operation (rc={rc}).");
    }

    // Last-resort mapping for a raw TpmException that slipped past the per-command response-code checks.
    // A lockout must still reach the UI as a typed lockout — but the connection that could report the
    // recovery interval is already torn down here, so it goes up without one.
    private static SealerException WrapTpmException(TpmException ex, string context)
        => ex.RawResponse == TpmRc.Lockout
            ? new TpmLockedException(LockoutMessage, recoverySeconds: null, inner: ex)
            : new SealerException($"{context}: {ex.Message}", ex);

    /// <summary>The TPM's dictionary-attack lockout state, read read-only via GetCapability.</summary>
    private readonly record struct LockoutStatus(bool InLockout, int EffectiveMaxAuthFail, int LockoutCounter, int LockoutInterval)
    {
        /// <summary>Failed attempts left before lockout (clamped at 0).</summary>
        public int RemainingAttempts => Math.Max(0, EffectiveMaxAuthFail - LockoutCounter);

        /// <summary>Seconds the chip needs to recover one attempt, or null when it reports no interval.</summary>
        public int? RecoverySeconds => LockoutInterval > 0 ? LockoutInterval : null;
    }

    // Reads the chip's DA parameters. Best-effort: returns null (rather than throwing) if the TPM does
    // not answer, so callers degrade to a generic message instead of failing the unlock outright.
    private static LockoutStatus? TryReadLockoutStatus(Tpm2 tpm)
    {
        try
        {
            return new LockoutStatus(
                InLockout: (ReadProperty(tpm, Pt.Permanent) & (uint)PermanentAttr.InLockout) != 0,
                EffectiveMaxAuthFail: ComputeEffectiveMaxAuthFail((int)ReadProperty(tpm, Pt.MaxAuthFail), StandardUserLockoutThreshold()),
                LockoutCounter: (int)ReadProperty(tpm, Pt.LockoutCounter),
                LockoutInterval: (int)ReadProperty(tpm, Pt.LockoutInterval));
        }
        catch
        {
            return null;
        }
    }

    // Microsoft's documented default "Standard User Individual Lockout Threshold" (the GP setting that,
    // when unset, governs how many TPM auth failures a non-elevated process gets).
    internal const int WindowsStandardUserLockoutDefault = 4;

    // The number of wrong PINs that actually locks SimpleOtp. The TPM's own MaxAuthFail is the limit on
    // Linux, but on Windows the OS (TBS) enforces a much smaller "standard user" lockout on top, and a
    // non-elevated app hits THAT first — so the effective ceiling is the smaller of the two. Reading the
    // hardware MaxAuthFail alone over-reports (e.g. 31 when the chip really locks at 4).
    internal static int ComputeEffectiveMaxAuthFail(int hardwareMaxAuthFail, int? standardUserThreshold)
        => standardUserThreshold is int t && t > 0 ? Math.Min(hardwareMaxAuthFail, t) : hardwareMaxAuthFail;

    // The standard-user threshold in effect, or null where there is no such layer (non-Windows). Uses the
    // group-policy override when an admin set one, else Microsoft's documented default.
    private static int? StandardUserLockoutThreshold()
        => OperatingSystem.IsWindows()
            ? (ReadWindowsStandardUserThresholdOverride() ?? WindowsStandardUserLockoutDefault)
            : null;

    [SupportedOSPlatform("windows")]
    private static int? ReadWindowsStandardUserThresholdOverride()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\TPM");
            if (key is null) return null;
            // Match the "Standard User ... Individual ... Threshold" GP value without hard-coding its exact
            // spelling (it varies); any positive individual-threshold value overrides the default.
            foreach (string name in key.GetValueNames())
                if (name.Contains("Individual", StringComparison.OrdinalIgnoreCase)
                    && name.Contains("Threshold", StringComparison.OrdinalIgnoreCase)
                    && key.GetValue(name) is int v && v > 0)
                    return v;
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static uint ReadProperty(Tpm2 tpm, Pt property)
    {
        tpm.GetCapability(Cap.TpmProperties, (uint)property, 1, out ICapabilitiesUnion caps);
        foreach (TaggedProperty p in ((TaggedTpmPropertyArray)caps).tpmProperty)
            if (p.property == property)
                return p.value;
        return 0;
    }

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

    private static TpmHandle CreateSrk(Tpm2 tpm)
    {
        // Allow errors so a lockout (or any failure) surfaces as a response code we can map while the
        // TPM connection is still open — rather than a raw TpmException that escapes as an opaque
        // "Error {Lockout} ... command CreatePrimary" message. In dictionary-attack lockout some chips
        // refuse CreatePrimary on the owner hierarchy even though it carries no DA-protected auth.
        TpmHandle srk = tpm._AllowErrors().CreatePrimary(
            TpmRh.Owner,
            new SensitiveCreate(Array.Empty<byte>(), Array.Empty<byte>()),
            SrkTemplate(),
            SrkOutsideInfo,
            Array.Empty<PcrSelection>(),
            out _, out _, out _, out _);
        TpmRc rc = tpm._GetLastResponseCode();
        if (rc != TpmRc.Success || srk is null)
            throw MapAuthFailure(tpm, rc);
        return srk;
    }

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
