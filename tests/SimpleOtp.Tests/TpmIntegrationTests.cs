using System.Security.Cryptography;
using System.Text;
using SimpleOtp.Core;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;
using SimpleOtp.Tpm;

namespace SimpleOtp.Tests;

/// <summary>
/// Exercises the REAL TPM. Skipped unless <c>SIMPLEOTP_TPM_TEST=1</c> is set, so the normal test
/// suite never touches the chip. Each test seals exactly one transient object and lets the sealer
/// flush it — nothing is persisted in the TPM.
/// </summary>
public class TpmIntegrationTests
{
    private const string EnableVar = "SIMPLEOTP_TPM_TEST";

    private static bool Enabled =>
        Environment.GetEnvironmentVariable(EnableVar) == "1";

    private const string SkipReason =
        "Real-TPM test. Set SIMPLEOTP_TPM_TEST=1 to run (seals one transient object and flushes it).";

    // The wrong-PIN test deliberately fails an auth, which advances the TPM's dictionary-attack
    // counter. On chips with a low MaxAuthFail (e.g. 3) a few suite runs can trip lockout, which is
    // shared, persistent state. So it is gated behind a SEPARATE opt-in on top of SIMPLEOTP_TPM_TEST.
    private const string DaEnableVar = "SIMPLEOTP_TPM_DA_TEST";

    private static bool DaEnabled =>
        Environment.GetEnvironmentVariable(DaEnableVar) == "1";

    private const string DaSkipReason =
        "Wrong-PIN DA test. Advances the TPM dictionary-attack counter, so it can trip lockout on a " +
        "shared chip with a low MaxAuthFail. Set SIMPLEOTP_TPM_DA_TEST=1 (with SIMPLEOTP_TPM_TEST=1) to run.";

    [SkippableFact]
    public void SealUnseal_RoundTrips_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        byte[] secret = sealer.GetRandomBytes(32);
        SealedBlob blob = sealer.Seal(secret, ReadOnlySpan<byte>.Empty);
        byte[] recovered = sealer.Unseal(blob, ReadOnlySpan<byte>.Empty);

        Assert.Equal(secret, recovered);
    }

    [SkippableFact]
    public void Pin_IsEnforced_OnRealTpm()
    {
        Skip.IfNot(DaEnabled, DaSkipReason); // gated separately: it fails an auth on purpose
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        byte[] secret = sealer.GetRandomBytes(32);
        SealedBlob blob = sealer.Seal(secret, "1234"u8);

        Assert.Equal(secret, sealer.Unseal(blob, "1234"u8));
        Assert.Throws<WrongPinException>(() => sealer.Unseal(blob, "9999"u8)); // single wrong attempt
    }

    [SkippableFact]
    public void Lockout_SurfacesTypedException_NotRawCreatePrimaryError_OnRealTpm()
    {
        Skip.IfNot(DaEnabled, DaSkipReason); // deliberately trips lockout
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        // Regression for the locked-TPM unlock crash: once the chip is in dictionary-attack lockout, an
        // unlock attempt must raise a typed TpmLockedException — never leak the raw
        // "Error {Lockout} ... command CreatePrimary" that previously reached (and crashed) the UI.
        // The chip is left exactly as found: we reset the DA counter in the finally.
        SealedBlob blob = sealer.Seal("payload"u8, "1234"u8);
        try
        {
            bool sawTypedLockout = false;
            // Hammer the wrong PIN well past MaxAuthFail so later attempts run fully locked (the
            // CreatePrimary path). Some attempts report WrongPin (with attempts-left); once locked they
            // must all be TpmLockedException with a clean message and no raw-error leak.
            for (int i = 0; i < 12 && !sawTypedLockout; i++)
            {
                try { sealer.Unseal(blob, "9999"u8); }
                catch (WrongPinException) { /* attempts remain */ }
                catch (TpmLockedException ex)
                {
                    sawTypedLockout = true;
                    Assert.DoesNotContain("CreatePrimary", ex.Message);
                    Assert.DoesNotContain("unseal failed", ex.Message);
                }
            }
            Assert.True(sawTypedLockout, "Expected the chip to reach a typed TpmLockedException.");

            // A further attempt while fully locked must also be typed (not a base SealerException).
            Assert.Throws<TpmLockedException>(() => sealer.Unseal(blob, "9999"u8));
        }
        finally
        {
            ResetDictionaryAttackLock();
        }

        // The reset restored the chip, so the correct PIN unseals again.
        Assert.Equal("payload"u8.ToArray(), sealer.Unseal(blob, "1234"u8));
    }

    // Resets the TPM dictionary-attack lockout (requires empty lockout-hierarchy auth, the default on a
    // never-provisioned chip). Best-effort: a chip with a lockout password simply stays locked until it
    // recovers on its own. Test-only — production never resets the chip's anti-hammering.
    private static void ResetDictionaryAttackLock()
    {
        try
        {
            string path = File.Exists("/dev/tpmrm0") ? "/dev/tpmrm0" : "/dev/tpm0";
            using Tpm2Lib.Tpm2Device dev = OperatingSystem.IsWindows()
                ? new Tpm2Lib.TbsDevice()
                : new Tpm2Lib.LinuxTpmDevice(path);
            dev.Connect();
            using var tpm = new Tpm2Lib.Tpm2(dev);
            tpm.DictionaryAttackLockReset(Tpm2Lib.TpmRh.Lockout);
        }
        catch { /* lockout auth is set on this chip; leave it to recover naturally */ }
    }

    [SkippableFact]
    public void LongAuthValue_RoundTrips_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        // Base64(32 bytes) = 44 chars, exceeding the 32-byte TPM auth limit unless the sealer
        // normalizes it. This guards the auto-unlock key / long-PIN path.
        byte[] longAuth = Encoding.UTF8.GetBytes(Convert.ToBase64String(sealer.GetRandomBytes(32)));
        Assert.True(longAuth.Length > 32);

        byte[] secret = sealer.GetRandomBytes(32);
        SealedBlob blob = sealer.Seal(secret, longAuth);
        Assert.Equal(secret, sealer.Unseal(blob, longAuth));
    }

    [SkippableTheory]
    // RFC 6238 seed → the real TPM must compute the spec's codes inside the chip. (8-digit codes @ t=59.)
    [InlineData("12345678901234567890", OtpAlgorithm.Sha1, "94287082")]
    [InlineData("12345678901234567890123456789012", OtpAlgorithm.Sha256, "46119246")]
    public void HmacKey_ComputesRfcCode_InsideTpm(string seedAscii, OtpAlgorithm algorithm, string expected)
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        byte[] seed = Encoding.ASCII.GetBytes(seedAscii);
        SealedBlob hmacKey = sealer.ImportHmacKey(seed, algorithm, ReadOnlySpan<byte>.Empty);

        // The TPM MAC must match a software HMAC of the same key+message (auth gates use, not the value)...
        byte[] counter = TotpGenerator.CounterBytes(30, DateTime.UnixEpoch.AddSeconds(59));
        byte[] tpmMac = sealer.ComputeHmac(hmacKey, counter, algorithm, ReadOnlySpan<byte>.Empty);
        using HMAC software = algorithm == OtpAlgorithm.Sha256 ? new HMACSHA256(seed) : new HMACSHA1(seed);
        Assert.Equal(software.ComputeHash(counter), tpmMac);
        // ...and truncate to the published RFC vector.
        Assert.Equal(expected, TotpGenerator.Truncate(tpmMac, 8));
    }

    [SkippableFact]
    public void HmacKey_WithAuth_ComputesWithCorrectAuth_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        // Advanced mode locks each HMAC key under the vault key. Verify the auth-carrying path computes
        // correctly with the RIGHT auth (the MAC value is independent of the auth). Wrong-auth is not
        // exercised here — it would advance the DA counter; that gating is covered by the fake sealer.
        byte[] seed = Encoding.ASCII.GetBytes("12345678901234567890");
        byte[] auth = sealer.GetRandomBytes(32); // stand-in for the vault key
        SealedBlob key = sealer.ImportHmacKey(seed, OtpAlgorithm.Sha1, auth);
        byte[] counter = TotpGenerator.CounterBytes(30, DateTime.UnixEpoch.AddSeconds(59));
        Assert.Equal("94287082", TotpGenerator.Truncate(sealer.ComputeHmac(key, counter, OtpAlgorithm.Sha1, auth), 8));
    }

    [SkippableFact]
    public void HmacKey_UnsupportedHash_FailsGracefully_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        // Many firmware TPMs reject SHA-512 keyed-hash keys. Whatever this chip does, the failure must
        // be the typed, actionable exception — never a raw TPM error leaking to the user.
        byte[] seed = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");
        try
        {
            SealedBlob blob = sealer.ImportHmacKey(seed, OtpAlgorithm.Sha512, ReadOnlySpan<byte>.Empty);
            // If this TPM *does* support SHA-512, it must still compute correctly.
            byte[] counter = TotpGenerator.CounterBytes(30, DateTime.UnixEpoch.AddSeconds(59));
            Assert.Equal("90693936", TotpGenerator.Truncate(sealer.ComputeHmac(blob, counter, OtpAlgorithm.Sha512, ReadOnlySpan<byte>.Empty), 8));
        }
        catch (UnsupportedAlgorithmException)
        {
            // Expected on TPMs without SHA-512 — the actionable, mapped error.
        }
    }

    [SkippableFact]
    public void HmacKey_CannotBeUnsealed_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        // The defining Advanced-mode property: an imported HMAC key is a signing object, so the TPM
        // refuses to unseal it — the seed can never be read back out, only used to compute HMACs.
        SealedBlob hmacKey = sealer.ImportHmacKey(Encoding.ASCII.GetBytes("12345678901234567890"), OtpAlgorithm.Sha1, ReadOnlySpan<byte>.Empty);
        Assert.ThrowsAny<SealerException>(() => sealer.Unseal(hmacKey, ReadOnlySpan<byte>.Empty));
    }

    [SkippableFact]
    public void AdvancedSecurity_FullFlow_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        const string uri = "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        const string pw = "a-long-master-password-for-export";
        string dir = Path.Combine(Path.GetTempPath(), "simpleotp-tpm-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "vault.json");
        try
        {
            string simpleCode;
            using (var svc = new VaultService(sealer, path))
            {
                svc.CreateNew(ReadOnlySpan<byte>.Empty);
                var acct = svc.AddAccount(OtpAuthUri.Parse(uri));
                simpleCode = svc.GenerateCode(acct, DateTime.UnixEpoch.AddSeconds(59));
                Assert.Equal("287082", simpleCode);

                // Simple → Advanced (with export password): code must be unchanged, now from the TPM.
                svc.ConvertToAdvanced(pw);
                Assert.Equal(SecurityMode.Advanced, svc.Mode);
                Assert.Equal(simpleCode, svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));

                // Export round-trips through the TPM-sealed export key.
                var exported = svc.ExportToMigrationUris(pw).SelectMany(OtpAuthMigration.Parse).ToList();
                Assert.Equal(Encoding.ASCII.GetBytes("12345678901234567890"), Assert.Single(exported).SecretBytes);

                // Advanced → Simple (with password): still the same code, exportable again.
                svc.ConvertToSimple(pw);
                Assert.Equal(SecurityMode.Simple, svc.Mode);
                Assert.Equal(simpleCode, svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
            }

            // Reopen from disk on the same TPM — proves persistence of the round-tripped Simple vault.
            using (var reopened = new VaultService(sealer, path))
            {
                reopened.Unlock(ReadOnlySpan<byte>.Empty);
                Assert.Equal(simpleCode, reopened.GenerateCode(reopened.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
            }
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [SkippableFact]
    public void DifferentParent_Rejected_OnRealTpm()
    {
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        SealedBlob blob = sealer.Seal(sealer.GetRandomBytes(32), ReadOnlySpan<byte>.Empty);
        // Corrupt the public area so it no longer matches the sealed private blob's parent binding.
        byte[] tamperedPublic = (byte[])blob.Public.Clone();
        tamperedPublic[^1] ^= 0xFF;
        Assert.ThrowsAny<SealerException>(() => sealer.Unseal(blob with { Public = tamperedPublic }, ReadOnlySpan<byte>.Empty));
    }
}
