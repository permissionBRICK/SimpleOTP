using System.Security.Cryptography;
using System.Text;
using SimpleOtp.Core.Crypto;
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
        Skip.IfNot(Enabled, SkipReason);
        var sealer = new TpmSecretSealer();
        Skip.IfNot(sealer.IsAvailable, "No usable TPM present.");

        byte[] secret = sealer.GetRandomBytes(32);
        SealedBlob blob = sealer.Seal(secret, "1234"u8);

        Assert.Equal(secret, sealer.Unseal(blob, "1234"u8));
        Assert.Throws<WrongPinException>(() => sealer.Unseal(blob, "9999"u8)); // single wrong attempt
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
