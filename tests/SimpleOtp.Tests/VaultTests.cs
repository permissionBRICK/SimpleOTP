using System.Text;
using SimpleOtp.Core.Crypto;

namespace SimpleOtp.Tests;

public class VaultTests
{
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("a-totp-seed-of-some-length");

    [Fact]
    public void Create_LeavesVaultUnlocked_AndRoundTrips()
    {
        var sealer = new FakeSealer();
        using var vault = Vault.Create(sealer, ReadOnlySpan<byte>.Empty);

        Assert.True(vault.IsUnlocked);
        Assert.False(vault.PinProtected);

        var enc = vault.Encrypt(Secret);
        Assert.Equal(Secret, vault.Decrypt(enc));
    }

    [Fact]
    public void Lock_PreventsUse_UntilUnlock()
    {
        var sealer = new FakeSealer();
        var sealedDek = Vault.Create(sealer, ReadOnlySpan<byte>.Empty).SealedDek;

        using var vault = Vault.Open(sealer, sealedDek, pinProtected: false);
        Assert.False(vault.IsUnlocked);
        Assert.Throws<InvalidOperationException>(() => vault.Encrypt(Secret));

        vault.Unlock(ReadOnlySpan<byte>.Empty);
        Assert.True(vault.IsUnlocked);
        var enc = vault.Encrypt(Secret);
        Assert.Equal(Secret, vault.Decrypt(enc));
    }

    [Fact]
    public void Pin_IsEnforced()
    {
        var sealer = new FakeSealer();
        var pin = "1234"u8.ToArray();
        SealedBlob dek;
        EncryptedSecretFixture fixture;
        using (var creating = Vault.Create(sealer, pin))
        {
            dek = creating.SealedDek;
            fixture = new EncryptedSecretFixture(creating.Encrypt(Secret));
        }

        using var vault = Vault.Open(sealer, dek, pinProtected: true);
        Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8));

        vault.Unlock("1234"u8);
        Assert.Equal(Secret, vault.Decrypt(fixture.Value));
    }

    [Fact]
    public void DifferentDevice_CannotUnlock()
    {
        var deviceA = new FakeSealer();
        var dek = Vault.Create(deviceA, ReadOnlySpan<byte>.Empty).SealedDek;

        var deviceB = new FakeSealer(); // different random device key
        using var vault = Vault.Open(deviceB, dek, pinProtected: false);
        Assert.Throws<WrongDeviceException>(() => vault.Unlock(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void ChangePin_KeepsDekStable_SoOldCiphertextStillDecrypts()
    {
        var sealer = new FakeSealer();
        SealedBlob dek;
        EncryptedSecretFixture fixture;
        using (var v = Vault.Create(sealer, ReadOnlySpan<byte>.Empty))
        {
            fixture = new EncryptedSecretFixture(v.Encrypt(Secret));
            v.ChangePin("9999"u8);
            dek = v.SealedDek;
            Assert.True(v.PinProtected);
        }

        // Reopen on the same device with the new PIN and decrypt the pre-existing ciphertext.
        using var reopened = Vault.Open(sealer.CloneSameDevice(), dek, pinProtected: true);
        reopened.Unlock("9999"u8);
        Assert.Equal(Secret, reopened.Decrypt(fixture.Value));
    }

    // Holds an EncryptedSecret across a `using` boundary in tests.
    private sealed record EncryptedSecretFixture(SimpleOtp.Core.Model.EncryptedSecret Value);
}
