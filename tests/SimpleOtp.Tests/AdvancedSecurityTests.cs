using System.Text;
using SimpleOtp.Core;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Storage;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

/// <summary>
/// Advanced Security mode: TPM-HMAC code generation (modelled by <see cref="FakeSealer"/>), the
/// optional master-password export path, and conversion between modes.
/// </summary>
public class AdvancedSecurityTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public AdvancedSecurityTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-adv-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "vault.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    // RFC 6238 SHA1 seed → known code at t=59 (low 6 digits of 94287082).
    private const string SampleUri =
        "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    private VaultService NewAdvancedVault(FakeSealer sealer, string? masterPassword)
    {
        var svc = new VaultService(sealer, _path);
        svc.CreateNew(ReadOnlySpan<byte>.Empty);     // first run is always Simple
        svc.AddAccount(OtpAuthUri.Parse(SampleUri));
        svc.ConvertToAdvanced(masterPassword);
        return svc;
    }

    [Fact]
    public void Advanced_GeneratesSameCode_AsSimpleAndRfc()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: null);
        Assert.Equal(SecurityMode.Advanced, svc.Mode);
        Assert.True(svc.IsUnlocked); // unlocked here: this vault has no PIN, so the vault key auto-opened

        var account = Assert.Single(svc.Accounts);
        Assert.Null(account.Secret);            // no plaintext-able ciphertext remains
        Assert.NotNull(account.HmacKey);        // key lives in the (fake) TPM
        Assert.Equal("287082", svc.GenerateCode(account, DateTime.UnixEpoch.AddSeconds(59)));
    }

    [Fact]
    public void Advanced_AddingAccount_NeedsNoMasterPassword()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: "correct horse battery staple");
        // The vault is unlocked (no PIN here), and adding an account must not require the export master
        // password — the export copy is made with only the public key.
        var added = svc.AddAccount(OtpAuthUri.Parse(SampleUri.Replace("octocat", "hubber")));
        Assert.NotNull(added.HmacKey);
        Assert.NotNull(added.ExportCopy); // export copy is created with only the public key
        Assert.Equal(2, svc.Accounts.Count);
    }

    [Fact]
    public void Advanced_WithoutPassword_ExportIsImpossible()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: null);
        Assert.False(svc.ExportProtected);
        Assert.Throws<InvalidOperationException>(() => svc.ExportToMigrationUris());
        Assert.All(svc.Accounts, a => Assert.Null(a.ExportCopy));
    }

    [Fact]
    public void Advanced_WithPassword_ExportRoundTrips()
    {
        const string pw = "a-long-master-password";
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: pw);
        Assert.True(svc.ExportProtected);

        var uris = svc.ExportToMigrationUris(pw);
        var exported = uris.SelectMany(OtpAuthMigration.Parse).ToList();
        Assert.Single(exported);
        Assert.Equal(Encoding.ASCII.GetBytes("12345678901234567890"), exported[0].SecretBytes);
    }

    [Fact]
    public void Advanced_Export_WrongPassword_Throws()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: "the-right-one");
        Assert.Throws<WrongPinException>(() => svc.ExportToMigrationUris("the-wrong-one"));
    }

    [Fact]
    public void Advanced_PersistsAcrossRestart_OnSameDevice()
    {
        var device = new FakeSealer();
        string codeAtT59;
        using (var svc = NewAdvancedVault(device, masterPassword: "pw"))
            codeAtT59 = svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59));

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        Assert.Equal(SecurityMode.Advanced, reopened.Mode);
        Assert.True(reopened.IsInitialized);
        Assert.False(reopened.IsUnlocked);             // locked until the vault key is unsealed
        reopened.Unlock(ReadOnlySpan<byte>.Empty);     // no PIN on this vault
        Assert.True(reopened.IsUnlocked);
        Assert.Equal(codeAtT59, reopened.GenerateCode(reopened.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
    }

    [Fact]
    public void Advanced_OnDifferentDevice_CannotUnlock()
    {
        using (var svc = NewAdvancedVault(new FakeSealer(), masterPassword: "pw")) { }

        using var attacker = new VaultService(new FakeSealer(), _path);
        Assert.Equal(SecurityMode.Advanced, attacker.Mode);
        // The vault key won't unseal on another device, so it never unlocks — codes are unreachable
        // even though the HMAC blobs are right there in the file.
        Assert.Throws<WrongDeviceException>(() => attacker.Unlock(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Advanced_WithPin_GatesCodeGeneration()
    {
        const string pin = "4242";
        var device = new FakeSealer();
        string code;
        using (var svc = NewAdvancedVault(device, masterPassword: "export-pw"))
        {
            code = svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59));
            svc.ChangePin(pin); // a PIN on an Advanced vault re-seals the vault key that gates the HMAC keys
        }

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        Assert.Equal(SecurityMode.Advanced, reopened.Mode);
        Assert.True(reopened.PinProtected);
        Assert.False(reopened.IsUnlocked);
        Assert.Throws<WrongPinException>(() => reopened.Unlock("0000"));  // stolen machine without the PIN
        reopened.Unlock(pin);
        Assert.True(reopened.IsUnlocked);
        Assert.Equal(code, reopened.GenerateCode(reopened.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
    }

    [Fact]
    public void ConvertBackToSimple_WithPassword_RoundTripsAndExportsFreely()
    {
        const string pw = "round-trip-password";
        var device = new FakeSealer();
        string advancedCode;
        using (var svc = NewAdvancedVault(device, masterPassword: pw))
        {
            advancedCode = svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59));
            svc.ConvertToSimple(pw);

            Assert.Equal(SecurityMode.Simple, svc.Mode);
            var account = svc.Accounts[0];
            Assert.NotNull(account.Secret);   // back to DEK ciphertext
            Assert.Null(account.HmacKey);
            Assert.Null(account.ExportCopy);
            // Same code, and Simple-mode export works without a password.
            Assert.Equal(advancedCode, svc.GenerateCode(account, DateTime.UnixEpoch.AddSeconds(59)));
            Assert.NotEmpty(svc.ExportToMigrationUris());
        }

        // Survives a restart as a normal Simple vault.
        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        Assert.Equal(SecurityMode.Simple, reopened.Mode);
        reopened.Unlock(ReadOnlySpan<byte>.Empty);
        Assert.Equal(advancedCode, reopened.GenerateCode(reopened.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
    }

    [Fact]
    public void ConvertBackToSimple_WrongPassword_Throws()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: "right");
        Assert.Throws<WrongPinException>(() => svc.ConvertToSimple("wrong"));
        Assert.Equal(SecurityMode.Advanced, svc.Mode); // unchanged
    }

    [Fact]
    public void ConvertBackToSimple_WithoutPassword_IsBlocked()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: null);
        Assert.Throws<InvalidOperationException>(() => svc.ConvertToSimple(""));
        Assert.Equal(SecurityMode.Advanced, svc.Mode);
    }

    [Fact]
    public void ConvertToAdvanced_Twice_Throws()
    {
        using var svc = NewAdvancedVault(new FakeSealer(), masterPassword: null);
        Assert.Throws<InvalidOperationException>(() => svc.ConvertToAdvanced(null));
    }

    [Fact]
    public void LegacyAdvancedVault_NoVaultKey_StillGeneratesCodes_ButBlocksPin()
    {
        // Reproduce a vault written by the pre-gate build: Mode=Advanced, empty Dek, and an HMAC key
        // created with EMPTY auth. The new code must keep it working (empty-auth operation), not try to
        // unseal a non-existent vault key and brick it.
        var device = new FakeSealer();
        SealedBlob legacyKey = device.ImportHmacKey(
            Encoding.ASCII.GetBytes("12345678901234567890"), OtpAlgorithm.Sha1, ReadOnlySpan<byte>.Empty);
        var file = new VaultFile
        {
            Backend = device.BackendId,
            Mode = SecurityMode.Advanced,
            Dek = new SealedBlob([], []), // legacy: no sealed vault key
            Accounts =
            [
                new Account { Issuer = "GitHub", Label = "octocat", Algorithm = OtpAlgorithm.Sha1, Digits = 6, Period = 30, HmacKey = legacyKey },
            ],
        };
        VaultStore.Save(_path, file);

        using var svc = new VaultService(device.CloneSameDevice(), _path);
        Assert.Equal(SecurityMode.Advanced, svc.Mode);
        Assert.True(svc.IsInitialized);
        Assert.False(svc.PinProtected);

        svc.Unlock(ReadOnlySpan<byte>.Empty); // legacy: no-op, must not throw
        Assert.True(svc.IsUnlocked);
        Assert.Equal("287082", svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));

        // Adding a PIN / auto-unlock to a legacy vault isn't possible without re-import; it's blocked clearly.
        Assert.Throws<InvalidOperationException>(() => svc.ChangePin("1234"));
    }

    [Fact]
    public void ConvertingLegacyV1Vault_StampsCurrentSchemaVersion()
    {
        var device = new FakeSealer();
        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew(ReadOnlySpan<byte>.Empty);
            svc.AddAccount(OtpAuthUri.Parse(SampleUri));
        }

        // Simulate an on-disk vault written by the old (v1) schema: Version 1, no Mode field.
        var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(_path))!.AsObject();
        node["Version"] = 1;
        node.Remove("Mode");
        File.WriteAllText(_path, node.ToJsonString());

        using (var reopened = new VaultService(device.CloneSameDevice(), _path))
        {
            reopened.Unlock(ReadOnlySpan<byte>.Empty);
            reopened.ConvertToAdvanced("pw");
        }

        var saved = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(_path))!.AsObject();
        Assert.Equal(VaultFile.CurrentSchemaVersion, (int)saved["Version"]!); // migrated forward on write
        Assert.Equal("Advanced", (string?)saved["Mode"]);
    }
}
