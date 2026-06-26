using SimpleOtp.Core;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

public class VaultServiceTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public VaultServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-tests-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "vault.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    // RFC 6238 SHA1 seed ("12345678901234567890") in Base32, so the expected code is grounded in the spec.
    private const string SampleUri =
        "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    [Fact]
    public void FirstRun_CreatesVault_AddsAccount_GeneratesCode()
    {
        var sealer = new FakeSealer();
        using var svc = new VaultService(sealer, _path);

        Assert.False(svc.IsInitialized);
        svc.CreateNew(ReadOnlySpan<byte>.Empty);
        Assert.True(svc.IsInitialized);
        Assert.True(svc.IsUnlocked);

        var account = svc.AddAccount(OtpAuthUri.Parse(SampleUri));
        Assert.Single(svc.Accounts);
        Assert.Equal("GitHub", account.Issuer);

        string code = svc.GenerateCode(account, DateTime.UnixEpoch.AddSeconds(59));
        Assert.Equal("287082", code); // RFC 6238 @ t=59, SHA1 → 8-digit 94287082; low 6 = 287082
    }

    [Fact]
    public void Persists_AndReopensOnSameDevice()
    {
        var device = new FakeSealer();
        string id;
        string codeAtT59;
        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew(ReadOnlySpan<byte>.Empty);
            var acct = svc.AddAccount(OtpAuthUri.Parse(SampleUri));
            id = acct.Id;
            codeAtT59 = svc.GenerateCode(acct, DateTime.UnixEpoch.AddSeconds(59));
        }

        // Simulate app restart: new service, same file, same device.
        using (var reopened = new VaultService(device.CloneSameDevice(), _path))
        {
            Assert.True(reopened.IsInitialized);
            Assert.False(reopened.PinProtected);
            reopened.Unlock(ReadOnlySpan<byte>.Empty);

            var acct = Assert.Single(reopened.Accounts);
            Assert.Equal(id, acct.Id);
            Assert.Equal(codeAtT59, reopened.GenerateCode(acct, DateTime.UnixEpoch.AddSeconds(59)));
        }
    }

    [Fact]
    public void CopiedVault_OnDifferentDevice_FailsToUnlock()
    {
        using (var svc = new VaultService(new FakeSealer(), _path))
        {
            svc.CreateNew(ReadOnlySpan<byte>.Empty);
            svc.AddAccount(OtpAuthUri.Parse(SampleUri));
        }

        // Same vault file, different device → device-bound DEK cannot be unsealed.
        using var attacker = new VaultService(new FakeSealer(), _path);
        Assert.True(attacker.IsInitialized);
        Assert.Throws<WrongDeviceException>(() => attacker.Unlock(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void SettingPin_RequiresItAfterRestart()
    {
        var device = new FakeSealer();
        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew(ReadOnlySpan<byte>.Empty);
            svc.AddAccount(OtpAuthUri.Parse(SampleUri));
            svc.ChangePin("4242");
        }

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        Assert.True(reopened.PinProtected);
        Assert.Throws<WrongPinException>(() => reopened.Unlock("0000"));
        reopened.Unlock("4242");
        Assert.Single(reopened.Accounts);
    }

    [Fact]
    public void RemoveAccount_Persists()
    {
        var device = new FakeSealer();
        string id;
        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew(ReadOnlySpan<byte>.Empty);
            id = svc.AddAccount(OtpAuthUri.Parse(SampleUri)).Id;
            svc.AddAccount(OtpAuthUri.Parse(SampleUri.Replace("octocat", "hubber")));
            Assert.Equal(2, svc.Accounts.Count);
            svc.RemoveAccount(id);
            Assert.Single(svc.Accounts);
        }

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        reopened.Unlock(ReadOnlySpan<byte>.Empty);
        Assert.Single(reopened.Accounts);
        Assert.DoesNotContain(reopened.Accounts, a => a.Id == id);
    }

    [Fact]
    public void ExportToMigrationUris_RoundTripsAccounts()
    {
        using var svc = new VaultService(new FakeSealer(), _path);
        svc.CreateNew(ReadOnlySpan<byte>.Empty);
        svc.AddAccount(OtpAuthUri.Parse(SampleUri));
        svc.AddAccount(OtpAuthUri.Parse(SampleUri.Replace("octocat", "hubber")));

        var uris = svc.ExportToMigrationUris();
        Assert.NotEmpty(uris);

        var exported = uris.SelectMany(OtpAuthMigration.Parse).ToList();
        Assert.Equal(2, exported.Count);
        Assert.Contains(exported, a => a.Label == "octocat");
        Assert.Contains(exported, a => a.Label == "hubber");
        // Secret survives decrypt -> export -> parse (RFC seed bytes).
        Assert.Equal(
            System.Text.Encoding.ASCII.GetBytes("12345678901234567890"),
            exported.First(a => a.Label == "octocat").SecretBytes);
    }
}
