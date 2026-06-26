using System.Net;
using System.Text;
using SimpleOtp.Core;
using SimpleOtp.Core.AutoUnlock;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

public class AutoUnlockTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public AutoUnlockTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-au-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "vault.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    private const string SampleUri =
        "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=6&period=30";

    // --- AutoUnlockClient ---------------------------------------------------

    [Fact]
    public async Task Client_ReturnsTrimmedBodyBytes_AndSendsAppKeyHeader()
    {
        string? seenHeader = null;
        var handler = new StubHandler(req =>
        {
            seenHeader = req.Headers.TryGetValues("X-App-Key", out var v) ? string.Join("", v) : null;
            return Text(HttpStatusCode.OK, "  the-secret-key\n");
        });

        var cfg = new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "app-123", Method = "POST" };
        byte[] key = await AutoUnlockClient.FetchKeyAsync(cfg, handler);

        Assert.Equal("the-secret-key", Encoding.UTF8.GetString(key));
        Assert.Equal("app-123", seenHeader);
    }

    [Fact]
    public async Task Client_Throws_OnNonSuccess()
    {
        var handler = new StubHandler(_ => Text(HttpStatusCode.Forbidden, "nope"));
        var cfg = new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "x" };
        await Assert.ThrowsAnyAsync<Exception>(() => AutoUnlockClient.FetchKeyAsync(cfg, handler));
    }

    [Fact]
    public async Task Client_Throws_OnEmptyBody()
    {
        var handler = new StubHandler(_ => Text(HttpStatusCode.OK, "   "));
        var cfg = new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "x" };
        await Assert.ThrowsAnyAsync<Exception>(() => AutoUnlockClient.FetchKeyAsync(cfg, handler));
    }

    // --- Vault double-seal --------------------------------------------------

    [Fact]
    public void Vault_SealedUnderPinAndAutoKey_BothUnlockSameDek()
    {
        var sealer = new FakeSealer();
        SealedBlob pinBlob, autoBlob;
        SimpleOtp.Core.Model.EncryptedSecret enc;
        using (var v = Vault.Create(sealer, "1234"u8))
        {
            pinBlob = v.SealedDek;
            autoBlob = v.SealCurrentUnder("auto-secret"u8);
            enc = v.Encrypt("the-seed"u8);
        }

        byte[] plain = "the-seed"u8.ToArray();

        using (var viaPin = Vault.Open(sealer.CloneSameDevice(), pinBlob, pinProtected: true))
        {
            viaPin.Unlock("1234"u8);
            Assert.Equal(plain, viaPin.Decrypt(enc));
        }

        using (var viaAuto = Vault.Open(sealer.CloneSameDevice(), pinBlob, pinProtected: true))
        {
            viaAuto.UnlockFrom(autoBlob, "auto-secret"u8);
            Assert.Equal(plain, viaAuto.Decrypt(enc)); // same DEK recovered via the auto blob
        }
    }

    // --- VaultService end-to-end -------------------------------------------

    [Fact]
    public async Task Service_AutoUnlock_OpensVault_AfterRestart()
    {
        var device = new FakeSealer();
        const string autoKey = "MY-PRESET-AUTO-KEY";
        string expectedCode;

        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew("1234"u8); // PIN-protected
            svc.AddAccount(OtpAuthUri.Parse(SampleUri));
            expectedCode = svc.GenerateCode(svc.Accounts[0], DateTime.UnixEpoch.AddSeconds(59));
            string returned = svc.EnableAutoUnlock(
                new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "k" }, autoKey);
            Assert.Equal(autoKey, returned);
            Assert.True(svc.AutoUnlockEnabled);
        }

        // Restart: same device, must auto-unlock via the (stubbed) webservice returning the key.
        using (var reopened = new VaultService(device.CloneSameDevice(), _path))
        {
            Assert.True(reopened.PinProtected);
            Assert.True(reopened.AutoUnlockEnabled);
            var handler = new StubHandler(_ => Text(HttpStatusCode.OK, autoKey));
            bool ok = await reopened.TryAutoUnlockAsync(handler);
            Assert.True(ok);
            Assert.Equal(expectedCode, reopened.GenerateCode(reopened.Accounts[0], DateTime.UnixEpoch.AddSeconds(59)));
        }
    }

    [Fact]
    public async Task Service_AutoUnlock_Fails_OnWrongKey_LeavesLocked()
    {
        var device = new FakeSealer();
        using (var svc = new VaultService(device, _path))
        {
            svc.CreateNew("1234"u8);
            svc.AddAccount(OtpAuthUri.Parse(SampleUri));
            svc.EnableAutoUnlock(new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "k" }, "right-key");
        }

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        var handler = new StubHandler(_ => Text(HttpStatusCode.OK, "WRONG-key"));
        bool ok = await reopened.TryAutoUnlockAsync(handler);
        Assert.False(ok);
        Assert.False(reopened.IsUnlocked);
    }

    [Fact]
    public async Task Service_TryAutoUnlock_FalseWhenNotConfigured()
    {
        var device = new FakeSealer();
        using var svc = new VaultService(device, _path);
        svc.CreateNew(ReadOnlySpan<byte>.Empty);
        Assert.False(svc.AutoUnlockEnabled);
        Assert.False(await svc.TryAutoUnlockAsync(new StubHandler(_ => Text(HttpStatusCode.OK, "x"))));
    }

    [Fact]
    public void Service_DisableAutoUnlock_ClearsIt()
    {
        var device = new FakeSealer();
        using var svc = new VaultService(device, _path);
        svc.CreateNew("1234"u8);
        svc.EnableAutoUnlock(new AutoUnlockConfig { Url = "http://localhost/unlock", AppKey = "k" }, "key");
        Assert.True(svc.AutoUnlockEnabled);
        svc.DisableAutoUnlock();
        Assert.False(svc.AutoUnlockEnabled);
        Assert.Null(svc.AutoUnlock);
    }

    private static HttpResponseMessage Text(HttpStatusCode code, string body)
        => new(code) { Content = new StringContent(body, Encoding.UTF8, "text/plain") };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(respond(request));
    }
}
