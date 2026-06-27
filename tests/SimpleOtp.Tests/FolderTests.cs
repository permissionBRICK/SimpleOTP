using SimpleOtp.Core;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

/// <summary>
/// Folders are cleartext organizational metadata: creating, renaming, moving accounts between them and
/// deleting them must persist, and deleting a folder must never take its accounts down with it.
/// </summary>
public class FolderTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public FolderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-folder-tests-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "vault.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    private const string SampleUri =
        "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    private static VaultService NewUnlocked(FakeSealer sealer, string path)
    {
        var svc = new VaultService(sealer, path);
        svc.CreateNew(ReadOnlySpan<byte>.Empty);
        return svc;
    }

    [Fact]
    public void AddFolder_AndPlaceAccount_FiltersByFolder()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var work = svc.AddFolder("Work");

        var inFolder = svc.AddAccount(OtpAuthUri.Parse(SampleUri), work.Id);
        var loose = svc.AddAccount(OtpAuthUri.Parse(SampleUri.Replace("octocat", "hubber")));

        Assert.Equal(work.Id, inFolder.FolderId);
        Assert.Null(loose.FolderId);

        Assert.Equal(new[] { inFolder.Id }, svc.AccountsInFolder(work.Id).Select(a => a.Id));
        Assert.Equal(new[] { loose.Id }, svc.AccountsInFolder(null).Select(a => a.Id));
    }

    [Fact]
    public void AddAccount_WithUnknownFolder_FallsBackToTopLevel()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var acct = svc.AddAccount(OtpAuthUri.Parse(SampleUri), "does-not-exist");
        Assert.Null(acct.FolderId);
    }

    [Fact]
    public void MoveAccount_MovesBetweenFolders_AndToTopLevel()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var a = svc.AddFolder("A");
        var b = svc.AddFolder("B");
        var acct = svc.AddAccount(OtpAuthUri.Parse(SampleUri), a.Id);

        svc.MoveAccount(acct.Id, b.Id);
        Assert.Equal(b.Id, acct.FolderId);
        Assert.Single(svc.AccountsInFolder(b.Id));
        Assert.Empty(svc.AccountsInFolder(a.Id));

        svc.MoveAccount(acct.Id, null); // back to the top level
        Assert.Null(acct.FolderId);
        Assert.Single(svc.AccountsInFolder(null));
    }

    [Fact]
    public void MoveAccount_ToUnknownFolder_IsIgnored()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var a = svc.AddFolder("A");
        var acct = svc.AddAccount(OtpAuthUri.Parse(SampleUri), a.Id);

        svc.MoveAccount(acct.Id, "nope");
        Assert.Equal(a.Id, acct.FolderId); // unchanged
    }

    [Fact]
    public void DeleteFolder_KeepsAccounts_MovingThemToTopLevel()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var folder = svc.AddFolder("Temp");
        var acct = svc.AddAccount(OtpAuthUri.Parse(SampleUri), folder.Id);

        svc.DeleteFolder(folder.Id);

        Assert.Empty(svc.Folders);
        Assert.Single(svc.Accounts);                 // account survived
        Assert.Null(svc.Accounts[0].FolderId);       // and fell back to the top level
        Assert.Equal(acct.Id, svc.AccountsInFolder(null).Single().Id);
    }

    [Fact]
    public void RenameFolder_Persists()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var folder = svc.AddFolder("Old");
        svc.RenameFolder(folder.Id, "  New  ");
        Assert.Equal("New", svc.Folders.Single().Name); // trimmed
    }

    [Fact]
    public void Folders_And_Assignments_SurviveReopen()
    {
        var device = new FakeSealer();
        string folderId, acctId;
        using (var svc = NewUnlocked(device, _path))
        {
            folderId = svc.AddFolder("Work").Id;
            acctId = svc.AddAccount(OtpAuthUri.Parse(SampleUri), folderId).Id;
        }

        using var reopened = new VaultService(device.CloneSameDevice(), _path);
        reopened.Unlock(ReadOnlySpan<byte>.Empty);

        var folder = Assert.Single(reopened.Folders);
        Assert.Equal(folderId, folder.Id);
        Assert.Equal("Work", folder.Name);
        var acct = Assert.Single(reopened.AccountsInFolder(folderId));
        Assert.Equal(acctId, acct.Id);
    }
}
