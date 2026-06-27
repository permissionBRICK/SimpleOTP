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

    // Adds an account whose Label is <paramref name="label"/>, so order can be asserted by label.
    private static string AddLabeled(VaultService svc, string label, string? folderId = null)
        => svc.AddAccount(OtpAuthUri.Parse(SampleUri.Replace("octocat", label)), folderId).Id;

    private static string[] Labels(IEnumerable<SimpleOtp.Core.Model.Account> accounts)
        => accounts.Select(a => a.Label).ToArray();

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
    public void MoveAccountUpDown_ReordersWithinTopLevel()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        AddLabeled(svc, "a");
        AddLabeled(svc, "b");
        AddLabeled(svc, "c");

        string b = svc.AccountsInFolder(null)[1].Id;
        Assert.True(svc.MoveAccountUp(b));
        Assert.Equal(new[] { "b", "a", "c" }, Labels(svc.AccountsInFolder(null)));
        Assert.True(svc.MoveAccountDown(b));
        Assert.Equal(new[] { "a", "b", "c" }, Labels(svc.AccountsInFolder(null)));
    }

    [Fact]
    public void MoveAccount_OnlyReordersWithinItsOwnFolderScope()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        var f = svc.AddFolder("F");
        AddLabeled(svc, "a");           // top level
        AddLabeled(svc, "b", f.Id);     // folder
        AddLabeled(svc, "c");           // top level
        string d = AddLabeled(svc, "d", f.Id); // folder

        // d's nearest preceding same-folder neighbour is b (with c, a top-level account, in between).
        Assert.True(svc.MoveAccountUp(d));
        Assert.Equal(new[] { "d", "b" }, Labels(svc.AccountsInFolder(f.Id)));
        Assert.Equal(new[] { "a", "c" }, Labels(svc.AccountsInFolder(null))); // top level untouched
    }

    [Fact]
    public void MoveAccount_AtScopeEdge_OrUnknown_IsNoOp()
    {
        using var svc = NewUnlocked(new FakeSealer(), _path);
        AddLabeled(svc, "a");
        AddLabeled(svc, "b");

        Assert.False(svc.MoveAccountUp(svc.AccountsInFolder(null)[0].Id));   // already first
        Assert.False(svc.MoveAccountDown(svc.AccountsInFolder(null)[1].Id)); // already last
        Assert.False(svc.MoveAccountUp("does-not-exist"));
        Assert.Equal(new[] { "a", "b" }, Labels(svc.AccountsInFolder(null)));
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
