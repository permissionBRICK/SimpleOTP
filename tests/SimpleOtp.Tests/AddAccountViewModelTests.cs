using System.Linq;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.Tests;

public class AddAccountViewModelTests
{
    [Fact]
    public void MultiPartMigration_AccumulatesAcrossParts_AndDedupes()
    {
        // A large export splits into several QRs; the importer must combine them.
        OtpAuthData[] accounts = [.. Enumerable.Range(0, 8).Select(i =>
            new OtpAuthData($"Issuer{i}", $"user{i}@example.com", [(byte)i, 1, 2, 3, 4, 5, 6, 7, 8, 9], OtpAlgorithm.Sha1, 6, 30))];
        var parts = OtpAuthMigration.BuildExport(accounts, maxPayloadBytes: 150);
        Assert.True(parts.Count >= 2); // forced into multiple parts

        var vm = new AddAccountViewModel();
        vm.ApplyDecoded(parts[0]);
        Assert.True(vm.IsBulk);
        int afterFirst = vm.BulkItems.Count;

        vm.ApplyDecoded(parts[1]);
        Assert.True(vm.BulkItems.Count > afterFirst); // accumulated, not replaced

        for (int i = 2; i < parts.Count; i++)
            vm.ApplyDecoded(parts[i]);
        Assert.Equal(8, vm.SelectedAccounts().Count); // all parts combined

        vm.ApplyDecoded(parts[0]); // re-loading a part doesn't duplicate
        Assert.Equal(8, vm.SelectedAccounts().Count);
    }

    [Fact]
    public void LoadFromPaste_Uri_PopulatesAllFields()
    {
        var vm = new AddAccountViewModel
        {
            PasteInput = "otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60",
        };
        vm.LoadFromPasteCommand.Execute(null);

        Assert.False(vm.IsError);
        Assert.Equal("ACME", vm.Issuer);
        Assert.Equal("bob", vm.Label);
        Assert.Equal(1, vm.SelectedAlgorithmIndex); // SHA256
        Assert.Equal(8, vm.Digits);
        Assert.Equal(60, vm.Period);
        Assert.Equal("JBSWY3DPEHPK3PXP", vm.Secret);
    }

    [Fact]
    public void LoadFromPaste_RawSecret_GoesIntoSecretField()
    {
        var vm = new AddAccountViewModel { PasteInput = "JBSWY3DPEHPK3PXP" };
        vm.LoadFromPasteCommand.Execute(null);
        Assert.Equal("JBSWY3DPEHPK3PXP", vm.Secret);
    }

    [Fact]
    public void ApplyDecoded_NonUri_SetsError()
    {
        var vm = new AddAccountViewModel();
        vm.ApplyDecoded("this is not a uri");
        Assert.True(vm.IsError);
    }

    [Fact]
    public void Build_Valid_ReturnsDescriptor()
    {
        var vm = new AddAccountViewModel
        {
            Issuer = "GitHub",
            Label = "octocat",
            Secret = "JBSWY3DPEHPK3PXP",
            SelectedAlgorithmIndex = 2, // SHA512
            Digits = 8,
            Period = 30,
        };
        var data = vm.Build();
        Assert.NotNull(data);
        Assert.Equal("GitHub", data!.Issuer);
        Assert.Equal("octocat", data.Label);
        Assert.Equal(OtpAlgorithm.Sha512, data.Algorithm);
        Assert.Equal(8, data.Digits);
        Assert.NotEmpty(data.SecretBytes);
    }

    [Fact]
    public void Build_EmptySecret_FailsWithError()
    {
        var vm = new AddAccountViewModel { Issuer = "x" };
        Assert.Null(vm.Build());
        Assert.True(vm.IsError);
    }

    [Fact]
    public void Build_InvalidBase32_FailsWithError()
    {
        var vm = new AddAccountViewModel { Issuer = "x", Secret = "10101810" }; // 0/1/8 not in Base32 alphabet
        Assert.Null(vm.Build());
        Assert.True(vm.IsError);
    }

    [Fact]
    public void Build_NoIssuerOrLabel_FailsWithError()
    {
        var vm = new AddAccountViewModel { Secret = "JBSWY3DPEHPK3PXP" };
        Assert.Null(vm.Build());
        Assert.True(vm.IsError);
    }
}
