using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Crypto;

namespace SimpleOtp.Tests;

/// <summary>
/// Covers the wrong-PIN / lockout UX: the sealer must report how many attempts remain and, once the
/// dictionary-attack limit is hit, surface a typed <see cref="TpmLockedException"/> with the recovery
/// interval — never an opaque error that would crash the unlock screen. The <see cref="FakeSealer"/>
/// models the real TPM's attempt counter so this can be exercised without touching the chip.
/// </summary>
public class TpmLockoutTests
{
    private const int MaxTries = 3;
    private const int RecoverySeconds = 120;

    private static (Vault vault, SealedBlob dek) OpenPinVault(FakeSealer sealer)
    {
        SealedBlob dek;
        using (var creating = Vault.Create(sealer, "1234"u8))
            dek = creating.SealedDek;
        return (Vault.Open(sealer, dek, pinProtected: true), dek);
    }

    [Fact]
    public void WrongPin_ReportsDecreasingRemainingAttempts_ThenLocksOut()
    {
        var sealer = new FakeSealer(maxAuthFail: MaxTries, recoverySeconds: RecoverySeconds);
        var (vault, _) = OpenPinVault(sealer);
        using var _v = vault;

        var first = Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8));
        Assert.Equal(2, first.RemainingAttempts);

        var second = Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8));
        Assert.Equal(1, second.RemainingAttempts);

        // The attempt that hits the limit reports lockout (not a wrong-PIN error), carrying the interval.
        var locked = Assert.Throws<TpmLockedException>(() => vault.Unlock("0000"u8));
        Assert.Equal(RecoverySeconds, locked.RecoverySeconds);
    }

    [Fact]
    public void OnceLockedOut_EvenTheCorrectPinIsRefused()
    {
        var sealer = new FakeSealer(maxAuthFail: 1, recoverySeconds: RecoverySeconds);
        var (vault, _) = OpenPinVault(sealer);
        using var _v = vault;

        Assert.Throws<TpmLockedException>(() => vault.Unlock("0000"u8)); // trips lockout immediately
        Assert.Throws<TpmLockedException>(() => vault.Unlock("1234"u8)); // correct PIN, still locked
    }

    [Fact]
    public void CorrectPin_ResetsTheAttemptCounter()
    {
        var sealer = new FakeSealer(maxAuthFail: MaxTries, recoverySeconds: RecoverySeconds);
        var (vault, _) = OpenPinVault(sealer);
        using var _v = vault;

        Assert.Equal(2, Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8)).RemainingAttempts);

        vault.Unlock("1234"u8); // a good unlock clears the counter...
        Assert.True(vault.IsUnlocked);

        // ...so the next wrong attempt starts the budget over rather than tripping lockout early.
        Assert.Equal(2, Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8)).RemainingAttempts);
    }

    [Fact]
    public void WrongPinWithoutDaInfo_StillReportsPlainWrongPin()
    {
        var sealer = new FakeSealer(); // DA simulation off → no attempts-remaining info
        var (vault, _) = OpenPinVault(sealer);
        using var _v = vault;

        Assert.Null(Assert.Throws<WrongPinException>(() => vault.Unlock("0000"u8)).RemainingAttempts);
    }

    [Theory]
    [InlineData(null, "Wrong PIN. Try again.")]
    [InlineData(3, "Wrong PIN. 3 attempts left before the TPM locks.")]
    [InlineData(1, "Wrong PIN. 1 attempt left before the TPM locks.")] // singular
    [InlineData(0, "Wrong PIN. Try again.")] // 0 left is conveyed by the lockout flow, not this message
    public void FormatWrongPin_ProducesExpectedText(int? remaining, string expected)
        => Assert.Equal(expected, MainWindowViewModel.FormatWrongPin(remaining));

    [Theory]
    [InlineData(45, "Try again in 45s.")]
    [InlineData(125, "Try again in 2m 05s.")]
    [InlineData(3725, "Try again in 1h 02m 05s.")]
    public void FormatLockoutCountdown_FormatsTime(int seconds, string expectedTail)
        => Assert.EndsWith(expectedTail, MainWindowViewModel.FormatLockoutCountdown(seconds));
}
