using System;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Tests;

/// <summary>
/// Covers the background-generation state machine on the card: claiming work (deduped), delivering a
/// finished code, pre-generating the next window, and promoting that cache at the rollover without
/// asking for the code again (so a rollover never blocks on the TPM).
/// </summary>
public class AccountItemViewModelTests
{
    private static Account Acct(int period = 30) =>
        new() { Issuer = "ACME", Label = "user", Period = period, Digits = 6 };

    // counter = unixSeconds / period; with period 30, second 40 → counter 1, second 70 → counter 2.
    private static DateTime At(int seconds) => DateTime.UnixEpoch.AddSeconds(seconds);

    [Fact]
    public void ClaimCurrent_IsDeduped_AndDeliverShowsCode()
    {
        var vm = new AccountItemViewModel(Acct());
        DateTime t = At(40); // counter 1

        Assert.Equal("------", vm.Code);
        Assert.Equal(1L, vm.ClaimCurrentWork(t));
        Assert.Null(vm.ClaimCurrentWork(t)); // already in flight — don't re-enqueue

        vm.Deliver(1, "123456", t);
        Assert.Equal("123 456", vm.Code);
        Assert.Equal("123456", vm.RawCode);
        Assert.False(vm.IsStale); // live code for the current window
        Assert.Null(vm.ClaimCurrentWork(t)); // already displayed — no work needed
    }

    [Fact]
    public void Code_IsStale_UntilCurrentWindowDelivered_AndAgainAfterItLapses()
    {
        var vm = new AccountItemViewModel(Acct());
        Assert.True(vm.IsStale); // nothing generated yet

        DateTime t1 = At(40); // counter 1
        vm.Refresh(t1);
        Assert.True(vm.IsStale); // still awaiting the first code

        vm.Deliver(1, "111111", t1);
        Assert.False(vm.IsStale);
        vm.Refresh(t1);
        Assert.False(vm.IsStale);

        DateTime t2 = At(70); // window rolled to counter 2, refreshed code not in yet
        vm.Refresh(t2);
        Assert.True(vm.IsStale); // old code greyed out until the new one arrives

        vm.Deliver(2, "222222", t2);
        Assert.False(vm.IsStale);
    }

    [Fact]
    public void NextCode_IsPrefetched_AndPromotedAtRolloverWithoutRegenerating()
    {
        var vm = new AccountItemViewModel(Acct());
        DateTime t1 = At(40); // counter 1
        vm.Deliver(1, "111111", t1);

        Assert.Equal(2L, vm.ClaimPrefetchWork(t1)); // claim the next window ahead of time
        Assert.Null(vm.ClaimPrefetchWork(t1));      // already in flight

        vm.Deliver(2, "222222", t1); // arrives early → cached, not shown yet
        Assert.Equal("111 111", vm.Code);
        Assert.Null(vm.ClaimPrefetchWork(t1)); // cached — no work needed

        DateTime t2 = At(70); // window rolls into counter 2
        vm.Refresh(t2);
        Assert.Equal("222 222", vm.Code);          // promoted from cache instantly
        Assert.False(vm.IsStale);                  // never went stale — cache was ready
        Assert.Null(vm.ClaimCurrentWork(t2));       // no TPM call on the rollover
    }

    [Fact]
    public void StaleDelivery_ForAPastWindow_IsDropped()
    {
        var vm = new AccountItemViewModel(Acct());
        DateTime t = At(70); // counter 2

        vm.Deliver(2, "654321", t);
        Assert.Equal("654 321", vm.Code);

        vm.Deliver(1, "000000", t); // a late result for the previous window must not overwrite
        Assert.Equal("654 321", vm.Code);
    }

    [Fact]
    public void EmptyDelivery_ShowsError_AndIsNotRetriedSameWindow()
    {
        var vm = new AccountItemViewModel(Acct());
        DateTime t = At(40); // counter 1

        Assert.Equal(1L, vm.ClaimCurrentWork(t));
        vm.Deliver(1, "", t); // generation failed (e.g. transient TPM error)
        Assert.Equal("error", vm.Code);
        Assert.Null(vm.ClaimCurrentWork(t)); // one attempt per window — don't hammer a failing account
    }
}
