using System;
using System.Threading;
using System.Threading.Tasks;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Model;

namespace SimpleOtp.Tests;

/// <summary>
/// The background code-generation queue: FIFO normally, but the hovered card's pending work jumps to the
/// front so a code you're looking at appears first even behind a long backlog.
/// </summary>
public class GenQueueTests
{
    private static AccountItemViewModel Card() =>
        new(new Account { Issuer = "X", Label = "y", Period = 30, Digits = 6 });

    [Fact]
    public async Task DrainsInFifoOrder_WithoutUrgency()
    {
        var q = new GenQueue();
        AccountItemViewModel a = Card(), b = Card(), c = Card();
        q.Enqueue(new GenRequest(a, 1));
        q.Enqueue(new GenRequest(b, 1));
        q.Enqueue(new GenRequest(c, 1));

        Assert.Same(a, (await q.DequeueAsync(default)).Item);
        Assert.Same(b, (await q.DequeueAsync(default)).Item);
        Assert.Same(c, (await q.DequeueAsync(default)).Item);
    }

    [Fact]
    public async Task UrgentItem_JumpsAheadOfBacklog()
    {
        var q = new GenQueue();
        AccountItemViewModel a = Card(), b = Card(), c = Card();
        q.Enqueue(new GenRequest(a, 1));
        q.Enqueue(new GenRequest(b, 1));
        q.Enqueue(new GenRequest(c, 1));

        q.SetUrgent(c); // pointer hovers c while a and b are still queued
        Assert.Same(c, (await q.DequeueAsync(default)).Item); // served first
        Assert.Same(a, (await q.DequeueAsync(default)).Item); // then back to FIFO
        Assert.Same(b, (await q.DequeueAsync(default)).Item);
    }

    [Fact]
    public async Task UrgentItem_ServesItsEarliestRequestFirst()
    {
        var q = new GenQueue();
        AccountItemViewModel x = Card(), y = Card();
        q.Enqueue(new GenRequest(x, 1)); // x current
        q.Enqueue(new GenRequest(y, 1));
        q.Enqueue(new GenRequest(x, 2)); // x prefetch

        q.SetUrgent(x);
        Assert.Equal(1L, (await q.DequeueAsync(default)).Counter); // x's current (visible) code before its prefetch
        Assert.Equal(2L, (await q.DequeueAsync(default)).Counter); // still urgent → its prefetch next
        Assert.Same(y, (await q.DequeueAsync(default)).Item);
    }

    [Fact]
    public async Task ClearUrgent_OnlyClearsMatchingItem()
    {
        var q = new GenQueue();
        AccountItemViewModel a = Card(), b = Card();
        q.Enqueue(new GenRequest(a, 1));
        q.Enqueue(new GenRequest(b, 1));

        q.SetUrgent(b);
        q.ClearUrgent(a);  // leaving a *different* card must not wipe b's urgency
        Assert.Same(b, (await q.DequeueAsync(default)).Item);

        var c = Card();
        q.Enqueue(new GenRequest(c, 1));
        q.ClearUrgent(b);  // now genuinely cleared → FIFO resumes
        Assert.Same(a, (await q.DequeueAsync(default)).Item);
        Assert.Same(c, (await q.DequeueAsync(default)).Item);
    }

    [Fact]
    public async Task DequeueAsync_RespectsCancellation_WhenEmpty()
    {
        var q = new GenQueue();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.DequeueAsync(cts.Token));
    }
}
