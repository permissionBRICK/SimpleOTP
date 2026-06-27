using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleOtp.App.ViewModels;

/// <summary>One unit of background work: compute <see cref="Item"/>'s code for TOTP <see cref="Counter"/>.</summary>
internal readonly record struct GenRequest(AccountItemViewModel Item, long Counter);

/// <summary>
/// FIFO work queue for code generation with one twist: a single card can be flagged urgent (the one the
/// pointer is hovering), and the next dequeue serves that card's earliest pending request ahead of the
/// backlog — so hovering a not-yet-loaded code jumps it to the front. Safe for one UI-thread producer
/// and one background consumer.
/// </summary>
internal sealed class GenQueue
{
    private readonly object _gate = new();
    private readonly LinkedList<GenRequest> _items = new();
    private readonly SemaphoreSlim _available = new(0);
    private AccountItemViewModel? _urgent;

    public void Enqueue(GenRequest req)
    {
        lock (_gate)
            _items.AddLast(req);
        _available.Release();
    }

    /// <summary>Flags a card whose queued work should be served first.</summary>
    public void SetUrgent(AccountItemViewModel item)
    {
        lock (_gate)
            _urgent = item;
    }

    /// <summary>
    /// Clears the urgent flag, but only if it still points at <paramref name="item"/> (so entering the
    /// next card before leaving this one doesn't wipe the newer urgency).
    /// </summary>
    public void ClearUrgent(AccountItemViewModel item)
    {
        lock (_gate)
            if (ReferenceEquals(_urgent, item))
                _urgent = null;
    }

    public async Task<GenRequest> DequeueAsync(CancellationToken ct)
    {
        await _available.WaitAsync(ct).ConfigureAwait(false);
        lock (_gate)
        {
            LinkedListNode<GenRequest>? node = null;
            if (_urgent is not null)
                for (var n = _items.First; n is not null; n = n.Next)
                    if (ReferenceEquals(n.Value.Item, _urgent)) { node = n; break; }
            node ??= _items.First!; // WaitAsync succeeded, so there is at least one item
            _items.Remove(node);
            return node.Value;
        }
    }
}
