using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Totp;

namespace SimpleOtp.App.ViewModels;

/// <summary>
/// One row/card in the main list: the account, its current code, and the countdown.
///
/// Code generation is expensive (in Advanced mode every code is a TPM round-trip), so it is never
/// done on the UI thread. Instead this card tracks, by TOTP counter, the code it is currently showing
/// and a pre-generated code for the <em>next</em> window. The owning <see cref="MainWindowViewModel"/>
/// drives a background worker that fulfils the work this card claims (<see cref="ClaimCurrentWork"/> /
/// <see cref="ClaimPrefetchWork"/>) and hands results back via <see cref="Deliver"/>. The cheap
/// wall-clock countdown still updates on the UI timer in <see cref="Refresh"/>, which also promotes a
/// pre-generated code the instant its window goes live — so a rollover never blocks on the TPM.
/// </summary>
public partial class AccountItemViewModel : ViewModelBase
{
    private readonly Account _account;

    // Counter of the code currently in `Code` (-1 = nothing shown yet).
    private long _displayedCounter = -1;
    // A code generated ahead of time for a future counter, swapped in when its window arrives.
    private long _cachedCounter = -1;
    private string _cachedRawCode = "";
    // Counters currently queued/in-flight on the worker, so repeated ticks don't re-enqueue them.
    private readonly HashSet<long> _pending = [];

    public AccountItemViewModel(Account account)
    {
        _account = account;
    }

    public string Id => _account.Id;

    /// <summary>The underlying account, used by the background worker to generate codes.</summary>
    public Account Account => _account;

    /// <summary>The TOTP period in seconds.</summary>
    public int Period => _account.Period;

    /// <summary>Primary line: issuer if present, else the label.</summary>
    public string Title => string.IsNullOrWhiteSpace(_account.Issuer) ? _account.Label : _account.Issuer;

    /// <summary>Secondary line: the account label (blank when it would duplicate the title).</summary>
    public string Subtitle => string.IsNullOrWhiteSpace(_account.Issuer) ? "" : _account.Label;

    /// <summary>The raw (unformatted) current code, used for clipboard copy.</summary>
    public string RawCode { get; private set; } = "";

    [ObservableProperty] private string _code = "------";
    [ObservableProperty] private int _secondsRemaining;
    [ObservableProperty] private double _progress;
    [ObservableProperty] private bool _isExpiring;

    /// <summary>
    /// True when the shown code's window has passed (or none has been generated yet) but the fresh code
    /// for the current window hasn't been delivered — the UI greys it out so a stale code isn't trusted.
    /// </summary>
    [ObservableProperty] private bool _isStale = true;

    /// <summary>
    /// Cheap, UI-thread, every-tick update: refreshes the wall-clock-derived countdown and, when the
    /// window has rolled into a counter we already pre-generated, swaps that code in instantly (no
    /// generation on the rollover). Never touches the vault.
    /// </summary>
    public void Refresh(DateTime utc)
    {
        long counter = CounterAt(utc);
        if (counter != _displayedCounter && counter == _cachedCounter)
        {
            _displayedCounter = counter;
            RawCode = _cachedRawCode;
            Code = Format(RawCode);
            _cachedCounter = -1;
            _cachedRawCode = "";
        }

        Progress = TotpGenerator.RemainingFraction(_account.Period, utc);
        SecondsRemaining = TotpGenerator.RemainingSeconds(_account.Period, utc);
        IsExpiring = SecondsRemaining <= 5;
        IsStale = _displayedCounter != counter; // shown code's window has passed (or none shown yet)
    }

    /// <summary>
    /// Claims the current window's code for background generation if it isn't already shown, cached, or
    /// in flight. Returns the counter to generate (and marks it in-flight), or null if nothing is needed.
    /// </summary>
    public long? ClaimCurrentWork(DateTime utc) => Claim(CounterAt(utc));

    /// <summary>
    /// Claims the next window's code so it is ready before the rollover. Returns the counter to
    /// generate (and marks it in-flight), or null if it's already cached or in flight.
    /// </summary>
    public long? ClaimPrefetchWork(DateTime utc) => Claim(CounterAt(utc) + 1);

    private long? Claim(long counter)
    {
        if (counter == _displayedCounter || counter == _cachedCounter || _pending.Contains(counter))
            return null;
        _pending.Add(counter);
        return counter;
    }

    /// <summary>
    /// Receives a finished code from the worker (UI thread). Shows it immediately if it's the current
    /// window, caches it if it's a future window, or drops it if its window has already passed. Empty
    /// strings (generation failure) are stored too, so a failing account doesn't retry every tick.
    /// </summary>
    public void Deliver(long counter, string rawCode, DateTime utc)
    {
        _pending.Remove(counter);
        long current = CounterAt(utc);
        if (counter < current)
            return; // window already gone; Refresh/Tick will claim the new current code

        if (counter == current)
        {
            _displayedCounter = counter;
            RawCode = rawCode;
            Code = Format(RawCode);
            IsStale = false; // fresh code for the current window
        }
        else
        {
            _cachedCounter = counter;
            _cachedRawCode = rawCode;
        }
    }

    private long CounterAt(DateTime utc)
        => (long)((utc - DateTime.UnixEpoch).TotalSeconds / _account.Period);

    private static string Format(string code) => code.Length switch
    {
        6 => $"{code[..3]} {code[3..]}",
        8 => $"{code[..4]} {code[4..]}",
        _ => string.IsNullOrEmpty(code) ? "error" : code,
    };
}
