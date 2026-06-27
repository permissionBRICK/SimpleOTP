using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.App.Services;
using SimpleOtp.Core;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.ViewModels;

/// <summary>
/// Root view model. Owns the <see cref="VaultService"/> and drives the whole UI state machine:
/// no-TPM → error, locked → unlock, ready → token list. A single shared timer refreshes every card.
/// </summary>
public partial class MainWindowViewModel : ViewModelBase
{
    private readonly ISecretSealer? _sealer;
    private readonly DispatcherTimer _timer;
    private int _toastToken;

    // Background code generation. Codes are expensive (a TPM round-trip each in Advanced mode), so they
    // are never computed on the UI thread. The timer enqueues per-card work here; a single worker drains
    // it one code at a time and posts each result back to the card. The queue lets the hovered card jump
    // ahead. Recreated per unlocked session so a lock/reload cancels any in-flight work before the vault
    // key is zeroed.
    private GenQueue? _genQueue;
    private CancellationTokenSource? _genCts;

    public ObservableCollection<AccountItemViewModel> Tokens { get; } = [];

    // Mutually-exclusive top-level states.
    [ObservableProperty] private bool _isReady;
    [ObservableProperty] private bool _isLocked;
    [ObservableProperty] private bool _isNoTpm;
    [ObservableProperty] private bool _isError;
    [ObservableProperty] private bool _isConnecting;
    [ObservableProperty] private bool _isLoading;

    /// <summary>True in Advanced Security mode — drives the "ADVANCED" badge. Both modes still unlock/lock.</summary>
    [ObservableProperty] private bool _isAdvancedMode;

    /// <summary>Whether the lock button applies (ready and unlocked). Both modes can be locked.</summary>
    [ObservableProperty] private bool _canLock;

    /// <summary>True when network auto-unlock is configured (controls the "retry" button on the lock screen).</summary>
    [ObservableProperty] private bool _autoUnlockAvailable;

    [ObservableProperty] private string _errorMessage = "";
    [ObservableProperty] private bool _hasAccounts;
    [ObservableProperty] private string _storePath = "";
    [ObservableProperty] private bool _pinSet;

    // Unlock view.
    [ObservableProperty] private string _unlockPin = "";
    [ObservableProperty] private string _unlockError = "";

    // Toast overlay.
    [ObservableProperty] private bool _isToastVisible;
    [ObservableProperty] private string _toastText = "";

    // Software update: drives the top-bar indicator. The actual check + popup are run by the view
    // (it owns the window needed to host the dialog); see MainWindow.CheckForUpdatesAsync.
    [ObservableProperty] private bool _updateAvailable;

    /// <summary>The pending update (set once a check finds one), reused when the indicator is clicked.</summary>
    public UpdateInfo? AvailableUpdate { get; private set; }

    /// <summary>The update service, or null at design time / in tests.</summary>
    public UpdateService? Update { get; }

    /// <summary>Design-time constructor (no TPM); shows the empty ready state in the previewer.</summary>
    public MainWindowViewModel() : this(null) { }

    public MainWindowViewModel(ISecretSealer? sealer, UpdateService? update = null)
    {
        _sealer = sealer;
        Update = update;
        _timer = new DispatcherTimer(DispatcherPriority.Normal) { Interval = TimeSpan.FromMilliseconds(100) };
        _timer.Tick += (_, _) => Tick();
        if (sealer is null)
            IsReady = true; // design-time
    }

    /// <summary>Records a found update so the top-bar indicator appears and the popup can be reopened.</summary>
    public void SetUpdateAvailable(UpdateInfo info)
    {
        AvailableUpdate = info;
        UpdateAvailable = true;
    }

    public VaultService? Service { get; private set; }

    /// <summary>Detects the TPM and opens/creates the vault. Call once after the window is shown.</summary>
    public async Task BootstrapAsync()
    {
        if (_sealer is null) return;
        // Show the loading spinner immediately, then do the (slow, first-call) TPM/vault work off the UI
        // thread so the window paints right away instead of sitting blank while the TPM warms up.
        SetState(loading: true);
        try
        {
            bool available = await Task.Run(() => _sealer.IsAvailable);
            if (!available)
            {
                SetState(noTpm: true);
                return;
            }

            VaultService service = await Task.Run(() => new VaultService(_sealer));
            Service = service;
            StorePath = service.StorePath;
            AutoUnlockAvailable = service.AutoUnlockEnabled;
            IsAdvancedMode = service.Mode == SecurityMode.Advanced;

            // Both modes seal a vault key under the PIN / network-unlock, so the unlock flow is the same;
            // Advanced just uses that key as the HMAC auth rather than an AES key.
            if (!service.IsInitialized)
            {
                await Task.Run(() => service.CreateNew(ReadOnlySpan<byte>.Empty)); // first run: Simple, no PIN
                EnterReady();
            }
            else if (!service.PinProtected)
            {
                await Task.Run(() => service.Unlock(ReadOnlySpan<byte>.Empty));
                EnterReady();
            }
            else if (service.AutoUnlockEnabled && await TryAutoUnlockAsync())
            {
                EnterReady();
            }
            else
            {
                SetState(locked: true);
            }
        }
        catch (WrongDeviceException ex)
        {
            SetError(ex.Message);
        }
        catch (SealerException ex)
        {
            SetError(ex.Message);
        }
        catch (Exception ex)
        {
            SetError("Unexpected error opening the vault: " + ex.Message);
        }
    }

    /// <summary>Tries network auto-unlock, showing a brief "connecting" state. Returns success.</summary>
    private async Task<bool> TryAutoUnlockAsync()
    {
        if (Service is null) return false;
        SetState(connecting: true);
        bool ok = await Service.TryAutoUnlockAsync();
        return ok;
    }

    [RelayCommand]
    private async Task RetryAutoUnlock()
    {
        if (Service is null) return;
        if (await TryAutoUnlockAsync())
            EnterReady();
        else
        {
            UnlockError = "Auto-unlock failed. Check the service, or enter your PIN.";
            SetState(locked: true);
        }
    }

    [RelayCommand]
    private void Unlock()
    {
        if (Service is null) return;
        try
        {
            Service.Unlock(UnlockPin);
            UnlockPin = "";
            UnlockError = "";
            EnterReady();
        }
        catch (WrongPinException)
        {
            UnlockError = "Wrong PIN. Try again.";
        }
        catch (TpmLockedException ex)
        {
            UnlockError = ex.Message;
        }
        catch (WrongDeviceException ex)
        {
            SetError(ex.Message);
        }
    }

    [RelayCommand]
    private void Lock()
    {
        if (Service is null || !IsReady) return;
        _timer.Stop();
        StopGenerator(); // cancel in-flight generation before the vault key is zeroed
        Tokens.Clear();
        HasAccounts = false;
        Service.Lock();
        UnlockPin = "";
        SetState(locked: true);
    }

    /// <summary>Rebuilds the token list from the (unlocked) vault and kicks off background generation.</summary>
    public void ReloadTokens()
    {
        if (Service is null) return;
        bool wasRunning = _timer.IsEnabled;
        _timer.Stop();
        StartGenerator(); // fresh work queue tied to the rebuilt card set
        Tokens.Clear();
        foreach (var account in Service.Accounts)
            Tokens.Add(new AccountItemViewModel(account));
        HasAccounts = Tokens.Count > 0;
        Tick(); // queues the first round of generation; codes stream in as the worker finishes each
        if (wasRunning || IsReady) _timer.Start();
    }

    public void DeleteItem(AccountItemViewModel item)
    {
        if (Service is null) return;
        Service.RemoveAccount(item.Id);
        Tokens.Remove(item);
        HasAccounts = Tokens.Count > 0;
    }

    public void NotifySettingsChanged()
    {
        IsAdvancedMode = Service?.Mode == SecurityMode.Advanced;
        PinSet = Service?.PinProtected ?? false;
        AutoUnlockAvailable = Service?.AutoUnlockEnabled ?? false;
        CanLock = IsReady;
        ReloadTokens(); // a mode switch rewrote how each secret is stored; rebuild the cards
    }

    public async Task ShowToastAsync(string message)
    {
        ToastText = message;
        IsToastVisible = true;
        int token = Interlocked.Increment(ref _toastToken);
        await Task.Delay(1400);
        if (_toastToken == token)
            IsToastVisible = false;
    }

    private void EnterReady()
    {
        ReloadTokens();
        SetState(ready: true);
        PinSet = Service?.PinProtected ?? false;
        _timer.Start();
    }

    private void Tick()
    {
        var now = DateTime.UtcNow;
        // Cheap, every tick: countdown + promote any code we already pre-generated for this window.
        foreach (var token in Tokens)
            token.Refresh(now);

        var queue = _genQueue;
        if (queue is null) return;

        // Hand the worker what's missing. Visible codes first so the list fills in, then next-cycle
        // codes so they're cached before the rollover. Each card only claims a counter once (until it's
        // delivered), so re-ticking 10x/second doesn't pile up duplicate work.
        foreach (var token in Tokens)
            if (token.ClaimCurrentWork(now) is long counter)
                queue.Enqueue(new GenRequest(token, counter));
        foreach (var token in Tokens)
            if (token.ClaimPrefetchWork(now) is long counter)
                queue.Enqueue(new GenRequest(token, counter));
    }

    /// <summary>
    /// Bumps a card's not-yet-loaded code to the front of the generation queue — called when the pointer
    /// hovers it, so the code you're looking at appears first even behind a long backlog. No-op once the
    /// card's current code is already shown.
    /// </summary>
    public void PrioritizeItem(AccountItemViewModel item)
    {
        if (item.IsStale)
            _genQueue?.SetUrgent(item);
    }

    /// <summary>Drops the hover priority when the pointer leaves the card.</summary>
    public void ReleasePriority(AccountItemViewModel item) => _genQueue?.ClearUrgent(item);

    /// <summary>Stops the timer and background worker. Call when the window closes.</summary>
    public void Shutdown()
    {
        _timer.Stop();
        StopGenerator();
    }

    // --- Background code generation -------------------------------------------

    private void StartGenerator()
    {
        StopGenerator();
        var cts = new CancellationTokenSource();
        var queue = new GenQueue();
        _genCts = cts;
        _genQueue = queue;
        _ = Task.Run(() => RunGeneratorAsync(queue, cts.Token));
    }

    private void StopGenerator()
    {
        _genCts?.Cancel();
        _genCts = null;
        _genQueue = null;
    }

    /// <summary>
    /// Drains the work queue one code at a time off the UI thread (also serializing the TPM, which
    /// dislikes concurrent access), posting each finished code back to its card. Generation failures
    /// (e.g. a lock landing mid-flight) surface as an empty code rather than crashing the worker.
    /// </summary>
    private async Task RunGeneratorAsync(GenQueue queue, CancellationToken ct)
    {
        try
        {
            while (true)
            {
                GenRequest req = await queue.DequeueAsync(ct).ConfigureAwait(false);
                AccountItemViewModel item = req.Item;
                long counter = req.Counter;
                string raw;
                try
                {
                    raw = Service!.GenerateCode(item.Account, TimeForCounter(counter, item.Period));
                }
                catch
                {
                    raw = "";
                }

                Dispatcher.UIThread.Post(() =>
                {
                    if (!ct.IsCancellationRequested)
                        item.Deliver(counter, raw, DateTime.UtcNow);
                });
            }
        }
        catch (OperationCanceledException)
        {
            // Session ended (lock / reload / shutdown); nothing to clean up.
        }
    }

    /// <summary>
    /// A UTC instant inside the given counter's window. <see cref="VaultService.GenerateCode"/> re-derives
    /// the same counter from it, identically for Simple and Advanced modes.
    /// </summary>
    private static DateTime TimeForCounter(long counter, int period)
        => DateTime.UnixEpoch.AddSeconds((double)counter * period);

    private void SetState(bool ready = false, bool locked = false, bool noTpm = false, bool error = false, bool connecting = false, bool loading = false)
    {
        IsReady = ready;
        IsLocked = locked;
        IsNoTpm = noTpm;
        IsError = error;
        IsConnecting = connecting;
        IsLoading = loading;
        CanLock = ready;
    }

    private void SetError(string message)
    {
        ErrorMessage = message;
        SetState(error: true);
    }
}
