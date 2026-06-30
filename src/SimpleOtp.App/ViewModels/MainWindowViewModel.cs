using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

    /// <summary>Folder cards shown on the top-level list (empty inside a folder / when none exist).</summary>
    public ObservableCollection<FolderItemViewModel> Folders { get; } = [];

    /// <summary>Id of the folder currently open, or null at the top level. Drives which codes generate.</summary>
    public string? CurrentFolderId { get; private set; }

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
    [ObservableProperty] private string _storePath = "";
    [ObservableProperty] private bool _pinSet;

    // --- Folder navigation / list-scope flags ---------------------------------
    // The ready view shows either the top level (folder cards + uncategorized accounts) or one open
    // folder (its accounts). These flags are kept in sync by RefreshScopeFlags() so the XAML can bind
    // simple booleans instead of expressions.

    /// <summary>True while a folder is open (shows the back bar; hides the folder list).</summary>
    [ObservableProperty] private bool _isInFolder;

    /// <summary>Name of the open folder, shown in the back bar.</summary>
    [ObservableProperty] private string _currentFolderName = "";

    /// <summary>Ready AND at the top level — gates the "Add folder" button.</summary>
    [ObservableProperty] private bool _isAtRoot;

    /// <summary>Any folders exist (independent of which scope is open).</summary>
    [ObservableProperty] private bool _hasFolders;

    /// <summary>Folder cards are visible (top level AND at least one folder exists).</summary>
    [ObservableProperty] private bool _showFolders;

    /// <summary>The current scope lists something (folder cards or account cards) — shows the list.</summary>
    [ObservableProperty] private bool _hasContent;

    /// <summary>The vault has at least one account anywhere — gates the Export button.</summary>
    [ObservableProperty] private bool _hasAnyAccounts;

    /// <summary>Whole vault is empty (top level, no folders, no accounts) — shows the first-run placeholder.</summary>
    [ObservableProperty] private bool _isEmptyState;

    /// <summary>An open folder has no accounts — shows the "folder is empty" hint.</summary>
    [ObservableProperty] private bool _isFolderEmpty;

    // Keep the combined "ready and at the top level" flag current as either input changes.
    partial void OnIsReadyChanged(bool value) => IsAtRoot = value && !IsInFolder;
    partial void OnIsInFolderChanged(bool value) => IsAtRoot = IsReady && !value;

    // Unlock view.
    [ObservableProperty] private string _unlockPin = "";
    [ObservableProperty] private string _unlockError = "";

    // TPM dictionary-attack lockout. While locked out the PIN box and Unlock button are disabled and a
    // live countdown is shown; the timer re-enables input once the chip's recovery interval elapses.
    [ObservableProperty] private bool _isLockedOut;
    [ObservableProperty] private string _lockoutMessage = "";
    private readonly DispatcherTimer _lockoutTimer;
    private int _lockoutRemaining;

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
        _lockoutTimer = new DispatcherTimer(DispatcherPriority.Normal) { Interval = TimeSpan.FromSeconds(1) };
        _lockoutTimer.Tick += (_, _) => LockoutTick();
        if (sealer is null)
        {
            IsReady = true;       // design-time
            IsEmptyState = true;  // show the first-run placeholder in the previewer
        }
    }

    /// <summary>Records a found update so the top-bar indicator appears and the popup can be reopened.</summary>
    public void SetUpdateAvailable(UpdateInfo info)
    {
        AvailableUpdate = info;
        UpdateAvailable = true;
    }

    public VaultService? Service { get; internal set; }

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
        if (Service is null || IsLockedOut) return;
        // Starting a fresh attempt clears any leftover lockout text (e.g. the "Lockout cleared…" line a
        // countdown leaves behind, or an unknown-duration lockout notice), so it can't linger beside the
        // next wrong-PIN / error message. The lockout path below re-sets it via BeginLockout.
        LockoutMessage = "";
        try
        {
            Service.Unlock(UnlockPin);
            UnlockPin = "";
            UnlockError = "";
            EnterReady();
        }
        catch (WrongPinException ex)
        {
            UnlockError = FormatWrongPin(ex.RemainingAttempts);
        }
        catch (TpmLockedException ex)
        {
            BeginLockout(ex.RecoverySeconds);
        }
        catch (WrongDeviceException ex)
        {
            SetError(ex.Message); // wrong device is unrecoverable here — show the full error screen
        }
        catch (Exception ex)
        {
            // Anything else (a base SealerException, an I/O error, …) must not crash the app: keep the
            // user on the lock screen with the reason so they can retry, lock, or quit.
            UnlockError = "Couldn't unlock: " + ex.Message;
        }
    }

    /// <summary>Wrong-PIN message, including attempts-left when the TPM reports it.</summary>
    internal static string FormatWrongPin(int? remainingAttempts) =>
        remainingAttempts is int n && n > 0
            ? $"Wrong PIN. {n} {(n == 1 ? "attempt" : "attempts")} left before the TPM locks."
            : "Wrong PIN. Try again.";

    /// <summary>Human-friendly "try again in …" line for the lockout countdown.</summary>
    internal static string FormatLockoutCountdown(int secondsRemaining)
    {
        var ts = TimeSpan.FromSeconds(Math.Max(0, secondsRemaining));
        string time =
            ts.TotalHours >= 1 ? $"{(int)ts.TotalHours}h {ts.Minutes:00}m {ts.Seconds:00}s" :
            ts.TotalMinutes >= 1 ? $"{ts.Minutes}m {ts.Seconds:00}s" :
            $"{ts.Seconds}s";
        return $"Too many wrong PINs — the TPM is locked. Try again in {time}.";
    }

    // Enter the locked-out state. With a known recovery interval, disable input and count it down;
    // otherwise just show the reason and leave input enabled (a still-locked retry re-enters this path).
    private void BeginLockout(int? recoverySeconds)
    {
        UnlockPin = "";
        UnlockError = "";
        if (recoverySeconds is int s && s > 0)
        {
            _lockoutRemaining = s;
            IsLockedOut = true;
            LockoutMessage = FormatLockoutCountdown(_lockoutRemaining);
            _lockoutTimer.Start();
        }
        else
        {
            ResetLockout();
            LockoutMessage =
                "The TPM is locked from too many wrong PINs. Wait for it to recover, or reboot, then try again.";
        }
    }

    private void LockoutTick()
    {
        if (--_lockoutRemaining <= 0)
        {
            _lockoutTimer.Stop();
            IsLockedOut = false;
            LockoutMessage = "Lockout cleared — enter your PIN to try again.";
            return;
        }
        LockoutMessage = FormatLockoutCountdown(_lockoutRemaining);
    }

    private void ResetLockout()
    {
        _lockoutTimer.Stop();
        _lockoutRemaining = 0;
        IsLockedOut = false;
        LockoutMessage = "";
    }

    [RelayCommand]
    private void Lock()
    {
        if (Service is null || !IsReady) return;
        _timer.Stop();
        StopGenerator(); // cancel in-flight generation before the vault key is zeroed
        Tokens.Clear();
        Folders.Clear();
        CurrentFolderId = null; // reopen at the top level after the next unlock
        IsInFolder = false;
        RefreshScopeFlags();
        Service.Lock();
        UnlockPin = "";
        ResetLockout();
        SetState(locked: true);
    }

    /// <summary>
    /// Rebuilds the folder cards and the current scope's account cards from the (unlocked) vault, and
    /// kicks off background generation. Only the open scope's accounts become cards, so codes generate
    /// for them alone — the TPM never has to keep the whole vault refreshed at once. Called on unlock,
    /// on add/move/delete, and whenever the open folder changes.
    /// </summary>
    public void ReloadTokens()
    {
        if (Service is null) return;
        bool wasRunning = _timer.IsEnabled;
        _timer.Stop();
        StartGenerator(); // fresh work queue tied to the rebuilt card set; cancels the old scope's work

        // If the open folder was deleted out from under us, fall back to the top level.
        if (CurrentFolderId is not null && Service.Folders.All(f => f.Id != CurrentFolderId))
            CurrentFolderId = null;

        // Account counts per folder, computed in one pass for the folder cards.
        var counts = new Dictionary<string, int>();
        foreach (Account account in Service.Accounts)
            if (account.FolderId is { } fid)
                counts[fid] = counts.GetValueOrDefault(fid) + 1;

        Folders.Clear();
        foreach (Folder folder in Service.Folders)
            Folders.Add(new FolderItemViewModel(folder.Id, folder.Name, counts.GetValueOrDefault(folder.Id)));
        HasFolders = Folders.Count > 0;

        Tokens.Clear();
        foreach (Account account in Service.AccountsInFolder(CurrentFolderId))
            Tokens.Add(new AccountItemViewModel(account));

        Folder? current = CurrentFolderId is null ? null : Service.Folders.FirstOrDefault(f => f.Id == CurrentFolderId);
        CurrentFolderName = current is null ? ""
            : string.IsNullOrWhiteSpace(current.Name) ? "(unnamed folder)" : current.Name;
        IsInFolder = CurrentFolderId is not null;

        RefreshScopeFlags();
        Tick(); // queues the first round of generation; codes stream in as the worker finishes each
        if (wasRunning || IsReady) _timer.Start();
    }

    /// <summary>Recomputes the list-scope visibility flags from the current collections and open folder.</summary>
    private void RefreshScopeFlags()
    {
        bool hasTokens = Tokens.Count > 0;
        ShowFolders = !IsInFolder && HasFolders;
        HasContent = hasTokens || ShowFolders;
        HasAnyAccounts = (Service?.Accounts.Count ?? 0) > 0;
        IsEmptyState = !IsInFolder && !HasFolders && !hasTokens;
        IsFolderEmpty = IsInFolder && !hasTokens;
    }

    // --- Folder navigation + mutations ----------------------------------------

    /// <summary>Opens a folder: its accounts become the only cards that generate codes.</summary>
    public void OpenFolder(string folderId)
    {
        if (Service is null) return;
        CurrentFolderId = folderId;
        ReloadTokens();
    }

    /// <summary>Returns to the top level (folder cards + uncategorized accounts).</summary>
    public void GoToRoot()
    {
        CurrentFolderId = null;
        ReloadTokens();
    }

    /// <summary>Creates a folder (no-op on a blank name) and rebuilds the list.</summary>
    public void AddFolder(string name)
    {
        if (Service is null || string.IsNullOrWhiteSpace(name)) return;
        Service.AddFolder(name);
        ReloadTokens();
    }

    /// <summary>Renames a folder (no-op on a blank name) and rebuilds the list.</summary>
    public void RenameFolder(string folderId, string name)
    {
        if (Service is null || string.IsNullOrWhiteSpace(name)) return;
        Service.RenameFolder(folderId, name);
        ReloadTokens();
    }

    /// <summary>Deletes a folder; its accounts fall back to the top level (they are not removed).</summary>
    public void DeleteFolder(string folderId)
    {
        if (Service is null) return;
        if (CurrentFolderId == folderId) CurrentFolderId = null; // close it if it was open
        Service.DeleteFolder(folderId);
        ReloadTokens();
    }

    /// <summary>Moves an account into a folder (null = top level) and rebuilds the current scope.</summary>
    public void MoveItemToFolder(AccountItemViewModel item, string? folderId)
    {
        if (Service is null) return;
        Service.MoveAccount(item.Id, folderId);
        ReloadTokens(); // the moved card usually leaves the current scope
    }

    /// <summary>Moves a card one step up within the open scope. Reorders in place so codes aren't regenerated.</summary>
    public void MoveItemUp(AccountItemViewModel item)
    {
        if (Service is null) return;
        int i = Tokens.IndexOf(item);
        if (i > 0 && Service.MoveAccountUp(item.Id))
            Tokens.Move(i, i - 1);
    }

    /// <summary>Moves a card one step down within the open scope. Reorders in place so codes aren't regenerated.</summary>
    public void MoveItemDown(AccountItemViewModel item)
    {
        if (Service is null) return;
        int i = Tokens.IndexOf(item);
        if (i >= 0 && i < Tokens.Count - 1 && Service.MoveAccountDown(item.Id))
            Tokens.Move(i, i + 1);
    }

    public void DeleteItem(AccountItemViewModel item)
    {
        if (Service is null) return;
        Service.RemoveAccount(item.Id);
        Tokens.Remove(item);
        RefreshScopeFlags();
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
        ResetLockout();
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
        _lockoutTimer.Stop();
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
