using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.Core;
using SimpleOtp.Core.Crypto;

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

    public ObservableCollection<AccountItemViewModel> Tokens { get; } = [];

    // Mutually-exclusive top-level states.
    [ObservableProperty] private bool _isReady;
    [ObservableProperty] private bool _isLocked;
    [ObservableProperty] private bool _isNoTpm;
    [ObservableProperty] private bool _isError;
    [ObservableProperty] private bool _isConnecting;

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

    /// <summary>Design-time constructor (no TPM); shows the empty ready state in the previewer.</summary>
    public MainWindowViewModel() : this(null) { }

    public MainWindowViewModel(ISecretSealer? sealer)
    {
        _sealer = sealer;
        _timer = new DispatcherTimer(DispatcherPriority.Normal) { Interval = TimeSpan.FromMilliseconds(100) };
        _timer.Tick += (_, _) => Tick();
        if (sealer is null)
            IsReady = true; // design-time
    }

    public VaultService? Service { get; private set; }

    /// <summary>Detects the TPM and opens/creates the vault. Call once after the window is shown.</summary>
    public async Task BootstrapAsync()
    {
        if (_sealer is null) return;
        try
        {
            if (!_sealer.IsAvailable)
            {
                SetState(noTpm: true);
                return;
            }

            Service = new VaultService(_sealer);
            StorePath = Service.StorePath;
            AutoUnlockAvailable = Service.AutoUnlockEnabled;

            if (!Service.IsInitialized)
            {
                Service.CreateNew(ReadOnlySpan<byte>.Empty); // first run: no PIN by default
                EnterReady();
            }
            else if (!Service.PinProtected)
            {
                Service.Unlock(ReadOnlySpan<byte>.Empty);
                EnterReady();
            }
            else if (Service.AutoUnlockEnabled && await TryAutoUnlockAsync())
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
        Tokens.Clear();
        HasAccounts = false;
        Service.Lock();
        UnlockPin = "";
        SetState(locked: true);
    }

    /// <summary>Rebuilds the token list from the (unlocked) vault and refreshes immediately.</summary>
    public void ReloadTokens()
    {
        if (Service is null) return;
        bool wasRunning = _timer.IsEnabled;
        _timer.Stop();
        Tokens.Clear();
        foreach (var account in Service.Accounts)
            Tokens.Add(new AccountItemViewModel(account, Service));
        HasAccounts = Tokens.Count > 0;
        Tick();
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
        PinSet = Service?.PinProtected ?? false;
        AutoUnlockAvailable = Service?.AutoUnlockEnabled ?? false;
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
        foreach (var token in Tokens)
            token.Refresh(now);
    }

    private void SetState(bool ready = false, bool locked = false, bool noTpm = false, bool error = false, bool connecting = false)
    {
        IsReady = ready;
        IsLocked = locked;
        IsNoTpm = noTpm;
        IsError = error;
        IsConnecting = connecting;
    }

    private void SetError(string message)
    {
        ErrorMessage = message;
        SetState(error: true);
    }
}
