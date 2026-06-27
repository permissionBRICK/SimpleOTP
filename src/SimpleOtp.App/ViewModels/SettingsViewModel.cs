using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleOtp.App.Services;
using SimpleOtp.Core;
using SimpleOtp.Core.AutoUnlock;
using SimpleOtp.Core.Crypto;
using SimpleOtp.Core.Model;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.ViewModels;

/// <summary>Backs the Settings window: PIN management, network auto-unlock, and software updates.</summary>
public partial class SettingsViewModel : ViewModelBase
{
    private readonly VaultService? _service;
    private readonly UpdateService? _updateService;
    private readonly bool _updatesLoaded;

    // Security mode
    [ObservableProperty] private bool _isAdvanced;
    [ObservableProperty] private bool _exportProtected;
    [ObservableProperty] private string _masterPassword = "";
    [ObservableProperty] private string _confirmMasterPassword = "";
    [ObservableProperty] private string _modeStatus = "";
    [ObservableProperty] private bool _modeError;

    // PIN
    [ObservableProperty] private bool _hasPin;
    [ObservableProperty] private string _newPin = "";
    [ObservableProperty] private string _confirmPin = "";
    [ObservableProperty] private string _pinStatus = "";
    [ObservableProperty] private bool _pinError;

    // Auto-unlock
    [ObservableProperty] private bool _autoUnlockOn;
    [ObservableProperty] private string _url = "";
    [ObservableProperty] private string _appKey = "";
    [ObservableProperty] private string _appKeyHeader = "X-App-Key";
    [ObservableProperty] private int _methodIndex; // 0=POST, 1=GET
    [ObservableProperty] private string _pinnedCert = "";
    [ObservableProperty] private bool _allowUntrusted;
    [ObservableProperty] private string _autoUnlockKey = "";
    [ObservableProperty] private string _autoStatus = "";
    [ObservableProperty] private bool _autoError;
    [ObservableProperty] private string _contract = "";
    [ObservableProperty] private bool _showContract;

    // Software updates
    [ObservableProperty] private bool _autoUpdateEnabled = true;
    [ObservableProperty] private string _currentVersionText = "";

    /// <summary>Short badge for the current mode.</summary>
    public string ModeBadge => IsAdvanced ? "ADVANCED" : "SIMPLE";
    partial void OnIsAdvancedChanged(bool value) => OnPropertyChanged(nameof(ModeBadge));

    // Persist the auto-update choice immediately when toggled (but not during construction).
    partial void OnAutoUpdateEnabledChanged(bool value)
    {
        if (!_updatesLoaded || _updateService is null) return;
        _updateService.SetAutoUpdate(value);
        Changed = true;
    }

    public string[] Methods { get; } = ["POST", "GET"];

    /// <summary>True if anything was changed (so the caller can refresh the main view).</summary>
    public bool Changed { get; private set; }

    public SettingsViewModel() : this(null) { }

    public SettingsViewModel(VaultService? service, UpdateService? updateService = null)
    {
        _service = service;
        _updateService = updateService;
        if (updateService is not null)
        {
            AutoUpdateEnabled = updateService.AutoUpdateEnabled;
            ReleaseVersion v = updateService.CurrentAppVersion;
            CurrentVersionText = v.IsZero ? "Development build" : $"Version {v}";
        }
        _updatesLoaded = true; // guard so the initial assignment above doesn't persist a no-op change

        if (service is not null)
        {
            IsAdvanced = service.Mode == SecurityMode.Advanced;
            ExportProtected = service.ExportProtected;
            HasPin = service.PinProtected;
            AutoUnlockOn = service.AutoUnlockEnabled;
            AutoUnlockConfig? cfg = service.AutoUnlock;
            if (cfg is not null)
            {
                Url = cfg.Url;
                AppKey = cfg.AppKey;
                AppKeyHeader = cfg.AppKeyHeader;
                MethodIndex = cfg.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
                PinnedCert = cfg.PinnedServerCertSha256 ?? "";
                AllowUntrusted = cfg.AllowUntrustedServerCert;
            }
        }
        if (string.IsNullOrEmpty(AppKey)) AppKey = NewToken();
        if (string.IsNullOrEmpty(AutoUnlockKey)) AutoUnlockKey = NewToken();
    }

    [RelayCommand] private void GenerateAppKey() => AppKey = NewToken();
    [RelayCommand] private void GenerateAutoKey() => AutoUnlockKey = NewToken();

    /// <summary>
    /// Converts the vault to Advanced Security. The master password is optional; with none, exporting
    /// becomes permanently impossible (the caller is expected to have confirmed this). Returns true on
    /// success. Validation/TPM errors are surfaced via <see cref="ModeStatus"/>.
    /// </summary>
    public bool TryConvertToAdvanced()
    {
        if (_service is null) return false;
        string pw = MasterPassword;
        if (pw.Length > 0 && pw != ConfirmMasterPassword) { SetMode("The master passwords don't match.", true); return false; }
        try
        {
            _service.ConvertToAdvanced(pw.Length == 0 ? null : pw);
            IsAdvanced = true;
            ExportProtected = _service.ExportProtected;
            // The PIN and network auto-unlock are preserved across conversion — they now gate the TPM
            // HMAC keys — so reflect their real state rather than assuming they were cleared.
            HasPin = _service.PinProtected;
            AutoUnlockOn = _service.AutoUnlockEnabled;
            MasterPassword = ConfirmMasterPassword = "";
            Changed = true;
            SetMode(ExportProtected
                ? "Advanced Security is on. Codes are now computed inside the TPM. Keep your master password safe — it is the only way to export."
                : "Advanced Security is on (no master password). Codes work, but these secrets can never be exported from this device.", false);
            return true;
        }
        catch (Exception ex) { SetMode(ex.Message, true); return false; }
    }

    /// <summary>
    /// Converts the vault back to Simple Security using the master password. Returns true on success;
    /// a wrong/absent password is surfaced via <see cref="ModeStatus"/>.
    /// </summary>
    public bool TryConvertToSimple()
    {
        if (_service is null) return false;
        try
        {
            _service.ConvertToSimple(MasterPassword);
            IsAdvanced = false;
            ExportProtected = false;
            // PIN / auto-unlock are preserved across conversion; show their real state.
            HasPin = _service.PinProtected;
            AutoUnlockOn = _service.AutoUnlockEnabled;
            MasterPassword = ConfirmMasterPassword = "";
            Changed = true;
            SetMode("Switched back to Simple Security.", false);
            return true;
        }
        catch (WrongPinException) { SetMode("Wrong master password.", true); return false; }
        catch (Exception ex) { SetMode(ex.Message, true); return false; }
    }

    private void SetMode(string message, bool error) { ModeStatus = message; ModeError = error; }

    [RelayCommand]
    private void SavePin()
    {
        if (_service is null) return;
        if (NewPin.Length == 0) { SetPin("Enter a PIN (or use Remove PIN).", true); return; }
        if (NewPin != ConfirmPin) { SetPin("The PINs don't match.", true); return; }
        try
        {
            _service.ChangePin(NewPin);
            HasPin = true;
            NewPin = ConfirmPin = "";
            Changed = true;
            SetPin("PIN saved.", false);
        }
        catch (Exception ex) { SetPin(ex.Message, true); }
    }

    [RelayCommand]
    private void RemovePin()
    {
        if (_service is null) return;
        try
        {
            _service.ChangePin(null);
            HasPin = false;
            NewPin = ConfirmPin = "";
            Changed = true;
            SetPin("PIN removed.", false);
        }
        catch (Exception ex) { SetPin(ex.Message, true); }
    }

    [RelayCommand]
    private void EnableAutoUnlock()
    {
        if (_service is null) return;
        if (string.IsNullOrWhiteSpace(Url)) { SetAuto("Enter the webservice URL.", true); return; }
        if (string.IsNullOrWhiteSpace(AutoUnlockKey)) { SetAuto("Enter or generate an auto-unlock key.", true); return; }
        try
        {
            AutoUnlockConfig cfg = BuildConfig();
            string key = _service.EnableAutoUnlock(cfg, AutoUnlockKey.Trim());
            AutoUnlockOn = true;
            Changed = true;
            Contract = BuildContract(cfg, key);
            ShowContract = true;
            SetAuto("Auto-unlock enabled. Configure your webservice exactly as shown below.", false);
        }
        catch (Exception ex) { SetAuto(ex.Message, true); }
    }

    [RelayCommand]
    private void DisableAutoUnlock()
    {
        if (_service is null) return;
        _service.DisableAutoUnlock();
        AutoUnlockOn = false;
        ShowContract = false;
        Changed = true;
        SetAuto("Auto-unlock disabled.", false);
    }

    [RelayCommand]
    private async Task TestConnection()
    {
        if (string.IsNullOrWhiteSpace(Url)) { SetAuto("Enter the URL first.", true); return; }
        try
        {
            byte[] key = await AutoUnlockClient.FetchKeyAsync(BuildConfig());
            string returned = Encoding.UTF8.GetString(key);
            CryptographicOperations.ZeroMemory(key);
            bool matches = AutoUnlockKey.Trim().Length > 0 && returned == AutoUnlockKey.Trim();
            SetAuto(matches
                ? "Success: the service returned the expected auto-unlock key."
                : "The service responded, but its body does not match the auto-unlock key set here.", !matches);
        }
        catch (Exception ex) { SetAuto("Test failed: " + ex.Message, true); }
    }

    private AutoUnlockConfig BuildConfig() => new()
    {
        Url = Url.Trim(),
        AppKey = AppKey.Trim(),
        AppKeyHeader = string.IsNullOrWhiteSpace(AppKeyHeader) ? "X-App-Key" : AppKeyHeader.Trim(),
        Method = Methods[Math.Clamp(MethodIndex, 0, Methods.Length - 1)],
        PinnedServerCertSha256 = string.IsNullOrWhiteSpace(PinnedCert) ? null : PinnedCert.Trim(),
        AllowUntrustedServerCert = AllowUntrusted,
    };

    private static string BuildContract(AutoUnlockConfig c, string key) =>
        $"Configure your webservice so that it:\n" +
        $"  • accepts  {c.Method} {c.Url}\n" +
        $"  • requires header  {c.AppKeyHeader}: {c.AppKey}\n" +
        $"  • responds 200 with this exact body:\n\n{key}\n\n" +
        "Keep this body only in the service's memory. It is NOT stored by this app.";

    private static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
    private void SetPin(string message, bool error) { PinStatus = message; PinError = error; }
    private void SetAuto(string message, bool error) { AutoStatus = message; AutoError = error; }
}
