using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using SimpleOtp.App.Services;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core;

namespace SimpleOtp.App.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow() : this(null) { }

    public SettingsWindow(VaultService? service, UpdateService? update = null)
    {
        InitializeComponent();
        DataContext = new SettingsViewModel(service, update);
    }

    private SettingsViewModel? Vm => DataContext as SettingsViewModel;

    /// <summary>True if any setting changed, so the caller can refresh.</summary>
    public bool Changed => Vm?.Changed ?? false;

    private async void OnSwitchToAdvanced(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        bool hasPassword = Vm.MasterPassword.Length > 0;
        string body = hasPassword
            ? "Each secret will be imported into the TPM as a non-exportable key. Codes will be computed inside the chip. " +
              "You'll be able to export only by entering this master password."
            : "Each secret will be imported into the TPM as a non-exportable key.\n\nWith NO master password, exporting these " +
              "secrets will be permanently impossible and you cannot switch back to Simple — keep your original QR codes.";
        if (!await Dialogs.ConfirmAsync(this, "Switch to Advanced Security", body, "Switch"))
            return;
        Vm.TryConvertToAdvanced();
    }

    private async void OnSwitchToSimple(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (!await Dialogs.ConfirmAsync(this, "Switch to Simple Security",
            "Secrets will be recovered with your master password and re-encrypted under a new device key. " +
            "They will then be exportable again.", "Switch"))
            return;
        Vm.TryConvertToSimple();
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close(Changed);

    // Open the GitHub releases page so the user can download an installer manually (the documented path
    // when automatic update checks are turned off).
    private void OnOpenReleases(object? sender, RoutedEventArgs e)
    {
        string url = $"https://github.com/{UpdateService.RepoOwner}/{UpdateService.RepoName}/releases";
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { /* no browser available */ }
    }
}
