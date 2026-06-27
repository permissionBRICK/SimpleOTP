using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Threading;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Totp;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainWindowViewModel? Vm => DataContext as MainWindowViewModel;

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        if (Vm is not null)
            Vm.PropertyChanged += OnVmPropertyChanged;
        _ = StartupAsync();
    }

    // Open the vault, then (once the window is up) check GitHub for a newer release. The update check
    // runs regardless of vault state — even the no-TPM / locked screens should be able to offer it.
    private async Task StartupAsync()
    {
        if (Vm is null) return;
        await Vm.BootstrapAsync();
        await CheckForUpdatesAsync();
    }

    private async Task CheckForUpdatesAsync()
    {
        if (Vm?.Update is null) return;
        UpdateInfo? info = await Vm.Update.CheckAsync();
        if (info is null) return;        // up to date, dev build, disabled, or a check failure
        Vm.SetUpdateAvailable(info);     // show the top-bar indicator
        if (Vm.Update.ShouldPrompt(info.LatestVersion))
            await ShowUpdateDialogAsync(info);
    }

    // The top-bar indicator: reopen the update popup for the already-found update.
    private async void OnUpdateClick(object? sender, RoutedEventArgs e)
    {
        if (Vm?.AvailableUpdate is { } info)
            await ShowUpdateDialogAsync(info);
    }

    private async Task ShowUpdateDialogAsync(UpdateInfo info)
    {
        if (Vm?.Update is null) return;
        // Guard the whole dialog flow: this runs from the startup task and from an async-void click
        // handler, so an unhandled error here would silently break the popup or crash the app.
        try
        {
            var dialog = new UpdateWindow(info, Vm.Update);
            await dialog.ShowDialog(this);
            // On "Ignore" the indicator stays (UpdateAvailable is already set); on "Update" the app is
            // shutting down so the installer can swap files and relaunch — nothing more to do here.
        }
        catch (Exception ex)
        {
            await Dialogs.AlertAsync(this, "Update",
                "Couldn't open the update window. You can download the latest version from the releases page.\n\n" + ex.Message);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        if (Vm is not null)
            Vm.PropertyChanged -= OnVmPropertyChanged;
        Vm?.Shutdown(); // stop the timer + background generation worker
        base.OnClosed(e);
    }

    // When the vault opens straight into the locked state (PIN enabled, no auto-unlock), or whenever it
    // relocks, put the cursor in the PIN box so the user can just start typing. Deferred to the dispatcher
    // so the locked view's visibility binding has settled before we focus.
    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainWindowViewModel.IsLocked) && Vm?.IsLocked == true)
            Dispatcher.UIThread.Post(() => PinBox.Focus());
    }

    // Hovering a card bumps its code to the front of the background generation queue, so a code you're
    // looking at appears first even when many accounts are still loading. Released when the pointer leaves.
    private void OnCardPointerEntered(object? sender, PointerEventArgs e)
    {
        if ((sender as Control)?.DataContext is AccountItemViewModel item)
            Vm?.PrioritizeItem(item);
    }

    private void OnCardPointerExited(object? sender, PointerEventArgs e)
    {
        if ((sender as Control)?.DataContext is AccountItemViewModel item)
            Vm?.ReleasePriority(item);
    }

    private async void OnCardClick(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is not AccountItemViewModel item || Vm is null)
            return;
        if (string.IsNullOrEmpty(item.RawCode))
            return;
        if (Clipboard is { } clipboard)
        {
            await clipboard.SetTextAsync(item.RawCode);
            await Vm.ShowToastAsync($"Copied {item.Title} code");
        }
    }

    private async void OnDeleteClick(object? sender, RoutedEventArgs e)
    {
        // Click is a bubbling routed event; mark it handled so it doesn't also trigger the card's
        // OnCardClick (which would copy the code). Set synchronously, before any await.
        e.Handled = true;
        if ((sender as Control)?.DataContext is not AccountItemViewModel item || Vm is null)
            return;
        bool confirmed = await Dialogs.ConfirmAsync(this, "Remove account",
            $"Remove “{item.Title}”?\n\nYou'll need the original QR code or secret to add it again — it cannot be " +
            "recovered from this device.", "Remove");
        if (confirmed)
            Vm.DeleteItem(item);
    }

    private async void OnAddClick(object? sender, RoutedEventArgs e)
    {
        if (Vm?.Service is null)
            return;
        var dialog = new AddAccountWindow();
        var accounts = await dialog.ShowDialog<IReadOnlyList<OtpAuthData>?>(this);
        if (accounts is null || accounts.Count == 0)
            return;
        try
        {
            foreach (OtpAuthData data in accounts)
                Vm.Service.AddAccount(data);
            Vm.ReloadTokens();
            await Vm.ShowToastAsync(accounts.Count == 1 ? "Account added" : $"{accounts.Count} accounts added");
        }
        catch (Exception ex)
        {
            await Dialogs.AlertAsync(this, "Couldn't add account", ex.Message);
        }
    }

    private async void OnExportClick(object? sender, RoutedEventArgs e)
    {
        if (Vm?.Service is null)
            return;

        // Advanced mode: secrets live non-exportably in the TPM. Exporting needs the master password
        // (and is impossible at all if none was set).
        string? masterPassword = null;
        if (Vm.Service.Mode == SimpleOtp.Core.Model.SecurityMode.Advanced)
        {
            if (!Vm.Service.ExportProtected)
            {
                await Dialogs.AlertAsync(this, "Export disabled",
                    "This vault uses Advanced Security without a master password, so the secrets cannot be " +
                    "read off this device. Use your original QR codes to set up another device.");
                return;
            }
            masterPassword = await Dialogs.PromptAsync(this, "Export accounts",
                "Enter your master password to recover the secrets for export.", "Export",
                placeholder: "Master password", isPassword: true);
            if (masterPassword is null) return; // cancelled
        }

        IReadOnlyList<string> uris;
        try
        {
            uris = Vm.Service.ExportToMigrationUris(masterPassword);
        }
        catch (SimpleOtp.Core.Crypto.WrongPinException)
        {
            await Dialogs.AlertAsync(this, "Couldn't export", "Wrong master password.");
            return;
        }
        catch (Exception ex)
        {
            await Dialogs.AlertAsync(this, "Couldn't export", ex.Message);
            return;
        }
        if (uris.Count == 0)
        {
            await Dialogs.AlertAsync(this, "Nothing to export", "Add some accounts first.");
            return;
        }
        var dialog = new ExportWindow(uris, Vm.Tokens.Count);
        await dialog.ShowDialog(this);
    }

    private void OnLockClick(object? sender, RoutedEventArgs e) => Vm?.LockCommand.Execute(null);

    private void OnPinKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            Vm?.UnlockCommand.Execute(null);
    }

    private async void OnSettingsClick(object? sender, RoutedEventArgs e)
    {
        if (Vm?.Service is null)
            return;
        var dialog = new SettingsWindow(Vm.Service, Vm.Update);
        await dialog.ShowDialog<bool>(this);
        Vm.NotifySettingsChanged();
    }
}
