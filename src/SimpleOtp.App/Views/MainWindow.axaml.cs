using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
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

    // The account whose ⋯ overflow menu is currently open. Captured from the card's DataContext when the
    // menu opens (reliable there), so the menu-item handlers don't depend on DataContext reaching the
    // flyout popup. Only one card menu can be open at a time.
    private AccountItemViewModel? _menuTarget;

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

    // Opens a card's overflow (⋯) menu. Handled here so the click doesn't fall through to the card's
    // OnCardClick (which would copy the code); the menu items act on the captured account.
    private void OnCardMenuClick(object? sender, RoutedEventArgs e)
    {
        e.Handled = true;
        if (sender is not Control control) return;
        _menuTarget = control.DataContext as AccountItemViewModel; // the button lives in the card's tree

        // Grey out Move up/down at the ends of the current scope. Done on the flyout's items directly so
        // it doesn't depend on DataContext reaching the popup.
        if (_menuTarget is not null && Vm is not null
            && FlyoutBase.GetAttachedFlyout(control) is MenuFlyout menu)
        {
            int index = Vm.Tokens.IndexOf(_menuTarget);
            int count = Vm.Tokens.Count;
            foreach (MenuItem item in menu.Items.OfType<MenuItem>())
            {
                if (item.Tag as string == "up") item.IsEnabled = index > 0;
                else if (item.Tag as string == "down") item.IsEnabled = index >= 0 && index < count - 1;
            }
        }

        FlyoutBase.ShowAttachedFlyout(control);
    }

    private void OnMoveUpClick(object? sender, RoutedEventArgs e)
    {
        if (_menuTarget is { } item) Vm?.MoveItemUp(item);
    }

    private void OnMoveDownClick(object? sender, RoutedEventArgs e)
    {
        if (_menuTarget is { } item) Vm?.MoveItemDown(item);
    }

    private async void OnDeleteClick(object? sender, RoutedEventArgs e)
    {
        if (_menuTarget is not { } item || Vm is null)
            return;
        bool confirmed = await Dialogs.ConfirmAsync(this, "Remove account",
            $"Remove “{item.Title}”?\n\nYou'll need the original QR code or secret to add it again — it cannot be " +
            "recovered from this device.", "Remove");
        if (confirmed)
            Vm.DeleteItem(item);
    }

    // --- Folders --------------------------------------------------------------

    private async void OnAddFolderClick(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        string? name = await Dialogs.PromptAsync(this, "New folder", "Name this folder.", "Create",
            placeholder: "Folder name");
        if (string.IsNullOrWhiteSpace(name)) return; // cancelled or blank
        Vm.AddFolder(name);
        await Vm.ShowToastAsync("Folder created");
    }

    private void OnBackClick(object? sender, RoutedEventArgs e) => Vm?.GoToRoot();

    private void OnFolderClick(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is FolderItemViewModel folder)
            Vm?.OpenFolder(folder.Id);
    }

    private async void OnRenameFolderClick(object? sender, RoutedEventArgs e)
    {
        e.Handled = true; // don't also open the folder
        if ((sender as Control)?.DataContext is not FolderItemViewModel folder || Vm is null)
            return;
        string? name = await Dialogs.PromptAsync(this, "Rename folder", "Choose a new name.", "Rename",
            placeholder: "Folder name", initial: folder.Name);
        if (string.IsNullOrWhiteSpace(name)) return;
        Vm.RenameFolder(folder.Id, name);
    }

    private async void OnDeleteFolderClick(object? sender, RoutedEventArgs e)
    {
        e.Handled = true; // don't also open the folder
        if ((sender as Control)?.DataContext is not FolderItemViewModel folder || Vm is null)
            return;
        bool confirmed = await Dialogs.ConfirmAsync(this, "Delete folder",
            $"Delete the folder “{folder.Name}”?\n\nAccounts inside it move back to the top level — none are removed.",
            "Delete");
        if (confirmed)
            Vm.DeleteFolder(folder.Id);
    }

    private async void OnMoveClick(object? sender, RoutedEventArgs e)
    {
        if (_menuTarget is not { } item || Vm?.Service is null)
            return;

        var folders = Vm.Service.Folders.Select(f => (f.Id, f.Name)).ToList();
        if (folders.Count == 0)
        {
            await Dialogs.AlertAsync(this, "No folders yet",
                "Create a folder first with the 🗂 button in the title bar, then you can move accounts into it.");
            return;
        }

        Dialogs.FolderPick? pick = await Dialogs.ChooseFolderAsync(this, folders, item.Account.FolderId);
        if (pick is null || pick.FolderId == item.Account.FolderId)
            return; // cancelled or no change
        Vm.MoveItemToFolder(item, pick.FolderId);
        await Vm.ShowToastAsync("Moved");
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
            // Adding while a folder is open files the new accounts into it; at the top level they stay
            // uncategorized (CurrentFolderId is null).
            foreach (OtpAuthData data in accounts)
                Vm.Service.AddAccount(data, Vm.CurrentFolderId);
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
