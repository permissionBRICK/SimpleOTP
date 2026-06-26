using System;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Totp;

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
        _ = Vm?.BootstrapAsync();
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
        OtpAuthData? data = await dialog.ShowDialog<OtpAuthData?>(this);
        if (data is null)
            return;
        try
        {
            Vm.Service.AddAccount(data);
            Vm.ReloadTokens();
            await Vm.ShowToastAsync("Account added");
        }
        catch (Exception ex)
        {
            await Dialogs.AlertAsync(this, "Couldn't add account", ex.Message);
        }
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
        var dialog = new SettingsWindow(Vm.Service);
        await dialog.ShowDialog<bool>(this);
        Vm.NotifySettingsChanged();
    }
}
