using Avalonia.Controls;
using Avalonia.Interactivity;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core;

namespace SimpleOtp.App.Views;

public partial class SettingsWindow : Window
{
    public SettingsWindow() : this(null) { }

    public SettingsWindow(VaultService? service)
    {
        InitializeComponent();
        DataContext = new SettingsViewModel(service);
    }

    /// <summary>True if any setting changed, so the caller can refresh.</summary>
    public bool Changed => (DataContext as SettingsViewModel)?.Changed ?? false;

    private void OnClose(object? sender, RoutedEventArgs e) => Close(Changed);
}
