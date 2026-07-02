using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SimpleOtp.App.ViewModels;

namespace SimpleOtp.App.Views;

public partial class ExportWindow : Window
{
    private readonly ExportViewModel _vm;

    public ExportWindow() : this([], 0) { }

    public ExportWindow(IReadOnlyList<string> uris, int accountCount,
        string heading = "Export accounts",
        string description = "Scan this with Google Authenticator (Add → Scan a QR code) or another authenticator to transfer your accounts. The migration format always uses a 30-second period and 6/8-digit codes.",
        string saveBaseName = "simpleotp-export")
    {
        InitializeComponent();
        Title = heading;
        _vm = new ExportViewModel(uris, accountCount, heading, description, saveBaseName);
        DataContext = _vm;
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();

    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if (_vm.Count == 0)
            return;

        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Choose a folder to save the QR image(s)",
            AllowMultiple = false,
        });
        if (folders.Count == 0)
            return;

        IStorageFolder folder = folders[0];
        int saved = 0;
        for (int i = 0; i < _vm.PngBytes.Count; i++)
        {
            string name = _vm.PngBytes.Count == 1 ? $"{_vm.SaveBaseName}.png" : $"{_vm.SaveBaseName}-{i + 1}.png";
            IStorageFile? file = await folder.CreateFileAsync(name);
            if (file is null)
                continue;
            await using var stream = await file.OpenWriteAsync();
            await stream.WriteAsync(_vm.PngBytes[i]);
            saved++;
        }

        await Dialogs.AlertAsync(this, "Saved",
            saved == 1 ? "Saved 1 QR image." : $"Saved {saved} QR images.");
    }
}
