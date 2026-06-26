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

    public ExportWindow(IReadOnlyList<string> migrationUris, int accountCount)
    {
        InitializeComponent();
        _vm = new ExportViewModel(migrationUris, accountCount);
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
            string name = _vm.PngBytes.Count == 1 ? "simpleotp-export.png" : $"simpleotp-export-{i + 1}.png";
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
