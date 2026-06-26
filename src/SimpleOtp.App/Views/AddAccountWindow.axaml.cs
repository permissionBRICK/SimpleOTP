using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Import;

namespace SimpleOtp.App.Views;

public partial class AddAccountWindow : Window
{
    private readonly AddAccountViewModel _vm = new();

    public AddAccountWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        AddHandler(DragDrop.DropEvent, OnDrop);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(null);

    private void OnAdd(object? sender, RoutedEventArgs e)
    {
        var data = _vm.Build();
        if (data is not null)
            Close(data);
    }

    private async void OnOpenImage(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Choose a QR code image",
            AllowMultiple = false,
            FileTypeFilter = [FilePickerFileTypes.ImageAll],
        });
        if (files.Count == 0)
            return;
        await using var stream = await files[0].OpenReadAsync();
        await DecodeAndApplyAsync(stream);
    }

    private async void OnPasteImage(object? sender, RoutedEventArgs e)
    {
        if (Clipboard is null)
            return;
        try
        {
            var bitmap = await Clipboard.TryGetBitmapAsync();
            if (bitmap is null)
            {
                _vm.SetStatus("The clipboard doesn't contain an image. Copy a QR screenshot first.", error: true);
                return;
            }
            using var ms = new MemoryStream();
            bitmap.Save(ms);
            ApplyDecoded(QrDecoder.DecodeFromBytes(ms.ToArray()));
        }
        catch (System.Exception ex)
        {
            _vm.SetStatus("Couldn't read the clipboard image: " + ex.Message, error: true);
        }
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer?.TryGetFiles();
        e.DragEffects = files is { Length: > 0 } ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private async void OnDrop(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer?.TryGetFiles();
        if (files is not { Length: > 0 })
            return;
        if (files[0] is IStorageFile file)
        {
            await using var stream = await file.OpenReadAsync();
            await DecodeAndApplyAsync(stream);
        }
    }

    private async Task DecodeAndApplyAsync(Stream stream)
    {
        try
        {
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms);
            ApplyDecoded(QrDecoder.DecodeFromBytes(ms.ToArray()));
        }
        catch (System.Exception ex)
        {
            _vm.SetStatus("Couldn't read that image: " + ex.Message, error: true);
        }
    }

    private void ApplyDecoded(string? decodedText)
    {
        if (string.IsNullOrEmpty(decodedText))
            _vm.SetStatus("No QR code was found in that image.", error: true);
        else
            _vm.ApplyDecoded(decodedText);
    }
}
