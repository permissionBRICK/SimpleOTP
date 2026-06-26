using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SimpleOtp.App.ViewModels;
using SimpleOtp.Core.Totp;
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

    // Returns the accounts to add: one in single mode, the ticked subset in bulk mode (null = cancel).
    private void OnAdd(object? sender, RoutedEventArgs e)
    {
        if (_vm.IsBulk)
        {
            IReadOnlyList<OtpAuthData> selected = _vm.SelectedAccounts();
            if (selected.Count == 0)
            {
                _vm.SetStatus("Select at least one account to import.", error: true);
                return;
            }
            Close(selected);
            return;
        }

        OtpAuthData? data = _vm.Build();
        if (data is not null)
            Close(new List<OtpAuthData> { data });
    }

    private async void OnOpenImage(object? sender, RoutedEventArgs e)
    {
        // Allow multiple images so a split (multi-QR) export can be imported in one go.
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Choose QR code image(s)",
            AllowMultiple = true,
            FileTypeFilter = [FilePickerFileTypes.ImageAll],
        });
        foreach (IStorageFile file in files)
        {
            await using var stream = await file.OpenReadAsync();
            await DecodeAndApplyAsync(stream);
        }
    }

    private async void OnPasteImage(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (!await TryImportClipboardImageAsync())
                _vm.SetStatus("The clipboard doesn't contain an image. Copy a QR screenshot first.", error: true);
        }
        catch (Exception ex)
        {
            _vm.SetStatus("Couldn't read the clipboard image: " + ex.Message, error: true);
        }
    }

    // Launches the Windows screen-clip overlay (the Win+Shift+S tool). The capture runs out-of-process
    // and lands on the clipboard, so we clear the clipboard first and then poll it for the new image and
    // import it automatically — no extra paste step.
    private async void OnSnip(object? sender, RoutedEventArgs e)
    {
        if (!OperatingSystem.IsWindows())
        {
            _vm.SetStatus("Screen snipping uses the Windows Snipping Tool. On this OS, use Open image or Paste image.", error: true);
            return;
        }
        if (Clipboard is null)
            return;

        try { await Clipboard.ClearAsync(); } catch { /* best effort */ }

        try
        {
            // ms-screenclip: is the protocol that opens the Snip & Sketch capture overlay.
            Process.Start(new ProcessStartInfo("ms-screenclip:") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _vm.SetStatus("Couldn't launch the Snipping Tool: " + ex.Message, error: true);
            return;
        }

        _vm.SetStatus("Drag to capture the QR code — it will import automatically.");
        for (int i = 0; i < 120; i++) // poll ~60s for the captured image
        {
            await Task.Delay(500);
            try
            {
                if (await TryImportClipboardImageAsync())
                    return; // got the snip (decode result, success or "no QR", is shown by ApplyDecoded)
            }
            catch { /* keep polling */ }
        }
        _vm.SetStatus("No capture detected. Snip again, or use Paste image.", error: true);
    }

    private async Task<bool> TryImportClipboardImageAsync()
    {
        if (Clipboard is null)
            return false;
        var bitmap = await Clipboard.TryGetBitmapAsync();
        if (bitmap is null)
            return false;
        using (bitmap)
        {
            using var ms = new MemoryStream();
            bitmap.Save(ms);
            ApplyDecoded(QrDecoder.DecodeFromBytes(ms.ToArray()));
        }
        return true;
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
        foreach (IStorageItem item in files)
        {
            if (item is IStorageFile file)
            {
                await using var stream = await file.OpenReadAsync();
                await DecodeAndApplyAsync(stream);
            }
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
