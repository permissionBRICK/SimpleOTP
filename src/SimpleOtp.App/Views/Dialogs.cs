using System.Collections.Generic;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace SimpleOtp.App.Views;

/// <summary>Tiny code-built modal dialogs (confirm / alert) to avoid extra XAML for simple prompts.</summary>
public static class Dialogs
{
    public static Task<bool> ConfirmAsync(Window owner, string title, string message, string okText)
    {
        var tcs = new TaskCompletionSource<bool>();

        var cancel = new Button { Content = "Cancel", MinWidth = 88, HorizontalContentAlignment = HorizontalAlignment.Center };
        var ok = new Button
        {
            Content = okText,
            MinWidth = 88,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Background = new SolidColorBrush(Color.Parse("#D24B43")),
            Foreground = Brushes.White,
        };

        var window = BuildWindow(title, message, [cancel, ok]);
        cancel.Click += (_, _) => { tcs.TrySetResult(false); window.Close(); };
        ok.Click += (_, _) => { tcs.TrySetResult(true); window.Close(); };
        window.Closed += (_, _) => tcs.TrySetResult(false);

        window.ShowDialog(owner);
        return tcs.Task;
    }

    /// <summary>Prompts for a single line of (optionally masked) text. Returns null if cancelled.</summary>
    public static Task<string?> PromptAsync(Window owner, string title, string message, string okText,
        string placeholder = "", bool isPassword = false, string initial = "")
    {
        var tcs = new TaskCompletionSource<string?>();

        var input = new TextBox { PlaceholderText = placeholder, Text = initial, Margin = new Thickness(0, 4, 0, 0) };
        if (isPassword) input.PasswordChar = '•';

        var cancel = new Button { Content = "Cancel", MinWidth = 88, HorizontalContentAlignment = HorizontalAlignment.Center };
        var ok = new Button
        {
            Content = okText,
            MinWidth = 88,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            Background = new SolidColorBrush(Color.Parse("#3D7DEB")),
            Foreground = Brushes.White,
        };

        var window = BuildWindow(title, message, [cancel, ok], input);
        void Submit() { tcs.TrySetResult(input.Text ?? ""); window.Close(); }
        cancel.Click += (_, _) => { tcs.TrySetResult(null); window.Close(); };
        ok.Click += (_, _) => Submit();
        input.KeyDown += (_, e) => { if (e.Key == Avalonia.Input.Key.Enter) Submit(); };
        window.Closed += (_, _) => tcs.TrySetResult(null);
        window.Opened += (_, _) => { input.Focus(); input.SelectAll(); };

        window.ShowDialog(owner);
        return tcs.Task;
    }

    /// <summary>Result of <see cref="ChooseFolderAsync"/>: the chosen folder id (null = top level).</summary>
    public sealed record FolderPick(string? FolderId);

    /// <summary>
    /// Shows a vertical list of folders (plus a "Top level" option) and returns the picked one, or null
    /// if cancelled. The account's current folder is marked with a check so a no-op move is obvious.
    /// </summary>
    public static Task<FolderPick?> ChooseFolderAsync(Window owner,
        IReadOnlyList<(string Id, string Name)> folders, string? currentFolderId)
    {
        var tcs = new TaskCompletionSource<FolderPick?>();
        Window? window = null;

        var options = new StackPanel { Spacing = 8 };
        Button Choice(string label, string? id)
        {
            var b = new Button
            {
                Content = label + (id == currentFolderId ? "   ✓" : ""),
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Left,
                Padding = new Thickness(12, 9),
            };
            b.Click += (_, _) => { tcs.TrySetResult(new FolderPick(id)); window?.Close(); };
            return b;
        }

        options.Children.Add(Choice("Top level (no folder)", null));
        foreach ((string id, string name) in folders)
            options.Children.Add(Choice(string.IsNullOrWhiteSpace(name) ? "(unnamed folder)" : name, id));

        var cancel = new Button
        {
            Content = "Cancel",
            MinWidth = 88,
            HorizontalAlignment = HorizontalAlignment.Right,
            HorizontalContentAlignment = HorizontalAlignment.Center,
        };
        cancel.Click += (_, _) => { tcs.TrySetResult(null); window?.Close(); };

        var content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 16,
            Children =
            {
                new TextBlock { Text = "Move to folder", FontSize = 16, FontWeight = FontWeight.SemiBold, Foreground = Brushes.White },
                new ScrollViewer { Content = options, MaxHeight = 320 },
                cancel,
            },
        };

        window = new Window
        {
            Title = "Move to folder",
            Width = 360,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            RequestedThemeVariant = Avalonia.Styling.ThemeVariant.Dark,
            Background = new SolidColorBrush(Color.Parse("#1E2024")),
            Content = content,
        };
        window.Closed += (_, _) => tcs.TrySetResult(null);
        window.ShowDialog(owner);
        return tcs.Task;
    }

    public static Task AlertAsync(Window owner, string title, string message)
    {
        var tcs = new TaskCompletionSource();
        var ok = new Button { Content = "OK", MinWidth = 88, HorizontalContentAlignment = HorizontalAlignment.Center };
        var window = BuildWindow(title, message, [ok]);
        ok.Click += (_, _) => window.Close();
        window.Closed += (_, _) => tcs.TrySetResult();
        window.ShowDialog(owner);
        return tcs.Task;
    }

    private static Window BuildWindow(string title, string message, Button[] buttons, Control? extra = null)
    {
        var buttonRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 10,
        };
        foreach (var b in buttons)
            buttonRow.Children.Add(b);

        var content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 16,
            Children =
            {
                new TextBlock { Text = title, FontSize = 16, FontWeight = FontWeight.SemiBold, Foreground = Brushes.White },
                new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.Parse("#C9CDD4")) },
            },
        };
        if (extra is not null) content.Children.Add(extra);
        content.Children.Add(buttonRow);

        return new Window
        {
            Title = title,
            Width = 360,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            RequestedThemeVariant = Avalonia.Styling.ThemeVariant.Dark,
            Background = new SolidColorBrush(Color.Parse("#1E2024")),
            Content = content,
        };
    }
}
