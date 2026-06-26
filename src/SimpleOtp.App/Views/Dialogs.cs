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

    private static Window BuildWindow(string title, string message, Button[] buttons)
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
                buttonRow,
            },
        };

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
