using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using SimpleOtp.App.Markdown;
using SimpleOtp.App.Services;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.Views;

/// <summary>
/// The "new version available" popup. Offers a one-click in-app update (download → silent install →
/// relaunch) when an installable asset exists for this platform, or a link to the GitHub releases page
/// otherwise / on failure. "Ignore" records the version so it won't prompt again (the top-bar indicator
/// stays until the user updates).
/// </summary>
public partial class UpdateWindow : Window
{
    private readonly UpdateInfo _info;
    private readonly UpdateService _update;
    private bool _pageOnly; // true once we can only offer the manual download page (no asset / after failure)
    private bool _busy;     // a download/apply is in progress — ignore repeat clicks

    // Design-time constructor.
    public UpdateWindow() : this(DesignInfo(), new UpdateService(current: new ReleaseVersion(1, 0, 0))) { }

    public UpdateWindow(UpdateInfo info, UpdateService update)
    {
        InitializeComponent();
        _info = info;
        _update = update;

        HeadingText.Text = $"SimpleOTP {info.LatestVersion} is available";
        SubText.Text = $"You're on {info.CurrentVersion}.";

        string notes = (info.ReleaseNotes ?? "").Trim();
        if (notes.Length > 0)
        {
            // GitHub release bodies are markdown; render them formatted rather than as raw text.
            NotesContent.Content = MarkdownRenderer.Build(notes);
            NotesBox.IsVisible = true;
        }

        _pageOnly = !UpdateService.CanSelfUpdate(info);
        if (_pageOnly)
            UpdateButton.Content = "Open download page";
    }

    private void OnIgnore(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        _update.Ignore(_info.LatestVersion);
        Close();
    }

    private async void OnUpdate(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;

        if (_pageOnly)
        {
            OpenReleasePage();
            Close();
            return;
        }

        _busy = true;
        IgnoreButton.IsEnabled = false;
        UpdateButton.IsEnabled = false;
        ErrorText.IsVisible = false;
        ProgressPanel.IsVisible = true;
        StatusText.Text = "Downloading update…";

        var progress = new Progress<double>(p =>
        {
            ProgressBarCtl.IsIndeterminate = false;
            ProgressBarCtl.Value = Math.Clamp(p * 100, 0, 100);
        });

        try
        {
            await _update.DownloadAndApplyAsync(_info, progress);
            StatusText.Text = "Installing and restarting…";
            await Task.Delay(800); // let the user read it; the external updater is waiting on our exit
            ShutdownApp();         // releases the AppMutex so the installer can replace files and relaunch
        }
        catch (Exception ex)
        {
            // Fall back to a manual download from the releases page.
            ProgressPanel.IsVisible = false;
            ErrorText.Text = $"The update couldn't be installed automatically ({ex.Message}). " +
                             "You can download it from the releases page instead.";
            ErrorText.IsVisible = true;
            _pageOnly = true;
            _busy = false;
            UpdateButton.Content = "Open download page";
            IgnoreButton.IsEnabled = true;
            UpdateButton.IsEnabled = true;
        }
    }

    private void OpenReleasePage()
    {
        string url = string.IsNullOrEmpty(_info.ReleaseUrl)
            ? $"https://github.com/{UpdateService.RepoOwner}/{UpdateService.RepoName}/releases"
            : _info.ReleaseUrl;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { /* nothing else we can do if no browser is available */ }
    }

    private static void ShutdownApp()
    {
        if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.Shutdown();
        else
            Environment.Exit(0);
    }

    private static UpdateInfo DesignInfo() => new()
    {
        UpdateAvailable = true,
        CurrentVersion = new ReleaseVersion(1, 0, 0),
        LatestVersion = new ReleaseVersion(1, 1, 0),
        ReleaseNotes = "## Downloads\n\n- **Installer:** Windows [x64](https://example/setup.exe)\n- **Portable:** Windows [x64](https://example/portable.zip)\n\n## Changes since v1.0.0\n\n- Add folders to organize accounts (`abc1234`)\n- Fix update popup crash (`def5678`)",
        Asset = new ReleaseAsset("SimpleOTP-1.1.0-linux-x64.tar.gz", "https://example/asset", 1),
    };
}
