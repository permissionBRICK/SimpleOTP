using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using SimpleOtp.App.Services;
using SimpleOtp.App.ViewModels;
using SimpleOtp.App.Views;
using SimpleOtp.Tpm;

namespace SimpleOtp.App;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                // Inject the real TPM-backed sealer. The view model probes it on Bootstrap()
                // and shows the "no TPM" screen if none is present. The UpdateService checks GitHub for
                // a newer release once the window is shown.
                DataContext = new MainWindowViewModel(new TpmSecretSealer(), new UpdateService()),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
