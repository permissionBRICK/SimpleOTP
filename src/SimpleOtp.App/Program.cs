using Avalonia;
using System;
using System.Threading;

namespace SimpleOtp.App;

sealed class Program
{
    // Held for the whole process lifetime so the Inno Setup installer's matching AppMutex can detect a
    // running instance and wait for it to exit during a self-update. Released automatically on process
    // exit. The name MUST match AppMutex= in the .iss script.
    private static Mutex? _appMutex;

    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        CreateAppMutex();
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static void CreateAppMutex()
    {
        if (!OperatingSystem.IsWindows()) return; // only the Windows installer consumes it
        try { _appMutex = new Mutex(initiallyOwned: true, "SimpleOTP_SingleInstance_Mutex"); }
        catch { /* the mutex is only an aid for the installer; failing to create it is non-fatal */ }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
