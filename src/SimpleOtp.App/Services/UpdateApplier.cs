using System;
using System.Diagnostics;
using System.IO;
using SimpleOtp.Core.Update;

namespace SimpleOtp.App.Services;

/// <summary>
/// Launches the platform-specific "apply the downloaded update and restart" step. Each path starts an
/// external helper (the silent installer, or a small swap/relaunch script) that waits for THIS process
/// to exit before replacing files — so the caller must shut the app down immediately after this returns.
///
/// Cross-channel contract for the relaunch:
///  - Windows / Inno:   the installer's [Run] entry relaunches SimpleOtp.exe after a silent re-install.
///  - all other paths:  a generated script waits for our PID, swaps files (elevating if needed), and
///                      relaunches the app itself.
/// </summary>
internal static class UpdateApplier
{
    public static void Launch(InstallInfo install, string downloadedPath)
    {
        if (OperatingSystem.IsWindows())
            LaunchWindows(install, downloadedPath);
        else if (OperatingSystem.IsLinux())
            LaunchLinux(install, downloadedPath);
        else
            throw new PlatformNotSupportedException("In-app update is only supported on Windows and Linux.");
    }

    // --- Windows ------------------------------------------------------------

    private static void LaunchWindows(InstallInfo install, string file)
    {
        bool isZip = file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
        if (install.Channel == InstallChannel.Portable || isZip)
        {
            LaunchWindowsPortable(install, file);
            return;
        }

        // Inno Setup installer. Re-run it silently over the existing install; the installer's AppMutex
        // makes it wait for this app to exit, then its [Run] entry relaunches us. UsePreviousPrivileges
        // / UsePreviousAppDir in the .iss reuse the original scope and directory, so no /DIR or
        // /ALLUSERS is needed here — we only elevate when the original install was machine-wide.
        var psi = new ProcessStartInfo
        {
            FileName = file,
            Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            UseShellExecute = true,
        };
        if (install.RequiresElevation)
            psi.Verb = "runas"; // UAC prompt so the silent installer can write to Program Files
        Process.Start(psi);
    }

    private static void LaunchWindowsPortable(InstallInfo install, string zipFile)
    {
        string exe = Path.Combine(install.InstallDir, "SimpleOtp.exe");
        string script = WriteTempScript("simpleotp-update.ps1", WindowsPortableScript);
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(script);
        psi.ArgumentList.Add("-ProcId"); psi.ArgumentList.Add(Environment.ProcessId.ToString());
        psi.ArgumentList.Add("-Zip"); psi.ArgumentList.Add(zipFile);
        psi.ArgumentList.Add("-Dest"); psi.ArgumentList.Add(install.InstallDir);
        psi.ArgumentList.Add("-Exe"); psi.ArgumentList.Add(exe);
        Process.Start(psi);
    }

    // --- Linux --------------------------------------------------------------

    private static void LaunchLinux(InstallInfo install, string file)
    {
        string exe = Path.Combine(install.InstallDir, "SimpleOtp");
        switch (install.Channel)
        {
            case InstallChannel.Deb:
                RunBash(WritePackageScript(), Environment.ProcessId.ToString(), file, exe, "deb");
                break;
            case InstallChannel.Rpm:
                RunBash(WritePackageScript(), Environment.ProcessId.ToString(), file, exe, "rpm");
                break;
            default: // Tarball / Unknown
                RunBash(WriteTempScript("simpleotp-update.sh", LinuxTarballScript),
                    Environment.ProcessId.ToString(), file, install.InstallDir, exe);
                break;
        }
    }

    private static string WritePackageScript() => WriteTempScript("simpleotp-update.sh", LinuxPackageScript);

    private static void RunBash(string script, params string[] args)
    {
        var psi = new ProcessStartInfo { FileName = "/bin/bash", UseShellExecute = false };
        psi.ArgumentList.Add(script);
        foreach (string a in args) psi.ArgumentList.Add(a);
        Process.Start(psi);
    }

    // --- helpers ------------------------------------------------------------

    private static string WriteTempScript(string name, string content)
    {
        string dir = Path.Combine(Path.GetTempPath(), "SimpleOtpUpdate");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.WriteAllText(path, content.ReplaceLineEndings(OperatingSystem.IsWindows() ? "\r\n" : "\n"));
        return path;
    }

    // PowerShell: wait for the app to exit, unpack the portable zip over the install dir, relaunch.
    private const string WindowsPortableScript = """
        param(
            [int]$ProcId,
            [string]$Zip,
            [string]$Dest,
            [string]$Exe
        )
        $ErrorActionPreference = 'Stop'
        try { Wait-Process -Id $ProcId -Timeout 60 } catch { }
        Start-Sleep -Milliseconds 500
        Expand-Archive -LiteralPath $Zip -DestinationPath $Dest -Force
        Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
        Start-Process -FilePath $Exe
        """;

    // Bash: wait for the app to exit, swap the tar.gz's app payload into the install dir (elevating with
    // pkexec when the dir is not writable), relaunch. The tarball lays its app files under SimpleOTP/app/.
    private const string LinuxTarballScript = """
        #!/usr/bin/env bash
        set -e
        PID="$1"; TARBALL="$2"; DEST="$3"; EXE="$4"
        for _ in $(seq 1 120); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
        STAGING="$(mktemp -d)"
        tar -xzf "$TARBALL" -C "$STAGING"
        SRC="$STAGING/SimpleOTP/app"
        [ -d "$SRC" ] || SRC="$STAGING"
        if [ -w "$DEST" ]; then
            cp -a "$SRC"/. "$DEST"/
        else
            pkexec cp -a "$SRC"/. "$DEST"/
        fi
        rm -rf "$STAGING" "$TARBALL"
        nohup "$EXE" >/dev/null 2>&1 &
        """;

    // Bash: wait for the app to exit, install the new .deb/.rpm via pkexec (graphical auth), relaunch.
    // The package path is passed as a positional argument ($1) to the elevated shell rather than
    // interpolated into the -c string, so a filename containing quotes/spaces/semicolons can neither
    // break the command nor inject into the elevated shell.
    internal const string LinuxPackageScript = """
        #!/usr/bin/env bash
        set -e
        PID="$1"; PKG="$2"; EXE="$3"; KIND="$4"
        for _ in $(seq 1 120); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
        if [ "$KIND" = "deb" ]; then
            pkexec sh -c 'dpkg -i "$1" || apt-get -f install -y' sh "$PKG"
        else
            pkexec sh -c 'rpm -U --force "$1"' sh "$PKG"
        fi
        rm -f "$PKG"
        nohup "$EXE" >/dev/null 2>&1 &
        """;
}
