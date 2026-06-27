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
/// Every path waits for THIS process to exit before touching files (a running instance makes a silent
/// Inno install abort via AppMutex and locks the files it must replace).
/// Relaunch:
///  - Windows / Inno:   the installer's [Run] entry relaunches SimpleOtp.exe after the silent re-install.
///  - all other paths:  the generated script relaunches the app itself.
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
            // Portable: wait for exit, expand the zip over the install dir, relaunch.
            string exe = Path.Combine(install.InstallDir, "SimpleOtp.exe");
            RunPowerShell(WriteTempScript("simpleotp-portable.ps1", WindowsPortableScript),
                "-ProcId", Environment.ProcessId.ToString(), "-Zip", file, "-Dest", install.InstallDir, "-Exe", exe);
            return;
        }

        // Inno Setup installer. A helper waits for this app to FULLY exit, then runs the installer
        // silently — otherwise the still-running instance makes /VERYSILENT abort (AppMutex) and locks
        // the files being replaced. The installer's [Run] entry relaunches us. UsePreviousPrivileges /
        // UsePreviousAppDir in the .iss reuse the original scope and directory; we only elevate when the
        // original install was machine-wide.
        RunPowerShell(WriteTempScript("simpleotp-installer.ps1", WindowsInstallerScript),
            "-ProcId", Environment.ProcessId.ToString(),
            "-Installer", file,
            "-Elevate", install.RequiresElevation ? "1" : "0");
    }

    private static void RunPowerShell(string script, params string[] args)
    {
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
        foreach (string a in args) psi.ArgumentList.Add(a);
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

    // PowerShell: wait for the app to exit, then run the Inno installer silently (elevating for a
    // machine-wide install). The installer's [Run] entry relaunches the app.
    private const string WindowsInstallerScript = """
        param(
            [int]$ProcId,
            [string]$Installer,
            [string]$Elevate
        )
        try { Wait-Process -Id $ProcId -Timeout 120 } catch { }
        Start-Sleep -Milliseconds 500
        $flags = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')
        if ($Elevate -eq '1') {
            Start-Process -FilePath $Installer -ArgumentList $flags -Verb RunAs
        } else {
            Start-Process -FilePath $Installer -ArgumentList $flags
        }
        """;

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
