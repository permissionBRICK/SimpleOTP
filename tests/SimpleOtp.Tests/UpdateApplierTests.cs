using System.Diagnostics;
using SimpleOtp.App.Services;

namespace SimpleOtp.Tests;

/// <summary>
/// Verifies the generated Linux package-update script is injection-safe: a package filename containing
/// shell metacharacters must reach the elevated installer as a single intact argument and must not be
/// able to execute attacker-controlled commands. Linux-only (the script is bash + uses pkexec/dpkg,
/// which we shadow with fakes on PATH so nothing is actually installed or elevated).
/// </summary>
public class UpdateApplierTests : IDisposable
{
    private readonly string _dir;

    public UpdateApplierTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "simpleotp-applier-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* ignore */ }
    }

    [SkippableFact]
    public void LinuxPackageScript_MaliciousFilename_DoesNotInject_AndReachesInstallerIntact()
    {
        Skip.IfNot(OperatingSystem.IsLinux(), "Bash/pkexec script is Linux-only.");

        string bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);

        // Fake pkexec that simply runs its argument command (so the inner `sh -c` actually executes —
        // this is what would let an injection fire on a vulnerable script).
        WriteExecutable(Path.Combine(bin, "pkexec"), "#!/usr/bin/env bash\nexec \"$@\"\n");
        // Fake dpkg/apt-get that record their args and do nothing.
        string dpkgArgs = Path.Combine(_dir, "dpkg-args.txt");
        WriteExecutable(Path.Combine(bin, "dpkg"), $"#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" >> '{dpkgArgs}'\nexit 0\n");
        WriteExecutable(Path.Combine(bin, "apt-get"), "#!/usr/bin/env bash\nexit 0\n");

        string script = Path.Combine(_dir, "update.sh");
        File.WriteAllText(script, UpdateApplier.LinuxPackageScript);

        // A package whose basename tries to break out of quoting and run `touch pwned`. The name has no
        // '/' (it must be a real filename); the script runs with WorkingDirectory = _dir, so an
        // injected `touch pwned` would land there.
        string marker = Path.Combine(_dir, "pwned");
        string evilName = "a'; touch pwned; true #.deb";
        string pkg = Path.Combine(_dir, evilName);
        File.WriteAllText(pkg, "pkg");

        var psi = new ProcessStartInfo("/bin/bash")
        {
            UseShellExecute = false,
            RedirectStandardError = true,
            WorkingDirectory = _dir,
        };
        psi.ArgumentList.Add(script);
        psi.ArgumentList.Add("999999");     // a PID that is not running, so the wait loop exits at once
        psi.ArgumentList.Add(pkg);
        psi.ArgumentList.Add("/bin/true");  // harmless "relaunch"
        psi.ArgumentList.Add("deb");
        psi.Environment["PATH"] = bin + ":" + Environment.GetEnvironmentVariable("PATH");

        using Process p = Process.Start(psi)!;
        Assert.True(p.WaitForExit(15000), "update script did not finish in time");

        Assert.False(File.Exists(marker), "command injection executed — the malicious filename ran `touch`");
        Assert.True(File.Exists(dpkgArgs), "dpkg was not invoked");
        // The exact package path must have reached dpkg as one intact argument.
        Assert.Contains(pkg, File.ReadAllLines(dpkgArgs));
    }

    private static void WriteExecutable(string path, string content)
    {
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows()) // the test only runs on Linux; guard satisfies the platform analyzer
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
    }
}
