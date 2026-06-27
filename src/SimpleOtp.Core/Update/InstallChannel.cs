namespace SimpleOtp.Core.Update;

/// <summary>
/// How this copy of SimpleOTP was installed. Read from the install marker file (see
/// <see cref="InstallInfo"/>); determines which release asset an update downloads and how it is
/// applied (silent installer re-run, file swap, or package-manager install).
/// </summary>
public enum InstallChannel
{
    /// <summary>No marker found — best-effort update via the OS default asset; treated like Portable/Tarball.</summary>
    Unknown = 0,

    /// <summary>Windows: installed by the Inno Setup installer (.exe). Update = silent installer re-run.</summary>
    Inno,

    /// <summary>Windows: unpacked from the self-contained portable .zip. Update = download zip, swap files.</summary>
    Portable,

    /// <summary>Linux: unpacked from the .tar.gz with install.sh. Update = download tarball, run update.sh.</summary>
    Tarball,

    /// <summary>Linux: installed from the .deb package. Update = download .deb, install via pkexec/dpkg.</summary>
    Deb,

    /// <summary>Linux: installed from the .rpm package. Update = download .rpm, install via pkexec/rpm.</summary>
    Rpm,
}
