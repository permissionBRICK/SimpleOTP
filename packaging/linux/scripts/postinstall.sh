#!/bin/sh
# Runs after install/upgrade for both .deb and .rpm. Must never exit non-zero for a missing runtime —
# that would fail the package install; we only warn.
set -e

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
fi

# Soft check for the .NET 10 base runtime (the app is framework-dependent).
if ! { command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null | grep -q 'Microsoft.NETCore.App 10\.'; }; then
    echo "SimpleOTP: the .NET 10 runtime was not detected." >&2
    if command -v apt-get >/dev/null 2>&1; then
        echo "  Install it with: sudo apt-get install -y dotnet-runtime-10.0" >&2
    elif command -v dnf >/dev/null 2>&1; then
        echo "  Install it with: sudo dnf install -y dotnet-runtime-10.0" >&2
    elif command -v zypper >/dev/null 2>&1; then
        echo "  Install it with: sudo zypper install -y dotnet-runtime-10.0" >&2
    else
        echo "  Install the 'dotnet-runtime-10.0' package for your distribution." >&2
    fi
fi

exit 0
