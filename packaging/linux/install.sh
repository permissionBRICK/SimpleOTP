#!/usr/bin/env bash
#
# Install (or update) SimpleOTP from this tar.gz on Linux.
#
# Layout of the extracted tarball this script lives in:
#   SimpleOTP/install.sh        <- this script
#   SimpleOTP/uninstall.sh
#   SimpleOTP/app/              <- the framework-dependent .NET publish output (SimpleOtp + dlls)
#   SimpleOTP/simpleotp.png
#
# The app is framework-dependent, so this checks for the .NET 10 runtime and installs it if missing
# (via your package manager, or Microsoft's dotnet-install.sh as a fallback).
#
# Usage:
#   ./install.sh                 # system-wide if run as root, else per-user
#   ./install.sh --user          # force per-user (~/.local)
#   ./install.sh --system        # force system-wide (/opt, needs root)
#   ./install.sh --prefix DIR    # custom install directory
#   ./install.sh --no-runtime    # skip the .NET runtime check/install
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="$SCRIPT_DIR/app"

MODE=""
PREFIX=""
BINDIR=""
SKIP_RUNTIME=0

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --user)       MODE=user ;;
        --system)     MODE=system ;;
        --prefix)     PREFIX="${2:?--prefix needs a directory}"; shift ;;
        --bindir)     BINDIR="${2:?--bindir needs a directory}"; shift ;;
        --no-runtime) SKIP_RUNTIME=1 ;;
        -h|--help)    usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage 1 ;;
    esac
    shift
done

[ -d "$APP_SRC" ] || { echo "error: '$APP_SRC' not found — run install.sh from the extracted tarball." >&2; exit 1; }

if [ -z "$MODE" ]; then
    if [ "$(id -u)" -eq 0 ]; then MODE=system; else MODE=user; fi
fi

if [ "$MODE" = system ]; then
    PREFIX="${PREFIX:-/opt/simpleotp}"
    BINDIR="${BINDIR:-/usr/local/bin}"
    DESKTOP_DIR=/usr/share/applications
    ICON_DIR=/usr/share/icons/hicolor/512x512/apps
    SCOPE=machine
    if [ "$(id -u)" -ne 0 ]; then
        echo "A system-wide install needs root. Re-run with sudo, or use --user." >&2
        exit 1
    fi
else
    PREFIX="${PREFIX:-$HOME/.local/share/simpleotp}"
    BINDIR="${BINDIR:-$HOME/.local/bin}"
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
    SCOPE=user
fi

# --- .NET 10 runtime -----------------------------------------------------------

DOTNET_ROOT_OVERRIDE=""

has_runtime() {
    if command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null | grep -q 'Microsoft.NETCore.App 10\.'; then
        return 0
    fi
    if [ -x "$PREFIX/.dotnet/dotnet" ] && "$PREFIX/.dotnet/dotnet" --list-runtimes 2>/dev/null | grep -q 'Microsoft.NETCore.App 10\.'; then
        DOTNET_ROOT_OVERRIDE="$PREFIX/.dotnet"
        return 0
    fi
    return 1
}

ensure_runtime() {
    if has_runtime; then echo "Found .NET 10 runtime."; return; fi

    echo "The .NET 10 runtime was not found; attempting to install it..."
    local sudo=""
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo=sudo

    if command -v apt-get >/dev/null 2>&1; then
        $sudo apt-get update -y || true
        $sudo apt-get install -y dotnet-runtime-10.0 || true
    elif command -v dnf >/dev/null 2>&1; then
        $sudo dnf install -y dotnet-runtime-10.0 || true
    elif command -v zypper >/dev/null 2>&1; then
        $sudo zypper install -y dotnet-runtime-10.0 || true
    elif command -v pacman >/dev/null 2>&1; then
        $sudo pacman -S --noconfirm dotnet-runtime || true
    fi
    if has_runtime; then echo "Installed the .NET 10 runtime via the package manager."; return; fi

    # Fallback: Microsoft's official installer into the app's own private runtime dir.
    echo "Falling back to dotnet-install.sh (installing a private runtime under $PREFIX/.dotnet)..."
    local dl="$PREFIX/.dotnet-install.sh"
    mkdir -p "$PREFIX"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://dot.net/v1/dotnet-install.sh -o "$dl"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dl" https://dot.net/v1/dotnet-install.sh
    else
        echo "Neither curl nor wget is available; cannot download the .NET runtime." >&2
        echo "Install 'dotnet-runtime-10.0' manually, then re-run with --no-runtime." >&2
        exit 1
    fi
    bash "$dl" --runtime dotnet --channel 10.0 --install-dir "$PREFIX/.dotnet"
    rm -f "$dl"
    has_runtime || { echo "Failed to install the .NET 10 runtime." >&2; exit 1; }
    echo "Installed a private .NET 10 runtime under $PREFIX/.dotnet."
}

[ "$SKIP_RUNTIME" -eq 0 ] && ensure_runtime

# --- install files -------------------------------------------------------------

echo "Installing SimpleOTP to $PREFIX ..."
mkdir -p "$PREFIX"
cp -a "$APP_SRC"/. "$PREFIX"/
chmod +x "$PREFIX/SimpleOtp" 2>/dev/null || true

# Launcher on PATH. It exports DOTNET_ROOT only when we installed a private runtime.
mkdir -p "$BINDIR"
{
    echo "#!/bin/sh"
    [ -n "$DOTNET_ROOT_OVERRIDE" ] && echo "export DOTNET_ROOT=\"$DOTNET_ROOT_OVERRIDE\""
    echo "exec \"$PREFIX/SimpleOtp\" \"\$@\""
} > "$BINDIR/simpleotp"
chmod +x "$BINDIR/simpleotp"

# Icon + desktop entry (generated with absolute paths so it works for any prefix).
mkdir -p "$ICON_DIR"
cp -f "$SCRIPT_DIR/simpleotp.png" "$ICON_DIR/simpleotp.png"

mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/simpleotp.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SimpleOTP
GenericName=Authenticator
Comment=TPM-backed TOTP authenticator
Exec=$BINDIR/simpleotp
Icon=simpleotp
Terminal=false
Categories=Utility;Security;
StartupWMClass=SimpleOtp
EOF

# Install marker the in-app updater reads to choose the tarball update path.
cat > "$PREFIX/simpleotp.install.json" <<EOF
{
  "channel": "tarball",
  "scope": "$SCOPE",
  "autoUpdate": true,
  "installDir": "$PREFIX"
}
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "$DESKTOP_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    # ICON_DIR is .../hicolor/512x512/apps; the theme root (.../hicolor) is two levels up.
    gtk-update-icon-cache -q -t -f "$(dirname "$(dirname "$ICON_DIR")")" 2>/dev/null || true
fi

echo "Done. SimpleOTP is installed."
echo "Launch it from your application menu, or run: $BINDIR/simpleotp"
case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *) [ "$MODE" = user ] && echo "Note: $BINDIR is not on your PATH; add it to run 'simpleotp' directly." ;;
esac
