#!/usr/bin/env bash
#
# Uninstall a tar.gz install of SimpleOTP (the .deb/.rpm packages are removed with apt/dnf instead).
#
# Usage:
#   ./uninstall.sh                # system if run as root, else per-user
#   ./uninstall.sh --user | --system | --prefix DIR
#
set -euo pipefail

MODE=""
PREFIX=""
BINDIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --user)    MODE=user ;;
        --system)  MODE=system ;;
        --prefix)  PREFIX="${2:?--prefix needs a directory}"; shift ;;
        --bindir)  BINDIR="${2:?--bindir needs a directory}"; shift ;;
        -h|--help) echo "Usage: $0 [--user|--system|--prefix DIR]"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

if [ -z "$MODE" ]; then
    if [ "$(id -u)" -eq 0 ]; then MODE=system; else MODE=user; fi
fi

if [ "$MODE" = system ]; then
    PREFIX="${PREFIX:-/opt/simpleotp}"
    BINDIR="${BINDIR:-/usr/local/bin}"
    DESKTOP_DIR=/usr/share/applications
    ICON_DIR=/usr/share/icons/hicolor/512x512/apps
    if [ "$(id -u)" -ne 0 ]; then echo "A system-wide uninstall needs root (sudo), or use --user." >&2; exit 1; fi
else
    PREFIX="${PREFIX:-$HOME/.local/share/simpleotp}"
    BINDIR="${BINDIR:-$HOME/.local/bin}"
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
fi

rm -rf "$PREFIX"
rm -f "$BINDIR/simpleotp"
rm -f "$DESKTOP_DIR/simpleotp.desktop"
rm -f "$ICON_DIR/simpleotp.png"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "$DESKTOP_DIR" 2>/dev/null || true
fi

echo "SimpleOTP removed from $PREFIX."
echo "Your vault (~/.config/SimpleOtp) was left untouched. Delete it manually if you want it gone."
