# Windows installer (Inno Setup)

`SimpleOTP.iss` builds the Windows installer. It is **framework-dependent**: the app ships without a
bundled .NET runtime (smaller, faster startup), and the installer checks for the **.NET 10 base runtime**
(`Microsoft.NETCore.App` — Avalonia does not need the Desktop Runtime) and downloads + installs it from
`aka.ms` when it is missing.

## What it does

- Lets the user choose a **per-user** (no admin) or **all-users** (admin) install and a custom directory.
- Detects the .NET 10 runtime via the registry and silently installs it if absent.
- Creates Start-menu and optional desktop shortcuts.
- Offers a **"Check for updates automatically on startup"** task (on by default).
- Writes `simpleotp.install.json` next to the app so the in-app updater knows its channel (`inno`),
  scope (`user`/`machine`) and initial auto-update setting.
- Sets `AppMutex=SimpleOTP_SingleInstance_Mutex` (matching the running app) so a **silent self-update**
  waits for the app to close, then relaunches it.

## Build

Requires **Inno Setup 6.3+** (for the built-in download page and the `x64compatible` architecture
identifier). CI installs the current release via `choco install innosetup`. On a Windows machine or CI runner:

```powershell
# 1. Publish a framework-dependent build first (see the repo README), e.g.:
dotnet publish src/SimpleOtp.App -c Release -r win-x64 --no-self-contained `
  -p:Version=1.0.3 -p:PublishReadyToRun=true -o publish/win-x64

# 2. Compile the installer (SourceDir must be absolute or relative to the installer\ folder,
#    since Inno resolves a relative Source against the .iss directory — note the ..\ below):
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\SimpleOTP.iss `
    /DMyAppVersion=1.0.3 /DMyAppArch=win-x64 "/DSourceDir=$PWD\publish\win-x64" /Odist
```

Output: `dist\SimpleOTP-Setup-1.0.3-win-x64.exe`. Use `/DMyAppArch=win-arm64` (and the matching
`win-arm64` publish dir) for the Arm64 installer. CI builds both automatically.

## Silent install / self-update

```
SimpleOTP-Setup-<ver>-<arch>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

This is exactly what the in-app updater runs (elevating only for an all-users install). `UsePreviousAppDir`
/ `UsePreviousPrivileges` reuse the original location and scope.
