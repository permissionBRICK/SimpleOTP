; Inno Setup script for SimpleOTP (framework-dependent .NET 10 Avalonia app).
;
; Build (on Windows, with Inno Setup 6.3+ — uses the built-in download page and the
; x64compatible architecture identifier):
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\SimpleOTP.iss ^
;       /DMyAppVersion=1.0.3 /DMyAppArch=win-x64 /DSourceDir=publish\win-x64 /Odist
;
; Supported /D defines (all optional, with the defaults below):
;   MyAppVersion  product/file version, e.g. 1.0.3
;   MyAppArch     win-x64 (default) or win-arm64
;   SourceDir     the framework-dependent publish output to package
;   IconFile      path to the app .ico
;
; The app is framework-dependent, so the installer checks for the .NET 10 *base* runtime
; (Microsoft.NETCore.App — Avalonia does NOT need the Desktop Runtime) and downloads + installs it
; from aka.ms when missing.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef MyAppArch
  #define MyAppArch "win-x64"
#endif
#ifndef SourceDir
  #define SourceDir "..\publish\" + MyAppArch
#endif
#ifndef IconFile
  #define IconFile "..\src\SimpleOtp.App\Assets\simpleotp.ico"
#endif

#define MyAppName "SimpleOTP"
#define MyAppExeName "SimpleOtp.exe"
#define MyAppPublisher "permissionBRICK"
#define MyAppUrl "https://github.com/permissionBRICK/SimpleOTP"

#if MyAppArch == "win-arm64"
  #define DotnetArch "arm64"
#else
  #define DotnetArch "x64"
#endif

[Setup]
; A stable AppId so future versions upgrade in place rather than installing side-by-side.
AppId={{B9A3F1E2-7C4D-4E8A-9F2B-1D6E5A0C7E34}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
VersionInfoVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Let the user pick a per-user (no admin) or all-users (admin) install, and a custom directory.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UsePreviousPrivileges=yes
UsePreviousAppDir=yes
UsePreviousTasks=yes
; Self-update: the running app holds this mutex so the silent installer waits for it to exit, then the
; [Run] entry below relaunches it.
AppMutex=SimpleOTP_SingleInstance_Mutex
CloseApplications=yes
CloseApplicationsFilter=*.exe
RestartApplications=no
; .NET 10 requires Windows 10 1607+ / Server 2016+.
MinVersion=10.0
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputBaseFilename=SimpleOTP-Setup-{#MyAppVersion}-{#MyAppArch}
#if MyAppArch == "win-arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "autoupdate"; Description: "Check for updates automatically on startup"; GroupDescription: "Updates:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Interactive install: offer a "launch now" checkbox on the finished page.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser
; Silent self-update: relaunch automatically after the new version is installed.
Filename: "{app}\{#MyAppExeName}"; Flags: nowait runasoriginaluser; Check: WizardSilent

[Code]
var
  DownloadPage: TDownloadWizardPage;
  NeedRuntime: Boolean;
  RuntimeUrl: String;
  RuntimeFile: String;

{ Compares dotted version strings; returns -1 / 0 / 1. }
function CompareVersion(V1, V2: String): Integer;
var
  P, N1, N2: Integer;
begin
  Result := 0;
  while (Result = 0) and ((V1 <> '') or (V2 <> '')) do
  begin
    P := Pos('.', V1);
    if P > 0 then begin N1 := StrToIntDef(Copy(V1, 1, P - 1), 0); Delete(V1, 1, P); end
    else if V1 <> '' then begin N1 := StrToIntDef(V1, 0); V1 := ''; end
    else N1 := 0;

    P := Pos('.', V2);
    if P > 0 then begin N2 := StrToIntDef(Copy(V2, 1, P - 1), 0); Delete(V2, 1, P); end
    else if V2 <> '' then begin N2 := StrToIntDef(V2, 0); V2 := ''; end
    else N2 := 0;

    if N1 < N2 then Result := -1
    else if N1 > N2 then Result := 1;
  end;
end;

{ True if Microsoft.NETCore.App >= MinVersion is installed for this arch (read from the 64-bit registry
  view so a 32-bit setup process still sees the x64/arm64 keys). }
function RuntimeInstalled(const MinVersion: String): Boolean;
var
  Key: String;
  Names: TArrayOfString;
  I: Integer;
begin
  Result := False;
  Key := 'SOFTWARE\dotnet\Setup\InstalledVersions\{#DotnetArch}\sharedfx\Microsoft.NETCore.App';
  if RegGetValueNames(HKLM64, Key, Names) then
    for I := 0 to GetArrayLength(Names) - 1 do
      if CompareVersion(Names[I], MinVersion) >= 0 then
      begin
        Result := True;
        Exit;
      end;
end;

function InitializeSetup(): Boolean;
begin
  NeedRuntime := not RuntimeInstalled('10.0.0');
  RuntimeUrl := 'https://aka.ms/dotnet/10.0/dotnet-runtime-win-{#DotnetArch}.exe';
  RuntimeFile := ExpandConstant('{tmp}\dotnet-runtime.exe');
  Result := True;
end;

procedure InitializeWizard();
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), nil);
  DownloadPage.ShowBaseNameInsteadOfUrl := True;
end;

function DownloadRuntime(): Boolean;
begin
  Result := True;
  if not NeedRuntime then Exit;
  DownloadPage.Clear;
  DownloadPage.Add(RuntimeUrl, 'dotnet-runtime.exe', ''); { no SHA pin: aka.ms tracks the latest patch }
  DownloadPage.Show;
  try
    try
      DownloadPage.Download;
      Result := True;
    except
      if not DownloadPage.AbortedByUser then
        SuppressibleMsgBox(AddPeriod(GetExceptionMessage), mbCriticalError, MB_OK, IDOK);
      Result := False;
    end;
  finally
    DownloadPage.Hide;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if not NeedRuntime then Exit;

  if not DownloadRuntime() then
  begin
    Result := 'The .NET 10 runtime is required but could not be downloaded. ' +
              'Check your internet connection and run Setup again, or install the .NET 10 Runtime manually.';
    Exit;
  end;

  if not Exec(RuntimeFile, '/install /quiet /norestart', '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 'Could not start the .NET runtime installer: ' + SysErrorMessage(ResultCode);
    Exit;
  end;

  case ResultCode of
    0: ;                                  { success }
    3010, 1641: NeedsRestart := True;     { success, reboot required }
    1602: Result := 'The .NET runtime installation was cancelled.';
  else
    Result := Format('The .NET runtime installer failed (exit code %d).', [ResultCode]);
  end;

  DeleteFile(RuntimeFile);
end;

{ Escapes backslashes for embedding a Windows path in a JSON string. }
function JsonEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
end;

{ Writes the install marker the app reads to choose its update channel/scope and initial auto-update setting. }
procedure WriteInstallMarker();
var
  Scope, Auto, Marker: String;
begin
  if IsAdminInstallMode then Scope := 'machine' else Scope := 'user';
  if WizardIsTaskSelected('autoupdate') then Auto := 'true' else Auto := 'false';
  Marker :=
    '{' + #13#10 +
    '  "channel": "inno",' + #13#10 +
    '  "scope": "' + Scope + '",' + #13#10 +
    '  "autoUpdate": ' + Auto + ',' + #13#10 +
    '  "installDir": "' + JsonEscape(ExpandConstant('{app}')) + '"' + #13#10 +
    '}' + #13#10;
  SaveStringToFile(ExpandConstant('{app}\simpleotp.install.json'), Marker, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteInstallMarker();
end;
