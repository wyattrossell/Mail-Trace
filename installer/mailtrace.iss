; Inno Setup script for MailTrace.
; Compiled by scripts/build_release.py:  ISCC.exe /DAppVersion=x.y.z installer\mailtrace.iss
;
; Upgrade behaviour: the fixed AppId makes every new version install over the
; previous one in place. [InstallDelete] removes shortcuts left by earlier
; versions (any name we have ever used) before the new shortcuts are created,
; so the desktop never shows a stale or duplicate icon after an update.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "MailTrace"
#define AppPublisher "MailTrace"
#define AppURL "https://github.com/wyattrossell/Mail-Trace"
#define AppExe "MailTrace.exe"
#define SourceDir "..\dist\MailTrace"

[Setup]
AppId={{7D9B4C2E-3F61-4E0A-9B7C-5A2D1F8E6C43}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Per-user by default (no admin prompt); the user may elevate for an all-users install.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\release
OutputBaseFilename=MailTrace-Setup-{#AppVersion}
SetupIconFile=..\assets\mailtrace.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Ask the running app to close before replacing files during an update.
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll,*.pyd
RestartApplications=no
LicenseFile=..\LICENSE
VersionInfoVersion={#AppVersion}
VersionInfoDescription={#AppName} installer
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\assets\mailtrace.ico"; DestDir: "{app}\assets"; Flags: ignoreversion

[InstallDelete]
; Remove every shortcut an earlier version may have created, on both the
; per-user and all-users desktop, before creating the new one below.
Type: files; Name: "{userdesktop}\{#AppName}.lnk"
Type: files; Name: "{commondesktop}\{#AppName}.lnk"
Type: files; Name: "{userdesktop}\Mail Trace.lnk"
Type: files; Name: "{commondesktop}\Mail Trace.lnk"
Type: files; Name: "{userdesktop}\{#AppName} (CLI).lnk"
Type: files; Name: "{commondesktop}\{#AppName} (CLI).lnk"
Type: filesandordirs; Name: "{userprograms}\{#AppName}"
Type: filesandordirs; Name: "{commonprograms}\{#AppName}"
; Stale files from a previous layout inside the install folder.
Type: files; Name: "{app}\mailtrace.exe"

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\assets\mailtrace.ico"; Comment: "Passive forensic email analysis"
Name: "{autoprograms}\{#AppName} command line"; Filename: "{cmd}"; Parameters: "/k ""{app}\mailtrace-cli.exe"" --help"; WorkingDir: "{app}"; IconFilename: "{app}\assets\mailtrace.ico"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\assets\mailtrace.ico"; Tasks: desktopicon

[Registry]
; Lets the app find its own install location and lets "Add or remove programs" show the icon.
Root: HKA; Subkey: "Software\{#AppName}"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\{#AppName}"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{userdesktop}\{#AppName}.lnk"
Type: files; Name: "{commondesktop}\{#AppName}.lnk"
Type: filesandordirs; Name: "{app}"
