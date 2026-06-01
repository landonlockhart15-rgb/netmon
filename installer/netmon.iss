; netmon.iss — Inno Setup script for the NetMon double-click installer.
;
; Build (after PyInstaller has produced dist\NetMon\):
;     "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\netmon.iss
; or use tools\build_installer.ps1 which runs both steps.
;
; Produces: installer\Output\NetMon-Setup-<version>.exe
;
; The app itself stores all user data in %LOCALAPPDATA%\NetMon, so the install
; directory under Program Files stays read-only. NetMon.exe carries a
; requireAdministrator manifest (it needs admin for nmap, firewall rules, DNS
; on port 53, and packet capture), so Windows will prompt for elevation on
; launch — that's expected.

#define AppName "NetMon"
#define AppVersion "0.3.0"
#define AppPublisher "Landon Lockhart"
#define AppURL "https://github.com/landonlockhart15-rgb/netmon"
#define AppExeName "NetMon.exe"

[Setup]
; A stable, unique AppId so upgrades/uninstalls are tracked correctly.
AppId={{B3F4E9C2-7A1D-4E8B-9C5F-2D6A8B1E4C70}
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
LicenseFile=..\LICENSE
OutputDir=Output
OutputBaseFilename=NetMon-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Installing into Program Files needs admin.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
; The entire PyInstaller one-dir output (NetMon.exe + _internal\...).
Source: "..\dist\NetMon\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch after install. nostack+runascurrentuser keeps it tied to the
; installing user; the exe self-elevates via its own manifest.
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leave user data (%LOCALAPPDATA%\NetMon) in place on uninstall by default —
; it holds the DB, captures, and logs. Only the program files are removed.
Type: dirifempty; Name: "{app}"
