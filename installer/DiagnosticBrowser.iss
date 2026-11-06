; Diagnostic Browser release candidate. Compiles ONLY on approved Windows with Inno Setup.
; Installer uses separate per-user data under LOCALAPPDATA (not program folder).
#define MyAppName "Diagnostic Browser"
#define MyAppVersion "5.0.0rc4"
#define MyAppPublisher "Internal IT Engineering"
#define MyAppExeName "DiagnosticBrowser.exe"
[Setup]
AppId={{E795D702-8673-467A-965C-BC24FB1E968C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Diagnostic Browser
DefaultGroupName=Diagnostic Browser
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=DiagnosticBrowser-5.0.0rc4-UNSIGNED
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
[Files]
Source: "..\dist\DiagnosticBrowser.exe"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\Diagnostic Browser"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Diagnostic Browser"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Diagnostic Browser"; Flags: postinstall nowait skipifsilent unchecked
