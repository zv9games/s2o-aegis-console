; S2O Aegis Enterprise Platform Installer Script (Inno Setup)
; Produces a self-contained, signed-ready Windows installer for S2O Aegis

#define MyAppName "S2O Aegis Enterprise Security"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Split2ops Software"
#define MyAppURL "https://split2ops.com"
#define MyAppExeName "aegis-gui.exe"
#define MyDaemonExeName "aegisd.exe"
#define MyCliExeName "aegis.exe"

[Setup]
AppId={{D3F9B1E0-76A3-4B89-8BC2-4E90B01D21F4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\S2O Aegis
DefaultGroupName=S2O Aegis
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=S2O-Aegis-Setup-v1.0.0
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Primary executive GUI
Source: "target\release\aegis-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
; Master Daemon
Source: "target\release\aegisd.exe"; DestDir: "{app}"; Flags: ignoreversion
; Unified Master CLI
Source: "target\release\aegis.exe"; DestDir: "{app}"; Flags: ignoreversion
; 9 Pillar Binaries
Source: "target\release\cyberwall.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberdns.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cybermesh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberdefender.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberedr.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cybersiem.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberintel.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberid.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "target\release\cyberztna.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Aegis CLI Terminal"; Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyCliExeName}"" status"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Add Aegis directory to system PATH for convenient CLI execution
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + UpperCase(Param) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
end;
