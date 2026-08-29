; CarrotAV installer
; Build with Inno Setup 5.6.1 (the last release with full Win9x/XP support).
; ISCC.exe carrotav.iss
;
; If you own InstallShield, this maps 1:1 onto a Basic MSI project:
;   [Files]    -> File Table / components
;   [Icons]    -> Shortcut Table
;   [Registry] -> Registry Table
;   [Run]      -> Custom Actions (deferred, after InstallFinalize)

#define AppName    "CarrotAV"
#define AppVersion "1.1"
#define AppExe     "carrotav.exe"

[Setup]
AppId={{8F2C4A10-7D3E-4B91-9C55-CA55E7A1D001}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Carrot Software
DefaultDirName={pf}\{#AppName}
DefaultGroupName={#AppName}
OutputBaseFilename=CarrotAV-{#AppVersion}-Setup
OutputDir=..\dist
Compression=lzma
SolidCompression=yes

; --- XP / classic wizard look ---
MinVersion=0,5.01
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=
PrivilegesRequired=admin
DisableWelcomePage=no
WizardImageFile=compiler:WIZMODERNIMAGE-IS.bmp
WizardSmallImageFile=compiler:WIZMODERNSMALLIMAGE-IS.bmp
SetupIconFile=..\src\carrot.ico
UninstallDisplayIcon={app}\{#AppExe}
ShowLanguageDialog=no
AllowNoIcons=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full";    Description: "Full installation"
Name: "compact"; Description: "Scanner only"
Name: "custom";  Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core";   Description: "CarrotAV scanner engine"; Types: full compact custom; Flags: fixed
Name: "defs";   Description: "Virus definition database"; Types: full custom
Name: "shield"; Description: "Real-time protection shield"; Types: full custom
Name: "web";    Description: "Web shield blocklist"; Types: full custom

[Tasks]
Name: "desktopicon";  Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"
Name: "quicklaunch";  Description: "Create a &Quick Launch icon"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startup";      Description: "Start the real-time shield when Windows starts"; GroupDescription: "Protection:"; Components: shield
Name: "importhosts";  Description: "Apply the bundled malware domain blocklist to HOSTS"; GroupDescription: "Protection:"; Components: web

[Files]
Source: "..\carrotav.exe";        DestDir: "{app}";      Components: core;  Flags: ignoreversion
Source: "..\README.txt";          DestDir: "{app}";      Components: core;  Flags: ignoreversion isreadme
Source: "..\tools\build_defs.py"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
Source: "..\tools\update_defs.cmd"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
Source: "..\tools\get_defs.py"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
; These two are optional - the installer still runs if they are absent.
Source: "..\defs\carrot.cdb";     DestDir: "{app}\defs"; Components: defs; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\defs\blocklist.txt";  DestDir: "{app}\defs"; Components: web;  Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
Name: "{app}\Quarantine"; Permissions: users-modify
Name: "{app}\defs"

[Icons]
Name: "{group}\{#AppName}";                Filename: "{app}\{#AppExe}"
Name: "{group}\Quick Scan";                Filename: "{app}\{#AppExe}"; Parameters: "/quick"
Name: "{group}\Full System Scan";          Filename: "{app}\{#AppExe}"; Parameters: "/full"
Name: "{group}\Uninstall {#AppName}";      Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";        Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#AppName}"; \
      Filename: "{app}\{#AppExe}"; Tasks: quicklaunch

[Registry]
Root: HKLM; Subkey: "Software\CarrotAV"; ValueType: string; ValueName: "InstallPath"; \
      ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "CarrotAV Shield"; ValueData: """{app}\{#AppExe}"""; \
      Tasks: startup; Flags: uninsdeletevalue
; right-click integration: files, folders, folder background, desktop, drives
Root: HKCR; Subkey: "*\shell\CarrotAV"; ValueType: string; ValueData: "Scan with CarrotAV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\CarrotAV"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKCR; Subkey: "*\shell\CarrotAV\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "Directory\shell\CarrotAV"; ValueType: string; ValueData: "Scan with CarrotAV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\CarrotAV"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKCR; Subkey: "Directory\shell\CarrotAV\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey

; empty space inside a folder window and the XP desktop background (%V = folder shown)
Root: HKCR; Subkey: "Directory\Background\shell\CarrotAV"; ValueType: string; ValueData: "Scan this folder with CarrotAV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\Background\shell\CarrotAV"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKCR; Subkey: "Directory\Background\shell\CarrotAV\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%V"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "DesktopBackground\shell\CarrotAV"; ValueType: string; ValueData: "Scan Desktop with CarrotAV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "DesktopBackground\shell\CarrotAV\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%V"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "Drive\shell\CarrotAV"; ValueType: string; ValueData: "Scan with CarrotAV"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Drive\shell\CarrotAV"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"
Root: HKCR; Subkey: "Drive\shell\CarrotAV\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey

[Run]      -> Custom Actions (deferred, after InstallFinalize)

#define AppName    "CarrotAV"
#define AppVersion "1.1"
#define AppExe     "carrotav.exe"

[Setup]
AppId={{8F2C4A10-7D3E-4B91-9C55-CA55E7A1D001}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Carrot Software
DefaultDirName={pf}\{#AppName}
DefaultGroupName={#AppName}
OutputBaseFilename=CarrotAV-{#AppVersion}-Setup
OutputDir=..\dist
Compression=lzma
SolidCompression=yes

; --- XP / classic wizard look ---
MinVersion=0,5.01
ArchitecturesAllowed=x86 x64
ArchitecturesInstallIn64BitMode=
PrivilegesRequired=admin
DisableWelcomePage=no
WizardImageFile=compiler:WIZMODERNIMAGE-IS.bmp
WizardSmallImageFile=compiler:WIZMODERNSMALLIMAGE-IS.bmp
SetupIconFile=..\src\carrot.ico
UninstallDisplayIcon={app}\{#AppExe}
ShowLanguageDialog=no
AllowNoIcons=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full";    Description: "Full installation"
Name: "compact"; Description: "Scanner only"
Name: "custom";  Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core";   Description: "CarrotAV scanner engine"; Types: full compact custom; Flags: fixed
Name: "defs";   Description: "Virus definition database"; Types: full custom
Name: "shield"; Description: "Real-time protection shield"; Types: full custom
Name: "web";    Description: "Web shield blocklist"; Types: full custom

[Tasks]
Name: "desktopicon";  Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"
Name: "quicklaunch";  Description: "Create a &Quick Launch icon"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startup";      Description: "Start the real-time shield when Windows starts"; GroupDescription: "Protection:"; Components: shield
Name: "importhosts";  Description: "Apply the bundled malware domain blocklist to HOSTS"; GroupDescription: "Protection:"; Components: web

[Files]
Source: "..\carrotav.exe";        DestDir: "{app}";      Components: core;  Flags: ignoreversion
Source: "..\README.txt";          DestDir: "{app}";      Components: core;  Flags: ignoreversion isreadme
Source: "..\tools\build_defs.py"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
Source: "..\tools\update_defs.cmd"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
Source: "..\tools\get_defs.py"; DestDir: "{app}\tools"; Components: core; Flags: ignoreversion
; These two are optional - the installer still runs if they are absent.
Source: "..\defs\carrot.cdb";     DestDir: "{app}\defs"; Components: defs; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\defs\blocklist.txt";  DestDir: "{app}\defs"; Components: web;  Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
Name: "{app}\Quarantine"; Permissions: users-modify
Name: "{app}\defs"

[Icons]
Name: "{group}\{#AppName}";                Filename: "{app}\{#AppExe}"
Name: "{group}\Quick Scan";                Filename: "{app}\{#AppExe}"; Parameters: "/quick"
Name: "{group}\Full System Scan";          Filename: "{app}\{#AppExe}"; Parameters: "/full"
Name: "{group}\Uninstall {#AppName}";      Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";        Filename: "{app}\{#AppExe}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#AppName}"; \
      Filename: "{app}\{#AppExe}"; Tasks: quicklaunch

[Registry]
Root: HKLM; Subkey: "Software\CarrotAV"; ValueType: string; ValueName: "InstallPath"; \
      ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "CarrotAV Shield"; ValueData: """{app}\{#AppExe}"""; \
      Tasks: startup; Flags: uninsdeletevalue
; right-click any file -> Scan with CarrotAV
Root: HKCR; Subkey: "*\shell\CarrotAV"; ValueType: string; ValueData: "Scan with CarrotAV"; \
      Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\CarrotAV\command"; ValueType: string; \
      ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\CarrotAV"; ValueType: string; ValueData: "Scan with CarrotAV"; \
      Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\CarrotAV\command"; ValueType: string; \
      ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "/importhosts ""{app}\defs\blocklist.txt"""; \
      StatusMsg: "Applying the web shield blocklist..."; Tasks: importhosts; \
      Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName} now"; \
      Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "/clearhosts"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}\Quarantine"
Type: files;          Name: "{app}\carrotav.log"

[Code]
function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  if Version.NTPlatform and (Version.Major < 5) then
  begin
    MsgBox('CarrotAV requires Windows 2000 or later.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Turn on the Windows Firewall if the user kept the protection component.
    if IsComponentSelected('shield') then
      Exec(ExpandConstant('{sys}\netsh.exe'),
           'firewall set opmode mode=ENABLE', '',
           SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
