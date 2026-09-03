; CarrotAV installer - NSIS 3.x
; Builds on Linux or Windows:  makensis carrotav.nsi
; Produces: dist\CarrotAV-1.0.0-Setup.exe

Unicode false                     ; ANSI build so the installer runs on XP
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Var UPGRADING
Var PREV_VER

!define APPNAME    "CarrotAV"
!define APPVER     "1.9"
!define APPEXE     "carrotav.exe"
!define REGUNINST  "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name            "${APPNAME} ${APPVER}"
OutFile         "..\dist\CarrotAV-${APPVER}-Setup.exe"
; Install to <systemdrive>\CarrotAV, NOT "Program Files". The space in
; "Program Files" is what makes XP throw the "rename C:\Program to Program1"
; warning whenever any autostart path isn't perfectly quoted. A space-free
; path sidesteps that whole class of problem - and it's easier to find and
; back up, which suits a lightweight tool. The real system drive is filled in
; at install time in .onInit (falls back to C:).
InstallDir      "C:\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallPath"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText    "Carrot Software"
XPStyle on

VIProductVersion "1.9.0.0"
VIAddVersionKey "ProductName"     "${APPNAME}"
VIAddVersionKey "FileDescription" "${APPNAME} Setup"
VIAddVersionKey "FileVersion"     "${APPVER}"
VIAddVersionKey "CompanyName"     "Carrot Software"
VIAddVersionKey "LegalCopyright"  "Public domain"

!define MUI_ICON   "..\src\carrot.ico"
!define MUI_UNICON "..\src\carrot.ico"
!define MUI_ABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APPEXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME} now"
; No /background here: when the user ticks "Launch now" they expect to SEE the
; window. Background/tray mode is for the autostart-at-logon entry, not for a
; deliberate launch - starting hidden made it look like nothing happened.
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Read the setup notes (how to load virus definitions)"

!define MUI_WELCOMEPAGE_TEXT "Setup will install or upgrade ${APPNAME} on this computer.$\r$\n$\r$\nAn existing installation will be upgraded in place. Your virus definitions, system baseline, quarantine vault and exclusions are all preserved.$\r$\n$\r$\nClick Next to continue."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; ------------------------------------------------------------------
Section "Scanner engine (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "..\carrotav.exe"
  File "..\README.txt"
  SetOutPath "$INSTDIR\tools"
  File "..\tools\build_defs.py"
  File "..\tools\update_defs.cmd"
  File "..\tools\get_defs.py"
  File "..\tools\defupdate.exe"
  File "..\tools\cacerts.pem"
  File "..\tools\UPDATING_TLS.txt"
  CreateDirectory "$INSTDIR\Quarantine"
  CreateDirectory "$INSTDIR\defs"

  WriteRegStr HKLM "Software\${APPNAME}" "InstallPath" "$INSTDIR"
  WriteRegStr HKLM "Software\${APPNAME}" "Version"     "${APPVER}"

  ; Scrub autostart entries from older versions. Pre-1.8 installers wrote an
  ; HKLM "CarrotAV Shield" Run value, and some early builds wrote it without
  ; quotes - which makes XP show a "rename C:\Program to Program1" warning at
  ; every boot because of the space in "Program Files". Remove the old value
  ; unconditionally; the current quoted HKCU entry is written by SecStartup.
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "CarrotAV Shield"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "CarrotAV"

  WriteRegStr HKLM "${REGUNINST}" "DisplayName"     "${APPNAME} ${APPVER}"
  WriteRegStr HKLM "${REGUNINST}" "DisplayVersion"  "${APPVER}"
  WriteRegStr HKLM "${REGUNINST}" "Publisher"       "Carrot Software"
  WriteRegStr HKLM "${REGUNINST}" "DisplayIcon"     "$INSTDIR\${APPEXE}"
  WriteRegStr HKLM "${REGUNINST}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${REGUNINST}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${REGUNINST}" "NoModify" 1
  WriteRegDWORD HKLM "${REGUNINST}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"        "$INSTDIR\${APPEXE}"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Quick Scan.lnk"        "$INSTDIR\${APPEXE}" "/quick"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Full System Scan.lnk"  "$INSTDIR\${APPEXE}" "/full"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Update Definitions.lnk" "$INSTDIR\tools\update_defs.cmd"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Firewall.lnk" "$INSTDIR\${APPEXE}"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"         "$INSTDIR\uninstall.exe"
SectionEnd

Section "Virus definitions" SecDefs
  SetOutPath "$INSTDIR\defs"
  ; Ship updated signature defs, but only if the installer's copy is newer
  ; or none exists - never clobber a larger DB the user built with get_defs.
  ${If} $UPGRADING == "1"
  ${AndIf} ${FileExists} "$INSTDIR\defs\carrot.cdb"
    ; keep the existing carrot.cdb; user may have a fuller one
    DetailPrint "Keeping existing virus definitions."
  ${Else}
    File "..\defs\carrot.cdb"
  ${EndIf}
  ; system.cavb (baseline) and exclusions.txt are NEVER shipped, so an
  ; upgrade can't touch them - they just stay where they are.
SectionEnd

; ------------------------------------------------------------------
; Right-click integration. Four separate shell targets so the verb shows up
; on files, on folders, inside a folder's empty space, on the desktop, and
; on drives in My Computer.
Section "Right-click 'Scan with CarrotAV'" SecShell
  ; any file
  WriteRegStr HKCR "*\shell\CarrotAV" "" "Scan with CarrotAV"
  WriteRegStr HKCR "*\shell\CarrotAV" "Icon" "$INSTDIR\${APPEXE},0"
  WriteRegStr HKCR "*\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%1"'

  ; a folder (right-click the folder icon)
  WriteRegStr HKCR "Directory\shell\CarrotAV" "" "Scan with CarrotAV"
  WriteRegStr HKCR "Directory\shell\CarrotAV" "Icon" "$INSTDIR\${APPEXE},0"
  WriteRegStr HKCR "Directory\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%1"'

  ; empty space inside a folder window, and the XP desktop background.
  ; %V is the folder being viewed - %1 is empty for background verbs.
  WriteRegStr HKCR "Directory\Background\shell\CarrotAV" "" "Scan this folder with CarrotAV"
  WriteRegStr HKCR "Directory\Background\shell\CarrotAV" "Icon" "$INSTDIR\${APPEXE},0"
  WriteRegStr HKCR "Directory\Background\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%V"'

  ; desktop background on Vista and later (harmless on XP)
  WriteRegStr HKCR "DesktopBackground\shell\CarrotAV" "" "Scan Desktop with CarrotAV"
  WriteRegStr HKCR "DesktopBackground\shell\CarrotAV" "Icon" "$INSTDIR\${APPEXE},0"
  WriteRegStr HKCR "DesktopBackground\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%V"'

  ; a drive in My Computer
  WriteRegStr HKCR "Drive\shell\CarrotAV" "" "Scan with CarrotAV"
  WriteRegStr HKCR "Drive\shell\CarrotAV" "Icon" "$INSTDIR\${APPEXE},0"
  WriteRegStr HKCR "Drive\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%1"'

  ; the Recycle Bin and My Computer namespace folders
  WriteRegStr HKCR "Folder\shell\CarrotAV" "" "Scan with CarrotAV"
  WriteRegStr HKCR "Folder\shell\CarrotAV\command" "" '"$INSTDIR\${APPEXE}" "%1"'

  System::Call 'shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
SectionEnd

Section "Desktop icon" SecDesktop
  CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${APPEXE}"
SectionEnd

Section "Start real-time shield with Windows" SecStartup
  ; The app manages its own logon entry (HKCU "CarrotAV", properly quoted,
  ; with /background so it starts silently in the tray). We just enable that
  ; here by writing the same value the app's "Start Shield at Logon" toggle
  ; uses. Quotes around the path are REQUIRED - without them XP misreads
  ; "C:\Program Files\..." at the space and pops a "rename to Program1"
  ; warning at every boot.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" \
              "CarrotAV" '"$INSTDIR\${APPEXE}" /background'
SectionEnd

Section "Web shield blocklist (79,746 domains)" SecWeb
  SetOutPath "$INSTDIR\defs"
  File "..\defs\blocklist.txt"
  DetailPrint "Applying blocklist to HOSTS (this takes a moment)..."
  nsExec::ExecToLog '"$INSTDIR\${APPEXE}" /importhosts "$INSTDIR\defs\blocklist.txt"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "Web shield active."
  ${Else}
    DetailPrint "Could not write HOSTS - apply it later from the Protection tab."
  ${EndIf}
SectionEnd

Section /o "Turn on Windows Firewall" SecFW
  nsExec::ExecToLog '"$SYSDIR\netsh.exe" firewall set opmode mode=ENABLE'
  Pop $0
SectionEnd

; ------------------------------------------------------------------
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}    "The CarrotAV scanner, quarantine vault and definition tools."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDefs}    "Starter signature database. Run Update Definitions for the full ClamAV set."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShell}   "Adds 'Scan with CarrotAV' when you right-click a file, folder, drive, or empty desktop space."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Put a CarrotAV shortcut on the desktop."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartup} "Load the on-write real-time shield at logon."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecWeb}     "Block known malware and adware domains through the HOSTS file."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFW}      "Enable the built-in Windows Firewall."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Function .onInit
  StrCpy $UPGRADING "0"

  ; Is CarrotAV already here? Read where, and which version.
  ReadRegStr $0 HKLM "Software\${APPNAME}" "InstallPath"
  ReadRegStr $PREV_VER HKLM "Software\${APPNAME}" "Version"
  ${If} $0 != ""
    StrCpy $INSTDIR $0            ; upgrade in place, same folder
    StrCpy $UPGRADING "1"
  ${Else}
    ; fresh install: use the real system drive (usually C:), space-free path
    StrCpy $INSTDIR "$WINDIR"     ; e.g. C:\WINDOWS
    StrCpy $INSTDIR $INSTDIR 2    ; -> "C:"
    StrCpy $INSTDIR "$INSTDIR\${APPNAME}"   ; -> C:\CarrotAV
  ${EndIf}

  ; A running instance (window or /background tray) would lock carrotav.exe,
  ; so ask it to close, then wait. FindWindow matches the main window class.
  ${If} $UPGRADING == "1"
    FindWindow $1 "CarrotAVMain" ""
    ${If} $1 != 0
      SendMessage $1 ${WM_CLOSE} 0 0
      Sleep 400
    ${EndIf}
    ; the tray process may still be resident with no window - kill it so the
    ; file is unlocked. taskkill is absent on XP Home, so use our own switch.
    nsExec::ExecToLog '"$INSTDIR\${APPEXE}" /exitnow'
    Pop $2
    Sleep 600
  ${EndIf}
FunctionEnd

Function un.onInit
FunctionEnd

; ------------------------------------------------------------------
Section "Uninstall"
  nsExec::ExecToLog '"$INSTDIR\${APPEXE}" /clearhosts'
  Pop $0

  Delete "$INSTDIR\${APPEXE}"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\carrotav.log"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\tools\build_defs.py"
  Delete "$INSTDIR\tools\update_defs.cmd"
  Delete "$INSTDIR\tools\get_defs.py"
  Delete "$INSTDIR\tools\defupdate.exe"
  Delete "$INSTDIR\tools\cacerts.pem"
  Delete "$INSTDIR\tools\UPDATING_TLS.txt"
  Delete "$INSTDIR\defs\carrot.cdb"
  Delete "$INSTDIR\defs\blocklist.txt"
  RMDir /r "$INSTDIR\Quarantine"
  RMDir  "$INSTDIR\tools"
  RMDir  "$INSTDIR\defs"
  RMDir  "$INSTDIR"

  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$SMPROGRAMS\${APPNAME}"

  DeleteRegKey HKCR "*\shell\CarrotAV"
  DeleteRegKey HKCR "Directory\shell\CarrotAV"
  DeleteRegKey HKCR "Directory\Background\shell\CarrotAV"
  DeleteRegKey HKCR "DesktopBackground\shell\CarrotAV"
  DeleteRegKey HKCR "Drive\shell\CarrotAV"
  DeleteRegKey HKCR "Folder\shell\CarrotAV"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "CarrotAV"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "CarrotAV Shield"
  DeleteRegKey HKLM "Software\${APPNAME}"
  DeleteRegKey HKLM "${REGUNINST}"

  System::Call 'shell32::SHChangeNotify(i 0x8000000, i 0, i 0, i 0)'
SectionEnd
