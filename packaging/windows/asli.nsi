; The Asli installer for Windows, built by build-installer.ps1 beside this file. Not meant to be
; compiled by hand: the script passes the version and the paths below as /D defines.
;
; It does what setup.ps1 -Install does, for someone who has never seen a terminal: a per user
; install into %LOCALAPPDATA%\Programs\Asli, so no administrator prompt; a Start menu shortcut;
; start at login through the Startup folder shortcut, written by asli.exe itself; and Asli started
; at the end. The uninstaller, listed in Settings > Apps, removes all of that and leaves the
; account key in Credential Manager and the settings in %APPDATA%\vnat\asli alone.

!ifndef VERSION | VIVERSION | SIZE_KB | SRCDIR | REPO | OUTFILE
  !error "build with packaging\windows\build-installer.ps1, which defines VERSION, VIVERSION, SIZE_KB, SRCDIR, REPO and OUTFILE"
!endif

Unicode true
ManifestDPIAware true
; Per user. No UAC prompt, and nothing written outside this user's profile and HKCU.
RequestExecutionLevel user
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Asli"
; The same names setup.ps1 and the program itself use, so either can clean up after the other.
!define STARTMENU_LINK "$SMPROGRAMS\Asli.lnk"
!define STARTUP_LINK "$SMSTARTUP\Asli.lnk"

Name "Asli"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\Asli"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"
BrandingText "Asli ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VIVERSION}"
VIAddVersionKey "ProductName" "Asli"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Asli installer"
VIAddVersionKey "CompanyName" "vnatco"
VIAddVersionKey "LegalCopyright" "MIT licensed"

; The Asli mark on the installer, the uninstaller, and the picture on the first and last pages.
!define MUI_ICON "${REPO}\packaging\windows\asli.ico"
!define MUI_UNICON "${REPO}\packaging\windows\asli.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${REPO}\packaging\windows\installer-sidebar.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${REPO}\packaging\windows\installer-sidebar.bmp"
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TITLE "Install Asli ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "Asli keeps the clipboard in sync across your own computers, end to end encrypted.$\r$\n$\r$\nIt installs for you alone, needs no administrator rights, and starts by itself when you sign in.$\r$\n$\r$\nClick Install to continue."
!define MUI_PAGE_CUSTOMFUNCTION_SHOW WelcomeShow
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "Asli is running"
!define MUI_FINISHPAGE_TEXT "Look for its icon in the notification area at the right of the taskbar. It may be under the ^ arrow.$\r$\n$\r$\nClick the icon to create an account, or to join one you already have on another computer."
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; The welcome page's button says Install rather than Next, since it is the only question asked.
Function WelcomeShow
  GetDlgItem $0 $HWNDPARENT 1
  SendMessage $0 ${WM_SETTEXT} 0 "STR:&Install"
FunctionEnd

; A running copy holds its executable open and the single instance lock, so it stops before the
; files are replaced or removed. taskkill by its full path: Windows looks in the working directory
; before PATH for a bare name.
!macro StopAsli
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM asliw.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM asli.exe'
  Pop $0
  Sleep 500
!macroend

Section "Asli" SecMain
  SetShellVarContext current
  SetOutPath "$INSTDIR"

  DetailPrint "Stopping any running copy of Asli"
  !insertmacro StopAsli

  File "${SRCDIR}\asli.exe"
  File "${SRCDIR}\asliw.exe"
  File "/oname=asli.ico" "${REPO}\packaging\windows\asli.ico"
  File "/oname=LICENSE.txt" "${REPO}\LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; The Start menu entry starts the windowed binary, so no console opens. Its icon is the one
  ; compiled into asliw.exe, which is the Asli mark.
  CreateShortcut "${STARTMENU_LINK}" "$INSTDIR\asliw.exe" "tray" "$INSTDIR\asliw.exe" 0 SW_SHOWNORMAL "" "Encrypted clipboard sync across your own machines"

  ; Start at login. asli.exe writes the Startup folder shortcut itself, pointing at asliw.exe
  ; beside it, which is the same code that checks the entry every time Asli starts. The Run key
  ; is deliberately not used: Explorer ignored it at logon on the owner's machine. A failure here
  ; does not fail the install, because Asli works without it and the tray retries at every start.
  DetailPrint "Turning on start at login"
  nsExec::ExecToLog '"$INSTDIR\asli.exe" autostart on'
  Pop $0
  ${If} $0 != 0
    DetailPrint "Could not turn on start at login ($0). Asli will try again when it starts."
  ${EndIf}

  ; Settings > Apps, and Add or Remove Programs, read this. HKCU because the install is per user.
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "Asli"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "vnatco"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\asli.ico"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKCU "${UNINSTALL_KEY}" "URLInfoAbout" "https://github.com/vnatco/asli"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "HelpLink" "https://github.com/vnatco/asli"
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1
  ; In kilobytes, which is the unit the Apps list expects.
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize" ${SIZE_KB}

  DetailPrint "Starting Asli"
  Exec '"$INSTDIR\asliw.exe" tray'
SectionEnd

Section "Uninstall"
  SetShellVarContext current

  DetailPrint "Stopping Asli"
  !insertmacro StopAsli

  ; Removed as files and values rather than through 'asli autostart off', which would also write
  ; the choice into the settings, and uninstalling leaves the settings as they were. The two Run
  ; values are where earlier builds put the entry.
  Delete "${STARTUP_LINK}"
  Delete "${STARTMENU_LINK}"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Asli"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "Asli"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" "Asli.lnk"

  Delete "$INSTDIR\asli.exe"
  Delete "$INSTDIR\asliw.exe"
  Delete "$INSTDIR\asli.ico"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  ; Only if empty, so nothing a person put there is lost.
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${UNINSTALL_KEY}"

  DetailPrint "Your account key is still in Windows Credential Manager, and your settings and"
  DetailPrint "history are still in $APPDATA\vnat\asli. To remove the key as well, run"
  DetailPrint "'asli reset' before uninstalling, or delete the 'asli' entry in Credential Manager."
SectionEnd
