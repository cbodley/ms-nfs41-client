; Use modern interface
  !include MUI2.nsh
  !include x64.nsh
  !define MUI_FINISHPAGE_NOAUTOCLOSE

; General
  Name                  "NFSv4.1 Client"
  OutFile               "ms-nfs41-client-setup-x64.exe"
  InstallDir            "$PROGRAMFILES64\NFSv4.1 Client"
  InstallDirRegKey      HKLM "Software\ms-nfs41-client" "InstallDir"
  ShowInstDetails       show
  RequestExecutionLevel admin

; Pages
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_UNPAGE_INSTFILES

; Write the uninstall keys for Windows
Section "nfs41"
  ; needed for bcdedit and installing from .inf
  ${DisableX64FSRedirection}
  SetRegView 64

  SetOutPath "$INSTDIR\"
  WriteRegStr HKLM SOFTWARE\ms-nfs41-client "InstallDir" "$INSTDIR"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client" "DisplayName" "NFSv4.1 Client Driver"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client" "Publisher" "University of Michigan"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client" "NoRepair" 1
  WriteUninstaller "uninstall.exe"
SectionEnd

Section "certificate"
  File CertMgr.exe
  File nfs41_driver.cer
  DetailPrint "Installing the driver certificate"

  ; install the test certificate to the trusted root store
  nsExec::Exec '"$INSTDIR\CertMgr.exe" /add /c "$INSTDIR\nfs41_driver.cer" /s /r localMachine root'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to install driver certificate: $R0"
  ${EndIf}

  ; enable test signing
  nsExec::Exec '$SYSDIR\bcdedit.exe /set testsigning on'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to enable test signing: $R0"
  ${EndIf}

  ; bcdedit requires a reboot
  SetRebootFlag true

  ; clean up
  Delete $INSTDIR\CertMgr.exe
  Delete $INSTDIR\nfs41_driver.cer
SectionEnd

; install the driver's .inf
Section "nfs41_driver"
  ; existing nfs41_np.dll must be removed before installing from .inf
  IfFileExists "$SYSDIR\nfs41_np.dll" 0 update_driver
    Rename $SYSDIR\nfs41_np.dll $SYSDIR\nfs41_np.dll.old
    Delete /rebootok $SYSDIR\nfs41_np.dll.old
    Goto update_driver

  update_driver:
  File nfs41rdr.inf
  File nfs41_driver.sys
  File nfs41_np.dll
  DetailPrint "Installing the NFSv4.1 Client driver"

  nsExec::Exec '$SYSDIR\rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $INSTDIR\nfs41rdr.inf'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to install nfs41rdr.inf: $R0"
  ${EndIf}

  Delete $INSTDIR\nfs41_driver.sys
  Delete $INSTDIR\nfs41_np.dll
SectionEnd

; visual studio runtime
Section "msvcrt"
  ; check whether it's already installed
  SetRegView 32
  ReadRegDWORD $R0 HKLM Software\Microsoft\VisualStudio\10.0\VC\VCRedist\x64 Installed
  SetRegView 64
  IfErrors 0 msvcrt_already_installed

  File vcredist_x64.exe
  DetailPrint "Installing the Visual Studio runtime library"

  nsExec::ExecToLog '"$INSTDIR\vcredist_x64.exe" /q /norestart'
  Pop $R0
  ${If} $R0 == 3010
    ; vcredist requires a reboot
    SetRebootFlag true
  ${ElseIf} $R0 != 0
    Abort "Failed to install the Visual Studio runtime library: $R0"
  ${EndIf}

  Delete $INSTDIR\vcredist_x64.exe
  Return

  msvcrt_already_installed:
  DetailPrint "Visual Studio runtime library is already installed"
SectionEnd

; register the network provider in ProviderOrder
Section "nfs41_np"
  File nfs_install.exe
  DetailPrint "Registering the NFSv4.1 Client as a network provider"

  nsExec::Exec '"$INSTDIR\nfs_install.exe"'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to register the network provider: $R0"
  ${EndIf}
SectionEnd

; config files required by nfsd/tirpc
Section "nfsd-config"
  DetailPrint "Installing configuration files"
  File netconfig
  File ms-nfs41-idmap.conf
  CreateDirectory C:\etc
  Rename netconfig C:\etc\netconfig
  Rename ms-nfs41-idmap.conf C:\etc\ms-nfs41-idmap.conf
SectionEnd

; add the debug nfsd and grant write access to its log files
Section "nfsd_debug"
  File nfsd_debug.exe
  File nfsddbg.log
  File nfsderr.log
  DetailPrint "Installing debug version of nfsd.exe"

  nsExec::Exec '$SYSDIR\icacls.exe nfsd*.log /grant *S-1-5-32-545:(R,W)'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to grant write access to log files: $R0"
  ${EndIf}
SectionEnd

; start nfsd service
Section "nfsd"
  ; existing service must be stopped before updating executables
  IfFileExists "$INSTDIR\nfsd.exe" 0 update_nfsd
    DetailPrint "Stopping the existing NFSv4.1 Client service"
    nsExec::ExecToLog '"$INSTDIR\nfsd.exe" -remove'
    Goto update_nfsd

  update_nfsd:
  File nfsd.exe
  File libtirpc.dll
  File nfs_mount.exe
  DetailPrint "Starting the NFSv4.1 Client service"

  nsExec::ExecToLog '"$INSTDIR\nfsd.exe" -install'
  Pop $R0
  ${If} $R0 != 0
    Abort "Failed to register the service: $R0"
  ${EndIf}

  IfRebootFlag 0 +3
  MessageBox MB_YESNO|MB_ICONQUESTION "The system needs to be restarted to complete the installation. Would you like to reboot now?" IDNO +2
    Reboot
SectionEnd

; Uninstaller
Section "Uninstall"
  ${DisableX64FSRedirection}
  SetRegView 64

  DetailPrint "Stopping the NFSv4.1 Client service"
  nsExec::ExecToLog '"$INSTDIR\nfsd.exe" -remove'

  DetailPrint "Unregistering the network provider"
  nsExec::ExecToLog '"$INSTDIR\nfs_install.exe" 0'

  DetailPrint "Uninstalling the driver"
  nsExec::ExecToLog '$SYSDIR\rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 $INSTDIR\nfs41rdr.inf'

  DetailPrint "Disabling test signing"
  nsExec::ExecToLog '$SYSDIR\bcdedit.exe /set testsigning off'

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ms-nfs41-client"
  DeleteRegKey HKLM SOFTWARE\ms-nfs41-client

  DetailPrint "Removing files"
  RMDir /r "$INSTDIR"
  RMDir /r C:\etc

  Delete /rebootok $SYSDIR\drivers\nfs41_driver.sys
  Delete /rebootok $SYSDIR\nfs41_np.dll
  Delete /rebootok $SYSDIR\nfsddbg.log
  Delete /rebootok $SYSDIR\nfsderr.log

  IfRebootFlag 0 +3
  MessageBox MB_YESNO|MB_ICONQUESTION "The system needs to be restarted to complete the cleanup. Would you like to reboot now?" IDNO +2
    Reboot
SectionEnd
