!macro MANTEL_FLAVOR_DEFINES
  !ifndef MANTEL_SERVICE
    !if "${PRODUCTNAME}" == "Mantel Debug"
      !define MANTEL_SERVICE "MantelServiceDebug"
      !define MANTEL_TUNNEL "mantel-debug"
      !define MANTEL_KS_GROUP "Mantel Debug Kill Switch"
      !define MANTEL_TASK "Mantel Debug Autostart"
      !define MANTEL_OTHER_EXE "$PROGRAMFILES64\Mantel\Mantel.exe"
      !define MANTEL_ELECTRON_GUID "11a43585-8369-5bce-ab90-05ee27f80282"
    !else
      !define MANTEL_SERVICE "MantelService"
      !define MANTEL_TUNNEL "mantel"
      !define MANTEL_KS_GROUP "Mantel Kill Switch"
      !define MANTEL_TASK "Mantel Autostart"
      !define MANTEL_OTHER_EXE "$PROGRAMFILES64\Mantel Debug\MantelDebug.exe"
      !define MANTEL_ELECTRON_GUID "ff1853a3-b550-5e0e-9069-d300a11094ab" ; appId "net.mantel.desktop"
    !endif
  !endif
!macroend
!define MANTEL_POWERSHELL `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command`

!macro MANTEL_STOP_SERVICE
  nsExec::ExecToLog `${MANTEL_POWERSHELL} "Stop-Service -Name '${MANTEL_SERVICE}' -ErrorAction SilentlyContinue"`
  Pop $0
!macroend

!macro MANTEL_REMOVE_ELECTRON_FILES
  Delete /REBOOTOK "$INSTDIR\Uninstall ${PRODUCTNAME}.exe"
  Delete /REBOOTOK "$INSTDIR\uninstallerIcon.ico"
  Delete /REBOOTOK "$INSTDIR\LICENSE.electron.txt"
  Delete /REBOOTOK "$INSTDIR\LICENSES.chromium.html"
  Delete /REBOOTOK "$INSTDIR\chrome_100_percent.pak"
  Delete /REBOOTOK "$INSTDIR\chrome_200_percent.pak"
  Delete /REBOOTOK "$INSTDIR\resources.pak"
  Delete /REBOOTOK "$INSTDIR\icudtl.dat"
  Delete /REBOOTOK "$INSTDIR\snapshot_blob.bin"
  Delete /REBOOTOK "$INSTDIR\v8_context_snapshot.bin"
  Delete /REBOOTOK "$INSTDIR\d3dcompiler_47.dll"
  Delete /REBOOTOK "$INSTDIR\dxcompiler.dll"
  Delete /REBOOTOK "$INSTDIR\dxil.dll"
  Delete /REBOOTOK "$INSTDIR\ffmpeg.dll"
  Delete /REBOOTOK "$INSTDIR\libEGL.dll"
  Delete /REBOOTOK "$INSTDIR\libGLESv2.dll"
  Delete /REBOOTOK "$INSTDIR\vk_swiftshader.dll"
  Delete /REBOOTOK "$INSTDIR\vk_swiftshader_icd.json"
  Delete /REBOOTOK "$INSTDIR\vulkan-1.dll"
  RMDir /r /REBOOTOK "$INSTDIR\locales"
  RMDir /r /REBOOTOK "$INSTDIR\resources"
  ${IfNot} ${FileExists} "$INSTDIR\Uninstall ${PRODUCTNAME}.exe"
    DeleteRegKey HKLM64 "Software\Microsoft\Windows\CurrentVersion\Uninstall\${MANTEL_ELECTRON_GUID}"
    DeleteRegKey HKLM64 "Software\${MANTEL_ELECTRON_GUID}"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro MANTEL_FLAVOR_DEFINES
  !insertmacro MANTEL_STOP_SERVICE
  ${If} ${FileExists} "$INSTDIR\Uninstall ${PRODUCTNAME}.exe"
    DetailPrint "${PRODUCTNAME}: Electron-Version ablösen"
    !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
    InitPluginsDir
    CopyFiles /SILENT "$INSTDIR\Uninstall ${PRODUCTNAME}.exe" "$PLUGINSDIR\electron-uninstaller.exe"
    ExecWait '"$PLUGINSDIR\electron-uninstaller.exe" /S /allusers /KEEP_APP_DATA --updated _?=$INSTDIR' $0
    DetailPrint "Electron-Deinstallation: Code $0"
    SetOutPath $INSTDIR
  ${EndIf}
  !insertmacro MANTEL_REMOVE_ELECTRON_FILES
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro MANTEL_FLAVOR_DEFINES
  DetailPrint "${PRODUCTNAME} Service einrichten"
  ExecWait '"$INSTDIR\service\mantel.exe" service install --root "$INSTDIR"' $0
  ${If} $0 != 0
    DetailPrint "${PRODUCTNAME} Service nicht eingerichtet (Code $0): die App bietet Dienst reparieren an."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro MANTEL_FLAVOR_DEFINES
  ${If} $UpdateMode = 1
  ${OrIf} $EXEDIR == $INSTDIR
    !insertmacro MANTEL_STOP_SERVICE
  ${Else}
    DetailPrint "${PRODUCTNAME}: Kill Switch und Tunnel entfernen"
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --disable-killswitch' $0
    nsExec::ExecToLog `${MANTEL_POWERSHELL} "Get-NetFirewallRule -Group '${MANTEL_KS_GROUP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"`
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule "name=${MANTEL_KS_GROUP}"'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /TN "${MANTEL_TASK}" /F'
    Pop $0
    IfFileExists "$PROGRAMFILES64\WireGuard\wireguard.exe" 0 +3
      nsExec::ExecToLog '"$PROGRAMFILES64\WireGuard\wireguard.exe" /uninstalltunnelservice ${MANTEL_TUNNEL}'
      Pop $0
    ReadEnvStr $1 "ProgramData"
    ${If} $1 != ""
      ${If} ${FileExists} "$1\Mantel\wireguard\wireguard.exe"
        nsExec::ExecToLog '"$1\Mantel\wireguard\wireguard.exe" /uninstalltunnelservice ${MANTEL_TUNNEL}'
        Pop $0
        Sleep 2000
      ${EndIf}
      Delete "$1\Mantel\${MANTEL_TUNNEL}.conf"
      ${IfNot} ${FileExists} "${MANTEL_OTHER_EXE}"
        RMDir /r "$1\Mantel\wireguard"
      ${EndIf}
    ${EndIf}
    ExecWait '"$INSTDIR\service\mantel.exe" service uninstall' $0
  ${EndIf}
!macroend
