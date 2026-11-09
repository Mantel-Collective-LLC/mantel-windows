!macro customInit
  nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Stop-Service -Name 'MantelServiceDebug' -ErrorAction SilentlyContinue"`
  Pop $0
!macroend

!macro customInstall
  DetailPrint "Mantel Debug Service einrichten"
  ExecWait '"$INSTDIR\resources\service\mantel.exe" service install --root "$INSTDIR"' $0
  ${If} $0 != 0
    DetailPrint "Mantel Debug Service nicht eingerichtet (Code $0): die App bietet Dienst reparieren an."
  ${EndIf}
!macroend

!macro customUnInstall
  ${ifNot} ${isUpdated}
    DetailPrint "Mantel Debug: Kill Switch und Tunnel entfernen"
    ExecWait '"$INSTDIR\MantelDebug.exe" --disable-killswitch' $0
    nsExec::ExecToLog `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Get-NetFirewallRule -Group 'Mantel Debug Kill Switch' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"`
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule "name=Mantel Debug Kill Switch"'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /TN "Mantel Debug Autostart" /F'
    Pop $0
    IfFileExists "$PROGRAMFILES64\WireGuard\wireguard.exe" 0 +3
      nsExec::ExecToLog '"$PROGRAMFILES64\WireGuard\wireguard.exe" /uninstalltunnelservice mantel-debug'
      Pop $0
    ReadEnvStr $1 "ProgramData"
    ${If} $1 != ""
      ${If} ${FileExists} "$1\Mantel\wireguard\wireguard.exe"
        DetailPrint "Mantel Debug: Tunnel-Dienst entfernen"
        nsExec::ExecToLog '"$1\Mantel\wireguard\wireguard.exe" /uninstalltunnelservice mantel-debug'
        Pop $0
        Sleep 2000
      ${EndIf}
      Delete "$1\Mantel\mantel-debug.conf"
      ${IfNot} ${FileExists} "$PROGRAMFILES64\Mantel\Mantel.exe"
        RMDir /r "$1\Mantel\wireguard"
      ${EndIf}
    ${EndIf}
    ExecWait '"$INSTDIR\resources\service\mantel.exe" service uninstall' $0
  ${endIf}
!macroend
