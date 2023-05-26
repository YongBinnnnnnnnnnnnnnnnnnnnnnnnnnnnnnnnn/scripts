@echo off
setlocal enabledelayedexpansion
for /f "tokens=3* delims=_" %%i in ('sc query^|findstr UserSvc_') do set SERVICE_LUID=%%i

sc config Themes start=disabled
sc config MSDTC start=disabled
sc config WpnService start=disabled
sc config WpnUserService start=disabled
sc config ShellHWDetection start=disabled
sc config RemoteRegistry start=disabled
sc config Spooler start=disabled
sc config PlugPlay start=disabled
sc config TrkWks start=disabled
sc config DiagTrack start=disabled
sc config CDPSvc start=disabled
sc config CDPUserSvc start=disabled
sc config WinRM start=disabled
sc config LanmanWorkstation start=disabled
sc config LanmanServer start=disabled
sc config lmhosts start=disabled
sc config DsSvc start=disabled
sc config lfsvc start=disabled
sc config WSearch start=disabled
sc config DPS start=disabled
sc config bthserv start=disabled
sc config BcmBtRSupport start=disabled
sc config BTAGService start=disabled
sc config BthAvctpSvc start=disabled
sc config BluetoothUserService start=disabled
sc config DeviceFlowUserSvc start=disabled
sc config DevicePickerUserSvc start=disabled
sc config DevQueryBroker start=disabled
sc config ibtsiva start=disabled
sc config NaturalAuthentication start=disabled
sc config BthAvctpSvc start=disabled
sc config bcbtums start=disabled
sc config cphs start=disabled
sc config cplspcon start=disabled
sc config CxMonSvc start=disabled
sc config CxUtilSvc start=disabled
sc config edgeupdate start=disabled
sc config edgeupdatem start=disabled
sc config igccservice start=disabled
sc config igfxCUIService2.0.0.0 start=disabled
sc config MicrosoftEdgeElevationService start=disabled
sc config XTU3SERVICE start=disabled
sc config WMIRegistrationService start=disabled
sc config WpcMonSvc start=disabled
sc config FontCache start=disabled
sc config SSDPSRV start=disabled
::sc config CmService start=disabled
sc config "Bonjour Service" start=disabled
::sc config DoSvc start=disabled
sc config DSMSvc start=disabled
sc config AarSvc start=disabled
::sc config netprofm start=disabled
sc config ALG start=disabled
sc config NetSetupSvc start=disabled

sc config wlidsvc start=disabled
sc config TokenBroker start=disabled
sc config CryptSvc start=disabled
sc config DeviceAssociationService start=disabled
sc config DispBrokerDesktopSvc start=disabled
sc config WFDSConMgrSvc start=disabled
sc config webthreatdefsvc start=disabled
sc config webthreatdefusersvc start=disabled
sc config BcastDVRUserService start=disabled
sc config PimIndexMaintenanceSvc start=disabled
sc config UserDataSvc start=disabled
sc config UnistoreSvc start=disabled
sc config uhssvc start=disabled

sc config IntelAudioService start=disabled
sc config jhi_service start=disabled

sc config Tcpip6 start=disabled
sc config tcpipreg start=disabled
sc config wanarp start=disabled
sc config wanarpv6 start=disabled
sc config RasAcd start=disabled
sc config HidIr start=disabled
sc config usbcir start=disabled
sc config circlass start=disabled
sc config iwdbus start=disabled
sc config MsLldp start=disabled
sc config MSTEE start=disabled
sc config NetBIOS start=disabled
sc config NetBT start=disabled
sc config rdpbus start=disabled
sc config RDPDR start=disabled
sc config RdpVideoMiniport start=disabled
sc config rspndr start=disabled
sc config Null start=disabled
sc config Beep start=disabled
sc config VfpExt start=disabled
sc config CSC start=disabled
sc config CldFlt start=disabled
sc config fdc start=disabled
sc config flpydisk start=disabled
sc config Ndu start=disabled
sc config afunix start=disabled
::sc config CmBatt start=disabled
sc config lltdio start=disabled
sc config luafv start=disabled
sc config UEFI start=disabled
sc config xboxgip start=disabled
sc config wdiwifi start=disabled
sc config wtd start=disabled

sc config cdrom start=demand


sc config start=disabled


sc delete wlms

sc config Audiosrv start=auto
::sc config start=disabled

powercfg -h off
powercfg /setACvalueIndex scheme_current sub_buttons LidAction 0 
powercfg /setACvalueIndex scheme_current sub_buttons PButtonAction 0
powercfg /setACvalueIndex scheme_current sub_buttons SButtonAction 0
powercfg /setDCvalueIndex scheme_current sub_buttons LidAction 0 
powercfg /setDCvalueIndex scheme_current sub_buttons PButtonAction 0
powercfg /setDCvalueIndex scheme_current sub_buttons SButtonAction 0

::pnputil /enum-drivers
::pnputil /delete-driver oem9.inf /force /uninstall
::dism /online /get-drivers /format:table

ren C:\Windows\System32\btwdi.dll btwdi.dll.bkup
ren C:\Windows\System32\BtwRSupportService.exe BtwRSupportService.exe.bkup
ren C:\Windows\System32\drivers\bcbtums.sys bcbtums.sys.bkup
ren C:\Windows\System32\drivers\bthport.sys bthport.sys.bkup
ren C:\Windows\System32\drivers\bthusb.sys bthusb.sys.bkup
ren C:\Windows\System32\drivers\btwampfl.sys btwampfl.sys.bkup
ren C:\Windows\System32\drivers\btha2dp.sys btha2dp.sys.bkup
ren C:\Windows\System32\drivers\bthenum.sys bthenum.sys.bkup
ren C:\Windows\System32\drivers\bthhfenum.sys bthhfenum.sys.bkup
ren C:\Windows\System32\drivers\bthleenum.sys bthleenum.sys.bkup
ren C:\Windows\System32\drivers\bthmini.sys bthmini.sys.bkup
ren C:\Windows\System32\drivers\bthmodem.sys bthmodem.sys.bkup
ren C:\Windows\System32\drivers\bthpan.sys bthpan.sys.bkup
ren C:\Windows\System32\drivers\igdkmd64.sys igdkmd64.sys.bkup
ren C:\Windows\System32\drivers\E1G6032E.sys E1G6032E.sys.bkup

sc stop dosvc

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v AnimationDisabled /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /f /t REG_DWORD /d 31
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v NoLockScreen /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\KeyboardFilter" /v ForceOffAccessibility /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowClipboardHistory /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockUserFromShowingAccountDetailsOnSignin /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v EnableDeviceHealthAttestationService /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /f /t REG_DWORD /d 99
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureKernelShadowStacksLaunch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureSystemGuardLaunch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HypervisorEnforcedCodeIntegrity /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /f /t REG_DWORD /d 3
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerAccountStateContent /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect" /v AllowProjectionToPC /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" /v DisableRegistration /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SettingSync" /v DisableSettingSync /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SettingSync" /v DisableSettingSyncUserOverride /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defencder" /v DisableRoutinelyTakingAction /f /t REG_DWORD /d 1

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IGMPLevel" /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /f /t REG_DWORD /d 255


reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvcc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc /v Start /f /t REG_DWORD /d 4

::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache /v Start /f /t REG_DWORD /d 4
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend /v Start /f /t REG_DWORD /d 4



reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptscureService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceFlowUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxn /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService /v ImagePath /f /t REG_EXPAND_SZ /d /
::%SystemRoot%\system32\svchost.exe -k NetworkService -p
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc /v ImagePath /f /t REG_EXPAND_SZ /d /

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcbtums /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthPan /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\btwampfl /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport /v ImagePath /f /t REG_EXPAND_SZ /d /

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO /v ImagePath /f /t REG_EXPAND_SZ /d \SystemRoot\System32\drivers\iaLPSSi_GPIO.sys
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtusb /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ICCWDT /v ImagePath /f /t REG_EXPAND_SZ /d \SystemRoot\System32\drivers\iaLPSSi_ICCWDT.sys
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intaud_WaveExtensible /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntcDAud /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iwdbus /v ImagePath /f /t REG_EXPAND_SZ /d \SystemRoot\System32\drivers\iwdbus.sys
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MEIx64 /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netwtw06 /v ImagePath /f /t REG_EXPAND_SZ /d \SystemRoot\System32\drivers\Netwtw06.sys
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XtuAcpiDriver /v ImagePath /f /t REG_EXPAND_SZ /d \SystemRoot\System32\drivers\XtuAcpiDriver.sys
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XTUComponent /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcbtums /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPMT /v ImagePath /f /t REG_EXPAND_SZ /d /

reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc /f
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1dexpress /f
::reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfx /f
::reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxn /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f

::powershell -Command "Get-AppxPackage -AllUsers -Name *Bing*| Remove-AppxPackage"
::powershell -Command "Get-AppxPackage -AllUsers -Name *Parental*| Remove-AppxPackage"
::powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.CBS| Remove-AppxPackage"
::powershell -Command "Get-AppxPackage -AllUsers -Name *WebExperience*| Remove-AppxPackage"
wmic product where name="Bonjour" call uninstall
::icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
::dir "C:\Program Files\WindowsApps\"

::netsh advfirewall firewall delete rule name="SearchHost in"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost in" dir=in program="%%A\SearchHost.exe" action=block
::for /F "usebackq delims=" %%A in (`wmic process where "name='SearchHost.exe'" get ExecutablePath^|findstr .exe`) do netsh advfirewall firewall add rule name="SearchHost in" dir=in program="%%A" action=block
::netsh advfirewall firewall delete rule name="SearchHost out"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost out" dir=out program="%%A\SearchHost.exe" action=block
::for /F "usebackq delims=" %%A in (`wmic process where "name='SearchHost.exe'" get ExecutablePath^|findstr .exe`) do netsh advfirewall firewall add rule name="SearchHost out" dir=out program="%%A" action=block

powershell -Command "Show-NetFirewallRule|Where-Object \"DisplayName\" -match \"Windows Feature Experience Pack^|Windows Security^|Mail and Calendar^|Microsoft Store^|xbox^|WWW^|Xbox Identity Provider^|Windows Camera^|Windows Calculator^|Store Experience Host^|News^|Microsoft People^|Microsoft Tips^|App Installer^|Clipchamp^|Microsoft To Do^|CmProxyD*^|Microsoft Photos\"|Set-NetFirewallRule -Action Block"

::netsh advfirewall firewall delete rule name="Widgets in"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets in" dir=in program="%%A\Dashboard\Widgets.exe" action=block
::netsh advfirewall firewall delete rule name="Widgets out"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets out" dir=out program="%%A\Dashboard\Widgets.exe" action=block
netsh advfirewall firewall delete rule name="common udp out"
netsh advfirewall firewall add rule name="common udp out" protocol=UDP dir=out localport=135,137,138,139,500,3389,4500,5353,5355 action=block
netsh advfirewall firewall delete rule name="common udp in"
netsh advfirewall firewall add rule name="common udp in" protocol=UDP dir=in localport=135,137,138,139,500,3389,4500,5353,5355 action=block
netsh advfirewall firewall delete rule name="common tcp out"
netsh advfirewall firewall add rule name="common tcp out" protocol=TCP dir=out localport=135,137,138,139,500,3389,4500,5353,5355 action=block
netsh advfirewall firewall delete rule name="common tcp in"
netsh advfirewall firewall add rule name="common tcp in" protocol=TCP dir=in localport=135,137,138,139,500,3389,4500,5353,5355 action=block

netsh advfirewall firewall show rule profile=any


::icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F /t

takeown /f %windir%\system32\utilman.exe /a
icacls %windir%\system32\utilman.exe /C /deny Everyone:RX
takeown /f %windir%\system32\sethc.exe /a
icacls %windir%\system32\sethc.exe /C /deny Everyone:RX
::ren %windir%\system32\utilman.exe utilman.exe.bak
::copy %windir%\system32\winver.exe %windir%\system32\utilman.exe
::icacls %windir%\system32\utilman.exe /C /deny Everyone:RX
::icacls %windir%\system32\utilman.exe /C /deny SYSTEM:RX
::icacls %windir%\system32\utilman.exe /C /deny Administrators:RX
::icacls %windir%\system32\utilman.exe /C /deny "ALL APPLICATION PACKAGES":RX
::icacls %windir%\system32\utilman.exe /C /deny "ALL RESTRICTED APPLICATION PACKAGES":RX
::ren %windir%\system32\utilman.exe %windir%\system32\utilman.exe.bak

pause
exit
set x=%random%
net user %x% /add
net localgroup Administrators %x% /add
wmic useraccount WHERE Name=%x% set PasswordExpires=false
pause