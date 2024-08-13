@echo off
setlocal enabledelayedexpansion

for /f "tokens=2 delims=\" %%i in ('whoami') do set currentUser=%%i

if "%currentUser%"=="defaultuser0" (
  net user defaultuser 123456 /add
  net localgroup Administrators defaultuser /add
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" /v ImageState /t REG_SZ /d "ImageState" /f >nul
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" /v SetupType /t REG_DWORD /d 0 /f >nul
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup" /v OOBEInProgress /t REG_DWORD /d 0 /f >nul
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup" /v SetupType /t REG_DWORD /d 0 /f >nul
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup" /v CmdLine /t REG_SZ /d "" /f >nul
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v DefaultAccountAction /t REG_DWORD /d 0 /f >nul
  net user defaultuser0 /delete
)

powershell -c "Set-ExecutionPolicy bypass"
cd %~dp0%
third_party\pssuspend64.exe wlms.exe
wmic product where name="Bonjour" call uninstall
wmic product where name="Apple Software Update" call uninstall
:: notworking
wmic product where name=null call uninstall
ren C:\Windows\System32\opencl.dll opencl.dll.ybkup
ren C:\Windows\SysWOW64\opencl.dll opencl.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c "ren C:\Windows\System32\opencl.dll opencl.dll.ybkup||ren C:\Windows\System32\opencl.dll opencl.dll.ybkup2"
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c "ren C:\Windows\SysWOW64\opencl.dll opencl.dll.ybkup||ren C:\Windows\SysWOW64\opencl.dll opencl.dll.ybkup2"
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c "ren C:\Windows\System32\opengl32.dll opengl32.dll.ybkup||ren C:\Windows\System32\opengl32.dll opengl32.dll.ybkup2"
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c "ren C:\Windows\SysWOW64\opengl32.dll opengl32.dll.ybkup||ren C:\Windows\SysWOW64\opengl32.dll opengl32.dll.ybkup2"

sc config IntelAudioService start=disabled
sc config cplspcon start=disabled
sc config igccservice start=disabled
sc config igfxCUIService2.0.0.0 start=disabled
sc config jhi_service start=disabled
sc config TbtP2pShortcutService start=disabled


pnputil /disable-device /deviceid "PCI\VEN_8086&DEV_9A1B"
pnputil /disable-device /deviceid "PCI\VEN_8086&DEV_9A1D"
::pnputil /disable-device "ACPI\USBC000\0"
pause

powershell -Command "Get-CimInstance Win32_SystemDriver|Where-Object \"DisplayName\" -match \"Nahimic\"|Invoke-CimMethod -MethodName Delete"
sc config NahimicService start=disabled
sc config GCUBridge start=disabled


bcdedit /set {current} bootstatuspolicy displayallfailures
bcdedit /set {current} quietboot no
::bcdedit /set {current} graphicsmodedisabled yes
bcdedit /set {current} sos yes
bcdedit /set {current} bootlog yes
bcdedit /set {current} nx alwayson

powershell -noprofile -Command "'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA'|Disable-TlsCipherSuite"
certutil -delstore Root 4decdf2606dc2410c0b699f4d739c76f19f82628
certutil -addstore root "third_party\Certificates\DigiCert Assured ID Root CA.cer"
certutil -addstore root "third_party\Certificates\VeriSign Class 3 Public Primary Certification Authority - G5.cer"

netsh dns add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=8.8.8.8 dohtemplate=https://dns.google/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=8.8.4.4 dohtemplate=https://dns.google/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=9.9.9.9 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
netsh dns add encryption server=149.112.112.112 dohtemplate=https://dns.quad9.net/dns-query autoupgrade=yes udpfallback=no
netsh int ip set dns Ethernet static 1.1.1.1 validate=no
netsh int ipv6 set state disabled
netsh int ipv6 6to4 set state disabled
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled

pnputil -i -a third_party\Drivers\Apple\netaapl64.inf
pnputil -i -a third_party\Drivers\Apple\usbaapl64.inf
pnputil -i -a third_party\Drivers\Intel\Thunderbolt\TbtHostController.inf

::dtsapo4acerextensionpkg.inf

::dism /online /get-features /format:table|findstr Enabled
start dism /online /enable-feature /featurename:"Containers-DisposableClientVM" -All -NoRestart
start powershell -noprofile -Command "Get-WindowsCapability -Online -Name *Wallpaper*|Remove-WindowsCapability -Online"
powershell -noprofile -Command "Get-WindowsCapability -Online -Name OneCore*|Remove-WindowsCapability -Online"

for /f "tokens=3* delims=_" %%i in ('sc query state^=all^|findstr UserSvc_') do set SERVICE_LUID=%%i
for /f "tokens=3 delims=_ " %%i in ('sc query state^=all^|findstr SERVICE_NAME^|findstr %SERVICE_LUID%') do (
    echo %%i
    call :disable_service %%i
    call :disable_service %%i_%SERVICE_LUID%
)

for /f "tokens=3 delims=_ " %%i in ('sc query state^=all^|findstr SERVICE_NAME^|findstr /I xbox') do (
    echo %%i
    call :disable_service %%i
)
for /f "tokens=3 delims=_ " %%i in ('sc query state^=all^|findstr SERVICE_NAME^|findstr /I " xbl"') do (
    echo %%i
    call :disable_service %%i
)
call :disable_service DmEnrollmentSvc
call :disable_service dmwappushservice

sc config Themes start=disabled
sc config MSDTC start=disabled
sc config WpnService start=disabled
sc config ShellHWDetection start=disabled
sc config WPDBusEnum start=disabled
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
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config DevicePickerUserSvc start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config DevQueryBroker start=disabled
sc config ibtsiva start=disabled
sc config NaturalAuthentication start=disabled
sc config BthAvctpSvc start=disabled
sc config bcbtums start=disabled
sc config cphs start=disabled
sc config CxMonSvc start=disabled
sc config CxUtilSvc start=disabled
sc config edgeupdate start=disabled
sc config edgeupdatem start=disabled
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
sc config netprofm start=disabled
sc config ALG start=disabled
::sc config NetSetupSvc start=disabled
sc config PcaSvc start=disabled
::sc config camsvc start=disabled
sc config MapsBroker start=disabled
sc config InstallService start=disabled
sc config UsoSvc start=disabled
sc config wuauserv start=disabled
sc config DusmSvc start=disabled
sc config LicenseManager start=disabled
::sc config NcbService start=disabled
sc config PushToInstall start=disabled
call :disable_service GraphicsPerfSvc
call :disable_service wisvc
call :disable_service FDResPub
call :disable_service NcdAutoSetup
call :disable_service spectrum
call :disable_service KtmRm
call :disable_service PeerDistSvc
call :disable_service TermService
call :disable_service smphost
call :disable_service Wecsvc
call :disable_service WMPNetworkSvc
call :disable_service WerSvc
::call :disable_service RpcSs

sc config wlidsvc start=disabled
sc config TokenBroker start=disabled
::sc config CryptSvc start=disabled
sc config DeviceAssociationService start=disabled
sc config DispBrokerDesktopSvc start=disabled
sc config WFDSConMgrSvc start=disabled
sc config webthreatdefsvc start=disabled
sc config webthreatdefusersvc start=disabled
sc config BcastDVRUserService start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config PimIndexMaintenanceSvc start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config UserDataSvc start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config UnistoreSvc start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_%SERVICE_LUID% /v Start /f /t REG_DWORD /d 4
sc config uhssvc start=disabled

sc config iphlpsvc start=demand

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
::sc config Null start=demand
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
sc config WifiCx start=disabled
sc config vwififlt start=disabled
sc config vwifimp start=disabled
sc config NativeWifiP start=disabled
::sc config IntcDMic start=disabled
sc config QWAVEdrv start=disabled
sc config xinputhid start=disabled
sc config kdnic start=disabled
sc config mssmbios start=disabled
::sc config MSPCLOCK start=disabled
::sc config MSPQM start=disabled
::sc config acpi start=disabled
sc config acpipagr start=disabled
sc config acpitime start=disabled
call :disable_service wmiacpi
call :disable_service UcmUcsiAcpiClient

sc config intelpmt start=disabled
sc config intelpep start=disabled

sc config cdrom start=demand
sc config usbser start=demand
sc config cdrom start=demand

third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\sc.exe /wait /account=ti /args=config wlms start=disabled
n third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\taskkill.exe /wait /account=ti /args=/f /im msmpeng.exe
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\sc.exe /wait /account=ti /args=config SecurityHealthService start=disabled

sc config Audiosrv start=auto
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\sc.exe /wait /account=ti /args=config WinDefend start=disabled
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\reg.exe /wait /account=ti /args=add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend /v ImagePath /f /t REG_EXPAND_SZ /d ""
reg copy HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend_ybkup
call :disable_service WinDefend_ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\sc.exe /wait /account=ti /args=delete WinDefend

::sc config start=disabled
powershell -Command "Get-ScheduledTask|Where-Object \"TaskName\" -match \"OneDrive*^|microsoftedge*\"|Disable-ScheduledTask"
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /wait /account=ti /args=-Command "Get-ScheduledTask|Where-Object \"TaskPath\" -match \"\\Microsoft.*(AppList^|ApplicationData^|Certificate^|Cloud^|Device Information^|DeviceDirect^|Diag^|DiskClean^|DUSM^|\\EDP\\^|Experience^|Feedback^|Flighting^|Footprint^|InstallService^|License^|\\Location\\^|NetTrace^|ongbin^|Provision^|Push^|Remote^|Sync^|SoftwareProtection^|SpacePort^|StateRepository^|Update^|WaaSMedic^|Work Folder^|XblGame^|Config^|Policy)\"|Disable-ScheduledTask"
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /wait /account=ti /args=-Command "Get-ScheduledTask|Where-Object \"TaskName\" -match \"Defender^|ShellAppRuntime^|SystemSound^|CacheTask^|BfeOnServ^|Family^|Discovery^|Intelligent^|Proxy^|Theme^|Report^|VerifiedPublisherCertStoreCheck^|WiFi^|WIM-Hash^|Yong^|NGEN^|Regist^|Sync^|Update^|Notif\"|Disable-ScheduledTask"
::del %windir%\System32\Tasks\Microsoft\Windows\PushToInstall\Registration
::del %windir%\System32\Tasks\Microsoft\Windows\Security\Pwdless\IntelligentPwdlessTask
::del %windir%\System32\Tasks\Microsoft\Windows\Shell\*Family*
::del %windir%\System32\Tasks\Microsoft\Windows\WaaSMedic\PerformRemediation


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

third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\CIRCoInst.dll CIRCoInst.dll.ybkup

third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\cbdhsvc.dll cbdhsvc.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\cdpsvc.dll cdpsvc.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\cdpusersvc.dll cdpusersvc.dll.ybkup
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\cryptsvc.dll cryptsvc.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\diagtrack.dll diagtrack.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\dusmsvc.dll dusmsvcc.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\windowsudkservices.shellcommon.dll windowsudkservices.shellcommon.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\wlidsvc.dll wlidsvc.dll.ybkup
third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\InstallService.dll InstallService.dll.ybkup

ren C:\Windows\System32\diagtrack.dll diagtrack.dll.ybkup

::ren C:\Windows\System32\btwdi.dll btwdi.dll.ybkup
::ren C:\Windows\System32\BtwRSupportService.exe BtwRSupportService.exe.ybkup
::ren C:\Windows\System32\drivers\bcbtums.sys bcbtums.sys.ybkup
::ren C:\Windows\System32\drivers\bthport.sys bthport.sys.ybkup
::ren C:\Windows\System32\drivers\bthusb.sys bthusb.sys.ybkup
::ren C:\Windows\System32\drivers\btwampfl.sys btwampfl.sys.ybkup
::ren C:\Windows\System32\drivers\btha2dp.sys btha2dp.sys.ybkup
::ren C:\Windows\System32\drivers\bthenum.sys bthenum.sys.ybkup
::ren C:\Windows\System32\drivers\bthhfenum.sys bthhfenum.sys.ybkup
::ren C:\Windows\System32\drivers\bthleenum.sys bthleenum.sys.ybkup
::ren C:\Windows\System32\drivers\bthmini.sys bthmini.sys.ybkup
::ren C:\Windows\System32\drivers\bthmodem.sys bthmodem.sys.ybkup
::ren C:\Windows\System32\drivers\bthpan.sys bthpan.sys.ybkup
::ren C:\Windows\System32\drivers\igdkmd64.sys igdkmd64.sys.ybkup
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren C:\Windows\System32\uxtheme.dll uxtheme.dll.ybkup
powershell -Command "Get-CimInstance Win32_SystemDriver -Filter \"name='E1G60'\"|Invoke-CimMethod -MethodName Delete"
powershell -Command "Get-CimInstance Win32_SystemDriver|Where-Object \"DisplayName\" -match \"Bluetooth^|Nahimic\"|Invoke-CimMethod -MethodName Delete"

sc stop dosvc

third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\reg.exe /wait /account=ti /args=add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /f /t REG_DWORD /d 1
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\reg.exe /wait /account=ti /args=add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiVirus /f /t REG_DWORD /d 1
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\reg.exe /wait /account=ti /args=add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" /v DisableAntiVirus /f /t REG_DWORD /d 1

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Filter /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideDrivesWithNoMedia /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideMergeConflicts /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /f /t REG_DWORD /d 1

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v AnimationDisabled /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /f /t REG_DWORD /d 31
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v NoLockScreen /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Embedded\KeyboardFilter" /v ForceOffAccessibility /f /t REG_DWORD /d 1

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerAccountStateContent /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect" /v AllowProjectionToPC /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" /v DisableRegistration /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /f /t REG_DWORD /d 99
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureKernelShadowStacksLaunch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureSystemGuardLaunch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HypervisorEnforcedCodeIntegrity /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DWM" /v DisallowAnimations /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowClipboardHistory /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockUserFromShowingAccountDetailsOnSignin /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AllowMUUpdateService" /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiVirus /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v PUAProtection /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v UILockDown /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v DisableOSUpgrade /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v EnableDeviceHealthAttestationService /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /f /t REG_DWORD /d 1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SettingSync" /v DisableSettingSync /f /t REG_DWORD /d 2
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SettingSync" /v DisableSettingSyncUserOverride /f /t REG_DWORD /d 1

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IGMPLevel" /f /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /f /t REG_DWORD /d 255


reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc /v Start /f /t REG_DWORD /d 4
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository /v Start /f /t REG_DWORD /d 4


::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure /v Start /f /t REG_DWORD /d 4


::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache /v Start /f /t REG_DWORD /d 4
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend /v Start /f /t REG_DWORD /d 4



reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptscureService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxn /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService /v ImagePath /f /t REG_EXPAND_SZ /d /
::%SystemRoot%\system32\svchost.exe -k NetworkService -p
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc /v ImagePath /f /t REG_EXPAND_SZ /d /

::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcbtums /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthPan /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\btwampfl /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM /v ImagePath /f /t REG_EXPAND_SZ /d /
::reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport /v ImagePath /f /t REG_EXPAND_SZ /d /

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

::reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc /f
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1dexpress /f
::reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfx /f
::reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxn /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f

::Even ti cannot write to this ass, will disable execution permission of this shit
::third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=add HKEY_LOCAL_MACHINE\SYSTEM\WaaS\Upfc /v NextHealthCheckTime /f /t REG_SZ /d "9999-01-01T00:00:00Z"

::Completely disabled UWP of Windows 11, explorer has to run in this way
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /f /t REG_SZ /d "explorer.exe \"shell:::{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\" -Embedding"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ShellAppRuntime /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ShellInfrastructure /f /t REG_SZ /d ""
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SiHostRestartCountLimit /f /t REG_DWORD /d 1
reg copy "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers_ybkup" /s /f
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /f /t REG_SZ /d "PasswordProvider"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{F8A1793B-7873-4046-B2A7-1F318747F427}" /f /t REG_SZ /d "FIDO Credential Provider"

::OLE DocFile Property Page
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\PropertySheetHandlers\{3EA48300-8CF6-101B-84FB-666CCB9BCD32}" /F
::Security Shell Extension
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\PropertySheetHandlers\{1f2e5c40-9550-11ce-99d2-00aa006e086c}" /F
::CryptoSignMenu
:: required for reading exe signatures {7444C719-39BF-11D1-8CD9-00C04FC29D45}
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\PropertySheetHandlers\CryptoSignMenu" /F
::FCI Properties
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\PropertySheetHandlers\FCI Properties" /F

::ModernSharing
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing" /f
::Client Side Caching UI
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{474C98EE-CF3D-41f5-80E3-4AAB0AB04301}" /f


::Cloud Cache Invalidator SSO
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{578480AA-1B1C-4343-AABD-62C0A273DCB5}" /f
::Bluetooth Authentication Agent SSO
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{F08C5AC2-E722-4116-ADB7-CE41B527994B}" /f
::HomeGroup SSO
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{ff363bfe-4941-4179-a81c-f3f1ca72d820}" /f
::OneDrive network states cache SSO
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{78DE489B-7931-4f14-83B4-C56D38AC9FFA}" /f
::Windows System Reset SSO
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{003e0278-eca8-4bb8-a256-3689ca1c2600}" /f
::Client Side Caching UI
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{C51F0A6B-2A63-4cf4-8938-24404EAEF422}" /f
::WebCheck
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{EF4D1E1A-1C87-4AA8-8934-E68E4367468D}" /f
::Sync Center Shell Service Object (Internal)
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{F20487CC-FC04-4B1E-863F-D9801796130B}" /f
::Security and Maintenance Shell Service Object	Security and Maintenance
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}" /f
::WPDShServiceObj Class
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}" /f

::Need to be TrustedInstaller
::Powershell permission failed 
:: $acl=Get-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{566296fe-e0e8-475f-ba9c-a31ad31620b1}"
:: $rule = New-Object System.Security.AccessControl.RegistryAccessRule(".\Administrators", "Delete", "None", "None", "Allow")
:: $acl.SetAccessRule($rule)
:: $acl|Set-Acl "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{566296fe-e0e8-475f-ba9c-a31ad31620b1}"

::Device Stage Shell Extension
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{566296fe-e0e8-475f-ba9c-a31ad31620b1}" /f
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{566296fe-e0e8-475f-ba9c-a31ad31620b1}" /f
::Windows To Go Shell Service Object
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{4DC9C264-730E-4CF6-8374-70F079E4F82B}" /f
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{4DC9C264-730E-4CF6-8374-70F079E4F82B}" /f
::Windows System Reset SSO
::reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{872f8dc8-dde4-43bd-ac7a-e3d9fe86ceac}" /f
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{872f8dc8-dde4-43bd-ac7a-e3d9fe86ceac}" /f


reg delete "HKEY_CURRENT_USER\Software\Classes\*\shellex\ContextMenuHandlers\ FileSyncEx" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Directory\shellex\ContextMenuHandlers\ FileSyncEx" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Directory\Background\shellex\ContextMenuHandlers\ FileSyncEx" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\ *" /f


::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name *Bing*| Remove-AppxPackage -AllUsers"
::powershell -Command "Get-AppxPackage -AllUsers -Name *Parental*| Remove-AppxPackage"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.CBS| Remove-AppxPackage"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.WindowsNotepad| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.WindowsTerminal| Remove-AppxPackage -AllUsers"
::powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name *Xbox*| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.Xbox.TCUI| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.XboxGameOverlay| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.XboxGamingOverlay| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.XboxIdentityProvider| Remove-AppxPackage -AllUsers"
powershell -noprofile -Command "Get-AppxPackage -AllUsers -Name Microsoft.XboxSpeechToTextOverlay| Remove-AppxPackage -AllUsers"


::for /F "usebackq delims=" %%A in (`dir %userprofile%\AppData\Local\Microsoft\OneDrive\OneDriveSetup.exe /s /b`) do %%A /uninstall
OneDriveSetup.exe /uninstall

::icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
::dir "C:\Program Files\WindowsApps\"

::netsh advfirewall firewall delete rule name="SearchHost in"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost in" dir=in program="%%A\SearchHost.exe" action=block
::for /F "usebackq delims=" %%A in (`wmic process where "name='SearchHost.exe'" get ExecutablePath^|findstr .exe`) do netsh advfirewall firewall add rule name="SearchHost in" dir=in program="%%A" action=block
::netsh advfirewall firewall delete rule name="SearchHost out"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost out" dir=out program="%%A\SearchHost.exe" action=block
::for /F "usebackq delims=" %%A in (`wmic process where "name='SearchHost.exe'" get ExecutablePath^|findstr .exe`) do netsh advfirewall firewall add rule name="SearchHost out" dir=out program="%%A" action=block

powershell -Command "Show-NetFirewallRule|Where-Object \"DisplayName\" -match \"WFD^|Windows Feature Experience Pack^|Windows Security^|Zune.*^|Mail and Calendar^|Microsoft Store^|xbox^|WWW^|Xbox Identity Provider^|Windows Camera^|Windows Calculator^|Sharing^|Experience^|News^|Microsoft People^|Microsoft Tips^|App Installer^|Clipchamp^|Microsoft To Do^|CmProxyD^|Microsoft Photos^|Wireless^|Cast^|Discovery^|Connected^|Wi-Fi^|Remote^|Identity^|Management^|Cortana^|Collabor^|mDNS^|UwpApp^|Core Networking\"|Set-NetFirewallRule -Action Block"
powershell -Command "Show-NetFirewallRule|Where-Object \"DisplayName\" -match \"Core Networking.*(DHCP^|DNS)\"|Set-NetFirewallRule -Action Allow"


::netsh advfirewall firewall delete rule name="Widgets in"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets in" dir=in program="%%A\Dashboard\Widgets.exe" action=block
::netsh advfirewall firewall delete rule name="Widgets out"
::for /F "usebackq delims=" %%A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets out" dir=out program="%%A\Dashboard\Widgets.exe" action=block
netsh advfirewall firewall delete rule name="common udp out"
netsh advfirewall firewall add rule name="common udp out" protocol=UDP dir=out localport=135,137,138,139,500,3389,4500,5353,5355 action=block
netsh advfirewall firewall delete rule name="common udp in"
netsh advfirewall firewall add rule name="common udp in" protocol=UDP dir=in localport=135,137,138,139,500,3389,4500,5353,5355 action=block
netsh advfirewall firewall delete rule name="common tcp out"
netsh advfirewall firewall add rule name="common tcp out" protocol=TCP dir=out localport=135,137,138,139,500,3389,4500,5353,5354,5355,49664,49665,49666,49667,49668 action=block
netsh advfirewall firewall delete rule name="common tcp in"
netsh advfirewall firewall add rule name="common tcp in" protocol=TCP dir=in localport=135,137,138,139,500,3389,4500,5353,5354,5355,49664,49665,49666,49667,49668 action=block

netsh advfirewall firewall show rule profile=any


::icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F /t

takeown /f %windir%\system32\utilman.exe /a
icacls %windir%\system32\utilman.exe /C /deny Everyone:RX
takeown /f %windir%\system32\sethc.exe /a
icacls %windir%\system32\sethc.exe /C /deny Everyone:RX
takeown /f %windir%\system32\upfc.exe /a
icacls %windir%\system32\upfc.exe /C /deny Everyone:RX
::third_party\RunX\RunXcmd.exe /exec=C:\Windows\System32\cmd.exe /wait /account=ti /args=/c ren "%ProgramFiles%\Windows Defender\MsMpEng.exe" MsMpEng.exe.ybkup

::ren %windir%\system32\utilman.exe utilman.exe.bak
::copy %windir%\system32\winver.exe %windir%\system32\utilman.exe
::icacls %windir%\system32\utilman.exe /C /deny Everyone:RX
::icacls %windir%\system32\utilman.exe /C /deny SYSTEM:RX
::icacls %windir%\system32\utilman.exe /C /deny Administrators:RX
::icacls %windir%\system32\utilman.exe /C /deny "ALL APPLICATION PACKAGES":RXp
::icacls %windir%\system32\utilman.exe /C /deny "ALL RESTRICTED APPLICATION PACKAGES":RX
::ren %windir%\system32\utilman.exe %windir%\system32\utilman.exe.bak

::set x=%random%
::net user %x% /add
::net localgroup Administrators %x% /add
::wmic useraccount WHERE Name=%x% set PasswordExpires=false
gpupdate /force
reg copy "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions_ybkup" /s /f
third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" /f


systempropertiesperformance
gpedit.msc
pause   
exit /b
exit /b

:disable_service
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start>NUL
if not errorlevel 1 (
    sc config %~1 start=disabled || (
        reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start /f /t REG_DWORD /d 4 
    ) || (
        third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start /f /t REG_DWORD /d 4
    )
  )
)
exit /b
