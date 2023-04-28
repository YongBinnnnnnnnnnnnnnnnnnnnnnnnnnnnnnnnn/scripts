@echo off
sc config Themes start=disabled
sc config MSDTC start=disabled
sc config WpnService start=disabled
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
sc config "Bonjour Service" start=disabled
echo sc config DoSvc start=disabled
sc config DSMSvc start=disabled


sc delete wlms

sc config Audiosrv start=auto

powercfg -h off

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


reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1dexpress /f
reg delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfx /f

sc stop dosvc
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc /v Start /f /t REG_DWORD /d 4

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\igfxn /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService /v ImagePath /f /t REG_EXPAND_SZ /d /
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService /v ImagePath /f /t REG_EXPAND_SZ /d /


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


echo powershell -Command "Get-AppxPackage -AllUsers -Name *Bing*| Remove-AppxPackage"
echo powershell -Command "Get-AppxPackage -AllUsers -Name *Parental*| Remove-AppxPackage"
echo powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.CBS| Remove-AppxPackage"
echo powershell -Command "Get-AppxPackage -AllUsers -Name *WebExperience*| Remove-AppxPackage"
wmic product where name="Bonjour" call uninstall
echo icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
echo dir "C:\Program Files\WindowsApps\"

netsh advfirewall firewall delete rule name="SearchHost in"
for /F "usebackq delims=" %A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost in" dir=in program="%A\SearchHost.exe" action=block
netsh advfirewall firewall delete rule name="SearchHost out"
for /F "usebackq delims=" %A in (`powershell -Command "Get-AppxPackage -Name MicrosoftWindows.Client.CBS |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="SearchHost out" dir=out program="%A\SearchHost.exe" action=block
netsh advfirewall firewall delete rule name="Widgets in"
for /F "usebackq delims=" %A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets in" dir=in program="%A\Dashboard\Widgets.exe" action=block
netsh advfirewall firewall delete rule name="Widgets out"
for /F "usebackq delims=" %A in (`powershell -Command "Get-AppxPackage -AllUsers -Name MicrosoftWindows.Client.WebExperience |Select InstallLocation|findstr Windows"`) do netsh advfirewall firewall add rule name="Widgets out" dir=out program="%A\Dashboard\Widgets.exe" action=block



netsh advfirewall firewall show rule profile=any


echo icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F /t

echo sc config start=disabled
pause
exit
set x=%random%
net user %x% /add
net localgroup Administrators %x% /add
wmic useraccount WHERE Name=%x% set PasswordExpires=false
pause