@echo off
setlocal enabledelayedexpansion

echo 111
::powershell -c "Set-ExecutionPolicy bypass"

cd %~dp0%
echo 1
call :stop_service Samss
call :stop_service mpssvc
call :stop_service Spooler
call :stop_service Winmgmt
call :stop_service lmhosts
call :stop_service Themes
call :stop_service UserManager
call :stop_service LanmanServer
call :stop_service IKEEXT
call :stop_service EventLog
call :stop_service "Bonjour Service"

copy third_party\Microsoft\Windows\system32\* %windir%\system32

call :stop_service Dhcp

::for /f "tokens=5 delims= " %%i in ('netstat -ano^|findstr 0:135') do third_party\pssuspend64.exe %%i

netstat -ano



exit /b

:stop_service
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start>NUL
if not errorlevel 1 (
    sc config %~1 start=disabled || (
        reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start /f /t REG_DWORD /d 4 
    ) || (
        third_party\RunX\RunXcmd.exe /exec=c:\windows\System32\reg.exe /wait /account=ti /args=add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1 /v Start /f /t REG_DWORD /d 4
    )
    sc stop %~1
  )
)
exit /b
