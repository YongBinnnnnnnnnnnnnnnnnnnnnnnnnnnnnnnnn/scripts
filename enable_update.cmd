@echo off
sc config CryptSvc start=auto
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc /v ImagePath /f /t REG_EXPAND_SZ /d "%SystemRoot%\System32\svchost.exe -k NetworkService -p"
pause
