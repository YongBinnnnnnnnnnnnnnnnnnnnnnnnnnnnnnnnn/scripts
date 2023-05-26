@echo off
sc config CryptSvc start=disabled
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc /v ImagePath /f /t REG_EXPAND_SZ /d /
sc stop CryptSvc
pause
