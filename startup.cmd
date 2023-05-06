@echo off
%~dp0%\third_party\pssuspend64.exe wlms.exe || (
    powershell.exe -noprofile -c Start-Process -Verb RunAs cmd.exe \"/c %0 1\"
    exit
)
taskkill /f /im msteams.exe
echo taskkill /f /im widget.exe
pause
