@echo off
::%~dp0%\third_party\pssuspend64.exe wlms.exe || (
fltmc || (
    powershell.exe -noprofile -c Start-Process -Verb RunAs cmd.exe \"/k %0 1\"
    exit
)
taskkill /f /im msteams.exe
taskkill /f /im msedge.exe
::taskkill /f /im widget.exe
cd %~dp0%