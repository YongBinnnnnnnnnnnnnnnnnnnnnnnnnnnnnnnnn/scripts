@echo off
setlocal enabledelayedexpansion


mkdir %temp%\wyem
dism /mount-wim /wimfile:boot.wim /mountdir:%temp%\wyem /index:1

::ren %temp%\wyem\WIndows\System32\drivers\acpiex.sys acpiex.sys.ybkup
::copy %temp%\wyem\WIndows\System32\drivers\beep.sys %temp%\wyem\WIndows\System32\drivers\acpiex.sys
set /p wim_source="wim source:"
copy /Y hbcd_SYSTEM %temp%\wyem\Windows\System32\config\SYSTEM
mkdir %temp%\wye
expand third_party\Drivers\Microsoft\Apple_Tether_USB_Drivers_netaapl_7503681835e08ce761c52858949731761e1fa5a1.cab -F:* %temp%\wye

copy third_party\Microsoft\WIndows\System32\* %temp%\wyem\WIndows\System32\

dism /image:%temp%\wyem /add-driver /driver:%temp%\wye\netaapl64.inf
dism /image:%temp%\wyem /add-driver /driver:third_party\Drivers\Apple\usbaapl64.inf
dism /unmount-image /mountdir:%temp%\wyem /commit