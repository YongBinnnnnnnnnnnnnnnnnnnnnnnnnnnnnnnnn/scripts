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

copy third_party\Microsoft\Windows\System32\* %temp%\wyem\Windows\System32\

del %temp%\wyem\Windows\System32\drivers\fltsrv.sys
del %temp%\wyem\Windows\System32\drivers\snapman.sys
del %temp%\wyem\Windows\System32\drivers\volume_tracker.sys
del %temp%\wyem\Windows\System32\drivers\EUDCPEPM.sys
del %temp%\wyem\Windows\System32\drivers\EUEDKEPM.sys
del %temp%\wyem\Windows\System32\drivers\ambakdrv.sys
del %temp%\wyem\Windows\System32\drivers\amwrtdrv10.sys
del %temp%\wyem\Windows\System32\drivers\ammntdrv10.sys


dism /image:%temp%\wyem /add-driver /driver:%temp%\wye\netaapl64.inf
dism /image:%temp%\wyem /add-driver /driver:%temp%\wye\netaapl64.inf
dism /image:%temp%\wyem /add-driver /driver:third_party\Drivers\Apple\usbaapl64.inf
dism /image:%temp%\wyem /add-driver /driver:..\u0407010.inf_amd64_3cdbf86c96072d50\u0407010.inf

dism /image:%temp%\wyem /remove-driver /driver:%temp%\wyem\Windows\INF\oem269.inf

dism /unmount-image /mountdir:%temp%\wyem /commit