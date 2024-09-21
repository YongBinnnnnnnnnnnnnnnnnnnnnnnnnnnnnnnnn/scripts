@echo off
setlocal enabledelayedexpansion


mkdir %temp%\wyem
dism /mount-wim /wimfile:boot.wim /mountdir:%temp%\wyem /index:1

ren %temp%\wyem\WIndows\System32\drivers\acpiex.sys acpiex.sys.ybkup
copy /Y hbcd_SYSTEM %tmp%\wyem\WIndows\System32\SYSTEM
mkdir %temp%\wye
expand third_party\Drivers\Microsoft\Apple_Tether_USB_Drivers_netaapl_7503681835e08ce761c52858949731761e1fa5a1.cab -F:* %temp%\wye
expand third_party\Drivers\Microsoft\Apple_USB_Drivers_01d96dfd-2f6f-46f7-8bc3-fd82088996d2_a31ff7000e504855b3fa124bf27b3fe5bc4d0893.cab -F:* %temp%\wye

dism /image:%tmp%\wyem /add-driver /driver:%temp%\wye\netaapl64.inf
dism /image:%tmp%\wyem /add-driver /driver:%temp%\wye\AppleUsb.inf
dism /unmount-image /mountdir:%tmp%\wyem /commit