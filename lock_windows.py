
#python -m pip install comtypes --user

import ctypes
from ctypes import *
import time
import win32con
import win32api
import win32gui
import time
import os
import subprocess
from threading import Thread
from ctypes.wintypes import HANDLE, DWORD
from comtypes import GUID

import random
random.seed()
os.chdir(os.path.dirname(__file__))
wintypes = ctypes.wintypes

alarming = False

def ring():
    global alarming
    alarming = True
    while True:
        os.system("powershell -Command Invoke-Expression(([string]::Join([System.Environment]::NewLine, (Get-Content .\maxmize_sound_volume.ps1))))")
        os.system('powershell -c (New-Object Media.SoundPlayer "C:\\Windows\\Media\\alarm01.wav").PlaySync()')
PBT_POWERSETTINGCHANGE = 0x8013
GUID_CONSOLE_DISPLAY_STATE = '{6FE69556-704A-47A0-8F24-C28D936FDA47}'
GUID_ACDC_POWER_SOURCE = '{5D3E9A59-E9D5-4B00-A6BD-FF34FF516548}'
GUID_BATTERY_PERCENTAGE_REMAINING = '{A7AD8041-B45A-4CAE-87A3-EECBB468A9E1}'
GUID_MONITOR_POWER_ON = '{02731015-4510-4526-99E6-E5A17EBD1AEA}'
GUID_SYSTEM_AWAYMODE = '{98A7F580-01F7-48AA-9C0F-44352C29E5C0}'

class POWERBROADCAST_SETTING(Structure):
    _fields_ = [("PowerSetting", GUID),
                ("DataLength", DWORD),
                ("Data", DWORD)]

def wndproc(hwnd, msg, wparam, lparam):
    if msg == win32con.WM_POWERBROADCAST:
        if wparam == win32con.PBT_APMPOWERSTATUSCHANGE:
            print('Power status has changed')
            status = win32api.GetSystemPowerStatus()
            print(status)
        if wparam == win32con.PBT_APMRESUMEAUTOMATIC:
            print('System resume')
        if wparam == win32con.PBT_APMRESUMESUSPEND:
            print('System resume by user input')
        if wparam == win32con.PBT_APMSUSPEND:
            print('System suspend')
        if wparam == PBT_POWERSETTINGCHANGE:
            print('Power setting changed...')
            settings = cast(lparam, POINTER(POWERBROADCAST_SETTING)).contents
            power_setting = str(settings.PowerSetting)
            data_length = settings.DataLength
            data = settings.Data
            print('power_setting')
            if power_setting == GUID_CONSOLE_DISPLAY_STATE:
                if data == 0: print('Display off')
                if data == 1: print('Display on')
                if data == 2: print('Display dimmed')
            elif power_setting == GUID_ACDC_POWER_SOURCE:
                if data == 0: print('AC power')
                if data == 1: print('Battery power')
                if data == 2: print('Short term power')
                if data == 0:
                    return True
            elif power_setting == GUID_BATTERY_PERCENTAGE_REMAINING:
                print('battery remaining: %s' % data)
            elif power_setting == GUID_MONITOR_POWER_ON:
                if data == 0: print('Monitor off')
                if data == 1: print('Monitor on')
            elif power_setting == GUID_SYSTEM_AWAYMODE:
                if data == 0: print('Exiting away mode')
                if data == 1: print('Entering away mode')
            else:
                print('unknown GUID')
        return True
    return False
    return win32gui.DefWindowProc(hwnd, msg, lparam, wparam)



def monitor_power():
    win32gui.InitCommonControls()
    hinst = win32api.GetModuleHandle(None)
    try:
        hwnd = win32gui.CreateWindowEx(win32con.WS_EX_TOPMOST,
                                     "Button", 
                                     "",
                                     win32con.WS_DISABLED|win32con.WS_DLGFRAME, 
                                     0, 
                                     0, 
                                     0, 
                                     0, 
                                     0, 
                                     0, 
                                     hinst, 
                                     None)
        win32gui.SetWindowLong(hwnd, win32con.GWL_WNDPROC, wndproc)
        #win32gui.UpdateWindow(hwnd)
        #win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
    except Exception as e:
        print("Exception: %s" % str(e))

    if hwnd is None:
        print("hwnd is none!")
    else:
        print("hwnd: %s" % hwnd)

    while True:
        win32gui.PumpWaitingMessages()
        #time.sleep(1)

INPUT_MOUSE    = 0
INPUT_KEYBOARD = 1
INPUT_HARDWARE = 2

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP       = 0x0002
KEYEVENTF_UNICODE     = 0x0004
KEYEVENTF_SCANCODE    = 0x0008

MAPVK_VK_TO_VSC = 0

# msdn.microsoft.com/en-us/library/dd375731
VK_TAB  = 0x09
VK_SHIFT  = 0x10
VK_CONTROL  = 0x11
VK_MENU = 0x12

# C struct definitions

wintypes.ULONG_PTR = wintypes.WPARAM

class MOUSEINPUT(ctypes.Structure):
    _fields_ = (("dx",          wintypes.LONG),
                ("dy",          wintypes.LONG),
                ("mouseData",   wintypes.DWORD),
                ("dwFlags",     wintypes.DWORD),
                ("time",        wintypes.DWORD),
                ("dwExtraInfo", wintypes.ULONG_PTR))

class KEYBDINPUT(ctypes.Structure):
    _fields_ = (("wVk",         wintypes.WORD),
                ("wScan",       wintypes.WORD),
                ("dwFlags",     wintypes.DWORD),
                ("time",        wintypes.DWORD),
                ("dwExtraInfo", wintypes.ULONG_PTR))

    def __init__(self, *args, **kwds):
        super(KEYBDINPUT, self).__init__(*args, **kwds)
        # some programs use the scan code even if KEYEVENTF_SCANCODE
        # isn't set in dwFflags, so attempt to map the correct code.
        if not self.dwFlags & KEYEVENTF_UNICODE:
            self.wScan = windll.user32.MapVirtualKeyExW(self.wVk,
                                                 MAPVK_VK_TO_VSC, 0)

class HARDWAREINPUT(ctypes.Structure):
    _fields_ = (("uMsg",    wintypes.DWORD),
                ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD))

class INPUT(ctypes.Structure):
    class _INPUT(ctypes.Union):
        _fields_ = (("ki", KEYBDINPUT),
                    ("mi", MOUSEINPUT),
                    ("hi", HARDWAREINPUT))
    _anonymous_ = ("_input",)
    _fields_ = (("type",   wintypes.DWORD),
                ("_input", _INPUT))

LPINPUT = ctypes.POINTER(INPUT)

def _check_count(result, func, args):
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return args

#windll.user32.SendInput.errcheck = _check_count
windll.user32.SendInput.argtypes = (wintypes.UINT, # nInputs
                             LPINPUT,       # pInputs
                             ctypes.c_int)  # cbSize

# Functions

def PressKey(hexKeyCode):
    x = INPUT(type=INPUT_KEYBOARD,
              ki=KEYBDINPUT(wVk=hexKeyCode))
    windll.user32.SendInput(1, ctypes.byref(x), ctypes.sizeof(x))

def ReleaseKey(hexKeyCode):
    x = INPUT(type=INPUT_KEYBOARD,
              ki=KEYBDINPUT(wVk=hexKeyCode,
                            dwFlags=KEYEVENTF_KEYUP))
    windll.user32.SendInput(1, ctypes.byref(x), ctypes.sizeof(x))

def GetForegroundWindowText():
    hwnd = windll.user32.GetForegroundWindow()
    buffer = create_unicode_buffer(256)
    windll.user32.GetWindowTextW(hwnd, buffer, 256)
    return buffer.value

def watchdog():
    def ConnectedInternet(timeout):
        import socket
        try:
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.settimeout(timeout)
            so.connect(("8.8.8.8.", 53))
            return True
        except socket.error:
            return False
    def GetDeviceList():
        return subprocess.check_output(["powershell", "-Command", '"Get-WmiObject Win32_PNPEntity|Where-Object -FilterScript {$_.Present -eq 1}|select Name,PNPDeviceID|Sort-Object PNPDeviceID"'], timeout=15)
    
    def check_window():
        foreground_window_text = GetForegroundWindowText()
        while True:
            text_now = GetForegroundWindowText()
            print(foreground_window_text, text_now)
            if text_now != foreground_window_text:
                print(1)
                ring()
            time.sleep(0.2)
            
    Thread(target=check_window).start()

    def check_device():
        device_list_string = GetDeviceList()
        while True:
            if GetDeviceList() != device_list_string:
                print(2)
                ring()
            time.sleep(0.2)

    Thread(target=check_device).start()
    
    def check3():
        if ConnectedInternet(0.1):
            print(3)
            ring()
    def check2():
        if win32api.GetSystemPowerStatus()['ACLineStatus'] == 0:
                print(4)
                ring()
    try:
       while True:
            check_list = [
                Thread(target=check2),
                Thread(target=check3),
            ]
            for thread in check_list:
                thread.start()
            
            for thread in check_list:
                thread.join(timeout=1)
            
            time.sleep(0.2)
    except Exception as e:
        print('e')
        ring()

def safe_exit_in_duration():
    global alarming
    while True:
        text = GetForegroundWindowText()
        #print(text)
        #if text == "UnlockingWindow":
        if win32api.GetKeyState(win32con.VK_CAPITAL):
            print("Triggered exit in duration", text)
            Thread(target=ring).start()
            time.sleep(40*60)
            windll.user32.BlockInput(False)
            windll.ntdll.RtlSetProcessIsCritical(0, 0 ,0)
            print("exit")
            windll.kernel32.ExitProcess(0)
        time.sleep(1)

def block_inputs(duration):
    begin = time.time()
    windll.user32.LockWorkStation()
    mouse_x = 0#930
    mouse_y = 0#660
    keyboard_state = (c_byte * 256)()
    windll.user32.SetKeyboardState.argtypes = [POINTER(c_byte)]
    windll.user32.LockWorkStation()
    time.sleep(9)
    
    safe_exit_thread = Thread(target=safe_exit_in_duration)
    safe_exit_thread.start()
    for _ in range(random.randint(2,5)):
        watchdog_thread = Thread(target=watchdog)
        watchdog_thread.start()
    while True:
        #time.sleep(1)
        #continue
        windll.ntdll.RtlSetProcessIsCritical(1, 0 ,0)
        windll.user32.LockWorkStation()
        windll.user32.BlockInput(True)
        windll.user32.SetCursorPos(mouse_x,mouse_y)
        win32api.ClipCursor((mouse_x,mouse_y,mouse_x+1,mouse_y+1))
        ReleaseKey(VK_CONTROL)
        ReleaseKey(VK_SHIFT)
        ReleaseKey(VK_TAB)
        ReleaseKey(VK_MENU)
        windll.user32.SetKeyboardState(keyboard_state)
        elapsed = time.time() - begin
        if elapsed > duration:
            break
        time.sleep(0.05)
    
    windll.user32.BlockInput(False)
    windll.ntdll.RtlSetProcessIsCritical(0, 0 ,0)
    print("Finished, ring to notify")
    ring()
    global alarming
    if not alarming:
        windll.kernel32.ExitProcess(0)


def modify_vlc():
    def callback(hwnd, _):
        win32gui.getw
    win32gui.EnumerateWGindows()

if __name__ == "__main__":
    # monitor_power()
    # exit()
    #9*60*60
    import sys
    hours = 8
    if len(sys.argv) >= 2:
        hours = float(sys.argv[1])
    print(hours, "hours")

    #if len(sys.argv) >= 3:
        #os.system(os.path.dirname(__file__) + "\\startup.cmd")

    block_thread = Thread(target=block_inputs,args=(hours*60*60,))
    block_thread.start()
    block_thread.join()