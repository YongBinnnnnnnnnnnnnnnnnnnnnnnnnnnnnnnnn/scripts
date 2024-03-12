
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

wintypes = ctypes.wintypes


def GetForegroundWindowText():
    hwnd = windll.user32.GetForegroundWindow()
    buffer = create_unicode_buffer(256)
    windll.user32.GetWindowTextW(hwnd, buffer, 256)
    return buffer.value

def watchdog():
    def ConnectedInternet(timeout):
        import socket
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8.", 53))
            return True
        except socket.error:
            return False
    def GetDeviceList():
        return subprocess.check_output(["powershell", "-Command", '"Get-WmiObject Win32_PNPEntity|Where-Object -FilterScript {$_.Present -eq 1}|select Name,PNPDeviceID|Sort-Object PNPDeviceID"'])
    
    foreground_window_text = GetForegroundWindowText()
    device_list_string = GetDeviceList()
    try:
        while True:
            text_now = GetForegroundWindowText()
            print(foreground_window_text, text_now)
            if text_now != foreground_window_text:
                print(1)
                ring()
            if GetDeviceList() != device_list_string:
                print(2)
                ring()
            if ConnectedInternet(0.2):
                ring()
            if win32api.GetSystemPowerStatus()['ACLineStatus'] == 0:
                print(4)
                ring()
            time.sleep(0.2)
    except Exception as e:
        ring()

def safe_exit_in_duration():
    while True:
        text = GetForegroundWindowText()
        
        if text == "" or text == "UnlockingWindow":
            Thread(target=ring).start()
            time.sleep(50*60)
            windll.user32.BlockInput(False)
            windll.ntdll.RtlSetProcessIsCritical(0, 0 ,0)
            print("exit")
            windll.kernel32.ExitProcess(0)
        time.sleep(1)

def block_inputs(duration):
    begin = time.time()
    windll.user32.LockWorkStation()
    time.sleep(0.5)
    safe_exit_thread = Thread(target=safe_exit_in_duration)
    safe_exit_thread.start()
    time.sleep(0.2)
    watchdog_thread = Thread(target=watchdog)
    watchdog_thread.start()
    mouse_x = 0#930
    mouse_y = 0#660
    keyboard_state = (c_byte * 256)()
    windll.user32.SetKeyboardState.argtypes = [POINTER(c_byte)]
    while True:
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

def modify_vlc():
    def callback(hwnd, _):
        win32gui.getw
    win32gui.EnumerateWindows()

if __name__ == "__main__":
    # monitor_power()
    # exit()
    #9*60*60
    block_thread = Thread(target=block_inputs,args=(9*60*60,))
    block_thread.start()
    block_thread.join()