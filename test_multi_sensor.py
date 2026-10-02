import time
import psutil
import pythoncom
import win32com.client
import win32file
import win32api
import ctypes

def get_current_state():
    pythoncom.CoInitialize()
    wmi = win32com.client.GetObject("winmgmts:")
    
    # 1. Active Audio Endpoints
    audio_endpoints = {}
    for a in wmi.ExecQuery("SELECT Name, DeviceID, Status FROM Win32_PnPEntity WHERE PNPClass = 'AudioEndpoint'"):
        name = str(a.Name or "").strip()
        did = str(a.DeviceID or "").strip()
        if name and did:
            audio_endpoints[did] = name

    # 2. USB Drives & Partitions
    drives = {}
    for p in psutil.disk_partitions(all=True):
        if p.mountpoint:
            drives[p.mountpoint] = p.fstype

    # 3. USB Disk Drives
    usb_disks = {}
    for d in wmi.ExecQuery("SELECT Model, DeviceID, InterfaceType FROM Win32_DiskDrive WHERE InterfaceType = 'USB'"):
        usb_disks[str(d.DeviceID)] = str(d.Model)

    # 4. Power
    batt = psutil.sensors_battery()
    power = batt.power_plugged if batt else True

    return {
        "audio": audio_endpoints,
        "drives": drives,
        "usb_disks": usb_disks,
        "power": power
    }

s = get_current_state()
print("Power plugged:", s["power"])
print("Drives:", list(s["drives"].keys()))
print("USB Disks:", s["usb_disks"])
print("Active Audio Endpoints:")
for did, name in s["audio"].items():
    print("  -", name)
