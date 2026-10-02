import pythoncom
import win32com.client
import psutil

def get_devices():
    pythoncom.CoInitialize()
    wmi = win32com.client.GetObject("winmgmts:")
    devices = {}

    # 1. Audio Endpoints (AirPods, Earphones, Bluetooth, Wired)
    try:
        for it in wmi.ExecQuery("SELECT Name, DeviceID, Status FROM Win32_PnPEntity WHERE PNPClass = 'AudioEndpoint' AND Status = 'OK'"):
            did = str(it.DeviceID or "").strip()
            name = str(it.Name or "").strip()
            if not did or not name:
                continue
            lower_name = name.lower()
            category = "audio"
            if any(k in lower_name for k in ["bluetooth", "airpods", "airdopes", "buds", "wireless", "tws", "hands-free", "handsfree"]):
                category = "bluetooth"
            devices[did] = {
                "name": name,
                "category": category,
                "type": "audio",
                "id": did
            }
    except Exception as e:
        print("Audio query error:", e)

    # 2. USB Storage / Pendrives / External Hard Drives
    try:
        for d in wmi.ExecQuery("SELECT Model, DeviceID, InterfaceType, PNPDeviceID FROM Win32_DiskDrive"):
            pnp_id = str(d.PNPDeviceID or "").upper()
            if "USBSTOR" in pnp_id or str(d.InterfaceType or "").upper() == "USB" or "USB" in pnp_id:
                model = str(d.Model or "USB Flash Drive").strip()
                did = str(d.DeviceID or pnp_id).strip()
                devices[did] = {
                    "name": model,
                    "category": "usb",
                    "type": "usb_drive",
                    "id": did
                }
    except Exception as e:
        print("Disk query error:", e)

    # 3. Mobile Phones, Android, iPhone, WPD Portable Devices
    try:
        for it in wmi.ExecQuery("SELECT Name, DeviceID, PNPClass FROM Win32_PnPEntity WHERE (PNPClass = 'WPD' OR PNPClass = 'USBDevice' OR PNPClass = 'Modem') AND Status = 'OK' AND Present = True"):
            did = str(it.DeviceID or "").strip()
            name = str(it.Name or "").strip()
            if not did or not name or name == "APP Mode":
                continue
            devices[did] = {
                "name": name,
                "category": "phone",
                "type": "phone",
                "id": did
            }
    except Exception as e:
        print("WPD query error:", e)

    # 4. USB Connected Hardware & Peripherals (excluding root hubs and PCI controllers)
    try:
        for it in wmi.ExecQuery("SELECT Name, DeviceID, PNPClass FROM Win32_PnPEntity WHERE Status = 'OK' AND Present = True"):
            did = str(it.DeviceID or "").strip()
            name = str(it.Name or "").strip()
            cls = str(it.PNPClass or "").strip()
            if not did or not name:
                continue
            
            # Match USB devices (USB\VID_xxxx) or USB Storage (USBSTOR\)
            is_usb_plugged = did.startswith("USB\\VID_") or did.startswith("USBSTOR\\") or did.startswith("SWD\\WPDBUSENUM")
            if is_usb_plugged:
                lower = name.lower()
                # Exclude only internal USB host controller or root hub
                if "root hub" in lower or "root router" in lower or "host controller" in lower:
                    continue
                # Determine category
                cat = "usb"
                if cls == "WPD" or any(k in lower for k in ["phone", "galaxy", "iphone", "m14", "pixel", "redmi", "android", "samsung mobile"]):
                    cat = "phone"
                elif any(k in lower for k in ["disk", "flash", "cruzer", "sandisk", "kingston", "transcend", "storage", "drive"]):
                    cat = "usb"
                elif any(k in lower for k in ["audio", "headset", "earphone", "headphone"]):
                    cat = "audio"

                devices[did] = {
                    "name": name,
                    "category": cat,
                    "type": "usb_device",
                    "id": did
                }
    except Exception as e:
        print("USB PnP query error:", e)

    # 5. Drive letters (psutil)
    drives = {}
    try:
        for p in psutil.disk_partitions(all=True):
            if p.mountpoint:
                drives[p.mountpoint] = p.fstype
    except Exception:
        pass

    # 6. Charger
    power = True
    try:
        batt = psutil.sensors_battery()
        if batt:
            power = batt.power_plugged
    except Exception:
        pass

    return devices, drives, power

devs, drives, pwr = get_devices()
print(f"Total devices tracked: {len(devs)}")
print(f"Drives: {list(drives.keys())}")
print(f"Power: {pwr}")
for did, d in devs.items():
    print(f"  [{d['category'].upper()}] {d['name']} (ID: {did[:45]})")
