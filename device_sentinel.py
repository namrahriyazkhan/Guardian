"""
device_sentinel.py - Hardware & Peripheral Sentinel for Laptop Anti-Theft Guard
Monitors AC Power, USB flash drives, Audio devices, and Bluetooth gadgets in real time.
Provides automated software ejection and hardware neutralization actions.
"""

import time
import threading
import psutil
import sys
import os
import subprocess
import ctypes
from ctypes import wintypes

try:
    import pythoncom
    import win32com.client
    import win32file
    import win32api
    import win32con
except ImportError:
    pythoncom = None
    win32com = None
    win32file = None
    win32api = None
    win32con = None


class DeviceSentinel:
    def __init__(self, on_event_callback=None):
        self.on_event_callback = on_event_callback
        self.running = False
        self.thread = None
        self.lock = threading.Lock()

        # Tracked baseline states
        self.last_power_plugged = self._get_power_plugged()
        self.last_drives = self._get_drives()
        self.last_pnp_devices = self._get_active_pnp_devices()

        # Pending verification queue (for popups / TVC)
        self.pending_devices = {}
        self.verified_devices = set()
        self.blocked_devices = set()
        self.recent_events_cache = {}

    # -------------------------------------------------------------
    # 1. AC POWER / CHARGER DETECTION
    # -------------------------------------------------------------
    def _get_power_plugged(self):
        try:
            batt = psutil.sensors_battery()
            if batt is not None:
                return batt.power_plugged
        except Exception:
            pass
        return True

    # -------------------------------------------------------------
    # 2. USB / STORAGE DRIVE DETECTION & FRIENDLY NAMES
    # -------------------------------------------------------------
    def _get_drives(self):
        drives = {}
        try:
            for p in psutil.disk_partitions(all=True):
                mount = p.mountpoint
                if not mount:
                    continue
                dtype = "fixed"
                label = ""
                total_gb = 0

                if win32file and win32api:
                    try:
                        dt = win32file.GetDriveType(mount)
                        if dt == win32file.DRIVE_REMOVABLE:
                            dtype = "usb_removable"
                        elif dt == win32file.DRIVE_CDROM:
                            dtype = "cdrom"
                        elif dt == win32file.DRIVE_REMOTE:
                            dtype = "network"
                        elif dt == win32file.DRIVE_FIXED:
                            dtype = "fixed"
                    except Exception:
                        pass

                # Get volume label
                try:
                    vol_buf = ctypes.create_unicode_buffer(260)
                    fs_buf = ctypes.create_unicode_buffer(260)
                    if ctypes.windll.kernel32.GetVolumeInformationW(
                        mount, vol_buf, 260, None, None, None, fs_buf, 260
                    ):
                        label = vol_buf.value.strip()
                except Exception:
                    pass

                # Get total size
                try:
                    usage = psutil.disk_usage(mount)
                    total_gb = round(usage.total / (1024 ** 3), 1)
                except Exception:
                    pass

                friendly_name = label if label else ("USB Drive" if dtype == "usb_removable" else f"Local Disk ({mount[0]}:)")
                if total_gb > 0:
                    friendly_name += f" ({total_gb} GB)"

                drives[mount] = {
                    "type": dtype,
                    "fstype": p.fstype,
                    "opts": p.opts,
                    "label": label,
                    "total_gb": total_gb,
                    "friendly_name": friendly_name
                }
        except Exception:
            pass
        return drives

    # -------------------------------------------------------------
    # 3. HIGH-SPEED PNP PERIPHERALS (BLUETOOTH, AIRPODS, AUDIO, PHONES, USB)
    # -------------------------------------------------------------
    def _get_active_pnp_devices(self):
        devices = {}
        if not pythoncom or not win32com:
            return devices

        try:
            pythoncom.CoInitialize()
            wmi = win32com.client.GetObject("winmgmts:")

            # A. Query Active Audio Endpoints (AirPods, Wireless Earbuds, Bluetooth Headset, Wired Earphones)
            try:
                query_audio = "SELECT Name, DeviceID, Status FROM Win32_PnPEntity WHERE PNPClass = 'AudioEndpoint' AND Status = 'OK'"
                for it in wmi.ExecQuery(query_audio):
                    name = str(it.Name or "").strip()
                    did = str(it.DeviceID or "").strip()
                    if not name or not did:
                        continue
                    lower_name = name.lower()
                    category = "audio"
                    if any(k in lower_name for k in ["bluetooth", "airpods", "airdopes", "buds", "wireless", "tws", "hands-free", "handsfree"]):
                        category = "bluetooth"
                    devices[did] = {
                        "name": name,
                        "class": "AudioEndpoint",
                        "category": category,
                        "id": did
                    }
            except Exception:
                pass

            # B. Query USB Storage Disks (Pendrives, Flash Drives, External SSD/HDD)
            try:
                query_disks = "SELECT Model, DeviceID, InterfaceType, PNPDeviceID FROM Win32_DiskDrive"
                for it in wmi.ExecQuery(query_disks):
                    pnp_id = str(it.PNPDeviceID or "").upper()
                    if "USBSTOR" in pnp_id or str(it.InterfaceType or "").upper() == "USB" or "USB" in pnp_id:
                        model = str(it.Model or "USB Storage Drive").strip()
                        did = str(it.DeviceID or pnp_id).strip()
                        if did:
                            devices[did] = {
                                "name": model,
                                "class": "DiskDrive",
                                "category": "usb",
                                "id": did
                            }
            except Exception:
                pass

            # C. Query Mobile Phones, Smartphones, Bluetooth, and USB Connected Hardware
            try:
                query_usb = "SELECT Name, DeviceID, PNPClass FROM Win32_PnPEntity WHERE Status = 'OK' AND Present = True"
                for it in wmi.ExecQuery(query_usb):
                    name = str(it.Name or "").strip()
                    did = str(it.DeviceID or "").strip().upper()
                    cls = str(it.PNPClass or "").strip()
                    if not name or not did:
                        continue

                    # Match USB devices (USB\VID_xxxx), WPD (phones), USBSTOR, Bluetooth, and Audio
                    is_peripheral = (
                        did.startswith("USB\\VID_") or
                        did.startswith("USBSTOR\\") or
                        did.startswith("SWD\\WPDBUSENUM") or
                        did.startswith("BTHENUM\\") or
                        did.startswith("BTH\\") or
                        cls in ["WPD", "Bluetooth", "USBDevice", "AndroidUsbDeviceClass"]
                    )
                    if is_peripheral:
                        lower = name.lower()
                        # Exclude internal motherboard root hubs and host controllers
                        if "root hub" in lower or "root router" in lower or "host controller" in lower or "composite bus" in lower or name == "APP Mode":
                            continue

                        # Resolve friendly name if generic Windows USB description
                        if lower in ["usb composite device", "mtp usb device", "mtp device", "usb mass storage device", "composite device", "usb device", "android"]:
                            if "VID_04E8" in did:
                                name = "Samsung Galaxy Smartphone"
                            elif "VID_05AC" in did:
                                name = "Apple iPhone / iPad"
                            elif "VID_18D1" in did:
                                name = "Google Pixel Smartphone"
                            elif "VID_2717" in did:
                                name = "Xiaomi / Redmi Smartphone"
                            elif "VID_22D9" in did or "VID_2A70" in did:
                                name = "OnePlus / OPPO Smartphone"
                            elif "VID_2E04" in did:
                                name = "Nothing Smartphone"
                            elif "VID_0781" in did:
                                name = "SanDisk USB Flash Drive"
                            elif "VID_0951" in did:
                                name = "Kingston USB Flash Drive"
                            elif "VID_8564" in did:
                                name = "Transcend USB Drive"
                            elif cls == "WPD":
                                name = "Smartphone (USB Connection)"
                            else:
                                name = "External USB Device"
                            lower = name.lower()

                        # Determine accurate category
                        if cls == "WPD" or any(k in lower for k in ["phone", "galaxy", "iphone", "m14", "pixel", "redmi", "xiaomi", "oppo", "vivo", "oneplus", "realme", "android", "samsung mobile", "apple mobile", "smartphone", "mtp"]):
                            category = "phone"
                        elif any(k in lower for k in ["disk", "flash", "cruzer", "sandisk", "kingston", "transcend", "drive", "storage", "usbstor"]):
                            category = "usb"
                        elif did.startswith("BTHENUM\\") or did.startswith("BTH\\") or cls == "Bluetooth" or any(k in lower for k in ["bluetooth", "airpods", "airdopes", "buds", "wireless", "tws", "headset"]):
                            category = "bluetooth"
                        elif any(k in lower for k in ["audio", "earphone", "headphone", "speaker", "microphone", "dac"]):
                            category = "audio"
                        else:
                            category = "usb"

                        devices[did] = {
                            "name": name,
                            "class": cls if cls else "USB",
                            "category": category,
                            "id": did
                        }
            except Exception:
                pass

        except Exception:
            pass
        return devices

    # -------------------------------------------------------------
    # HARDWARE NEUTRALIZATION ACTIONS
    # -------------------------------------------------------------
    def eject_drive(self, mountpoint):
        """Safely ejects and dismounts a removable USB drive."""
        clean_mount = mountpoint.strip().rstrip("\\")
        drive_letter = clean_mount[0] if len(clean_mount) >= 1 else "E"
        success = False

        # Method 1: Shell COM object Eject
        try:
            ps_script = f"(New-Object -comObject Shell.Application).Namespace(17).ParseName('{drive_letter}:').InvokeVerb('Eject')"
            subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                capture_output=True, timeout=5, creationflags=0x08000000 if sys.platform == "win32" else 0
            )
            success = True
        except Exception as e:
            print(f"[DeviceSentinel] Shell eject error: {e}")

        # Method 2: Win32 Volume Dismount
        if win32file and win32con:
            try:
                vol_path = f"\\\\.\\{drive_letter}:"
                h_vol = win32file.CreateFile(
                    vol_path,
                    win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                if h_vol != win32file.INVALID_HANDLE_VALUE:
                    FSCTL_LOCK_VOLUME = 0x00090018
                    FSCTL_DISMOUNT_VOLUME = 0x00090020
                    IOCTL_STORAGE_EJECT_MEDIA = 0x002D4808
                    try:
                        win32file.DeviceIoControl(h_vol, FSCTL_LOCK_VOLUME, None, 0)
                        win32file.DeviceIoControl(h_vol, FSCTL_DISMOUNT_VOLUME, None, 0)
                        win32file.DeviceIoControl(h_vol, IOCTL_STORAGE_EJECT_MEDIA, None, 0)
                    except Exception:
                        pass
                    win32file.CloseHandle(h_vol)
                    success = True
            except Exception as e:
                print(f"[DeviceSentinel] Win32 eject error: {e}")

        return success

    def disable_bluetooth_device(self, device_name):
        """Disconnects / disables a specific Bluetooth device."""
        try:
            clean_name = device_name.replace("'", "").replace('"', '').strip()
            ps_script = (
                f"$devs = Get-PnpDevice | Where-Object {{($_.Class -eq 'Bluetooth' -or $_.Class -eq 'AudioEndpoint' -or $_.FriendlyName -like '*{clean_name}*') -and $_.Status -eq 'OK'}};"
                f"foreach ($d in $devs) {{ Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false -ErrorAction SilentlyContinue }}"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                capture_output=True, timeout=6, creationflags=0x08000000 if sys.platform == "win32" else 0
            )
            return True
        except Exception as e:
            print(f"[DeviceSentinel] Bluetooth disable error: {e}")
            return False

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="DeviceSentinelWorker")
        self.thread.start()

    def stop(self):
        self.running = False

    def _emit(self, event_type, device_category, device_name, target, title, details, severity="HIGH"):
        now_t = time.time()
        # Clean expired debouncing entries older than 3.0 seconds
        self.recent_events_cache = {k: v for k, v in self.recent_events_cache.items() if now_t - v < 3.0}

        # Debounce rapid identical peripheral signals within 2.0s
        dedup_key = f"{event_type}:{device_category}:{device_name.lower().strip()}"
        cat_key = f"{event_type}:{device_category}"
        if dedup_key in self.recent_events_cache or (cat_key in self.recent_events_cache and (now_t - self.recent_events_cache[cat_key] < 1.8)):
            return None

        self.recent_events_cache[dedup_key] = now_t
        self.recent_events_cache[cat_key] = now_t

        event_id = f"DEV-{int(now_t*1000)}"
        evt = {
            "id": event_id,
            "type": event_type,
            "category": device_category,
            "device_name": device_name,
            "target": target,
            "title": title,
            "details": details,
            "severity": severity,
            "timestamp": time.strftime("%I:%M %p"),
            "epoch": now_t,
            "needs_verification": True
        }
        with self.lock:
            self.pending_devices[event_id] = evt

        if self.on_event_callback:
            try:
                self.on_event_callback(evt)
            except Exception as e:
                print(f"[DeviceSentinel] Callback error: {e}")

        # Instantly notify notifier popup server on port 5001
        def _notify_popup():
            try:
                import requests
                requests.post(
                    "http://127.0.0.1:5001/show_peripheral_popup",
                    json=evt,
                    timeout=1.0
                )
            except Exception:
                pass
        threading.Thread(target=_notify_popup, daemon=True).start()

        print(f"[DeviceSentinel] 🚨 DETECTED: {title} ({device_name})")
        return evt

    def _monitor_loop(self):
        if pythoncom:
            pythoncom.CoInitialize()

        loop_count = 0
        while self.running:
            try:
                # 1. Real-time AC Charger Check (every 0.3s)
                current_plugged = self._get_power_plugged()
                if self.last_power_plugged is True and current_plugged is False:
                    self._emit(
                        event_type="power_unplugged",
                        device_category="power",
                        device_name="AC Charger",
                        target="charger",
                        title="⚡ AC Power Disconnected",
                        details="Laptop charger was unplugged! Device is running on battery.",
                        severity="MEDIUM"
                    )
                elif self.last_power_plugged is False and current_plugged is True:
                    self._emit(
                        event_type="power_plugged",
                        device_category="power",
                        device_name="AC Charger",
                        target="charger",
                        title="⚡ AC Power Connected",
                        details="Laptop charger was connected to power mains.",
                        severity="LOW"
                    )
                self.last_power_plugged = current_plugged

                # 2. Real-time Storage Drives Check (every 0.3s)
                current_drives = self._get_drives()
                new_drives = set(current_drives.keys()) - set(self.last_drives.keys())
                removed_drives = set(self.last_drives.keys()) - set(current_drives.keys())

                for d in new_drives:
                    info = current_drives[d]
                    fname = info.get("friendly_name", d)
                    dtype_label = "USB Flash Drive" if info.get("type") == "usb_removable" else "External Storage"
                    self._emit(
                        event_type="usb_plugged",
                        device_category="usb",
                        device_name=fname,
                        target=d,
                        title=f"🔌 {dtype_label} Inserted: {fname}",
                        details=f"Mounted at drive {d} [Format: {info.get('fstype', 'FAT32/NTFS')}]. Please verify if this is you.",
                        severity="HIGH"
                    )

                for d in removed_drives:
                    old_info = self.last_drives.get(d, {})
                    fname = old_info.get("friendly_name", d)
                    self._emit(
                        event_type="usb_removed",
                        device_category="usb",
                        device_name=fname,
                        target=d,
                        title=f"🔌 Storage Device Removed: {fname}",
                        details=f"Drive {d} was disconnected or ejected safely.",
                        severity="LOW"
                    )
                self.last_drives = current_drives

                # 3. Real-time PnP Hardware Check (Bluetooth, AirPods, Audio, Phones, USB Pendrives & gadgets)
                curr_pnp = self._get_active_pnp_devices()
                new_pnp_ids = set(curr_pnp.keys()) - set(self.last_pnp_devices.keys())
                removed_pnp_ids = set(self.last_pnp_devices.keys()) - set(curr_pnp.keys())

                for did in new_pnp_ids:
                    dev = curr_pnp[did]
                    d_name = dev["name"]
                    d_cat = dev["category"]
                    lower_n = d_name.lower()
                    is_phone = "phone" in lower_n or "galaxy" in lower_n or "iphone" in lower_n or "m14" in lower_n or "pixel" in lower_n or "android" in lower_n
                    is_disk = "disk" in lower_n or "flash" in lower_n or "cruzer" in lower_n or "sandisk" in lower_n or "kingston" in lower_n or "storage" in lower_n
                    
                    icon = "📱" if is_phone else ("🎧" if d_cat in ["bluetooth", "audio"] else "🔌")
                    cat_label = "Smartphone" if is_phone else ("USB Flash Drive" if is_disk else ("Bluetooth Device" if d_cat == "bluetooth" else ("Audio Peripheral" if d_cat == "audio" else "USB Device")))

                    self._emit(
                        event_type=f"{d_cat}_connected",
                        device_category=d_cat,
                        device_name=d_name,
                        target=d_name,
                        title=f"{icon} {cat_label} Connected: {d_name}",
                        details=f"Peripheral '{d_name}' connected to laptop. Please confirm if this is you.",
                        severity="HIGH"
                    )

                for did in removed_pnp_ids:
                    dev = self.last_pnp_devices.get(did, {})
                    d_name = dev.get("name", "Peripheral")
                    d_cat = dev.get("category", "usb")
                    lower_n = d_name.lower()
                    is_phone = "phone" in lower_n or "galaxy" in lower_n or "iphone" in lower_n or "m14" in lower_n
                    icon = "📱" if is_phone else ("🎧" if d_cat in ["bluetooth", "audio"] else "🔌")
                    self._emit(
                        event_type=f"{d_cat}_disconnected",
                        device_category=d_cat,
                        device_name=d_name,
                        target=d_name,
                        title=f"{icon} Device Disconnected: {d_name}",
                        details=f"'{d_name}' was disconnected.",
                        severity="LOW"
                    )

                self.last_pnp_devices = curr_pnp
                loop_count += 1
            except Exception as e:
                pass

            time.sleep(0.3)

    def get_snapshot(self):
        batt = None
        try:
            b = psutil.sensors_battery()
            if b:
                batt = {
                    "percent": b.percent,
                    "plugged": b.power_plugged,
                    "secsleft": b.secsleft
                }
        except Exception:
            pass

        return {
            "battery": batt,
            "drives_count": len(self.last_drives),
            "pnp_count": len(self.last_pnp_devices)
        }
