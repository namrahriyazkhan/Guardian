import pythoncom
import win32com.client
import psutil

pythoncom.CoInitialize()
wmi = win32com.client.GetObject("winmgmts:")

print("=== ALL PnPEntities with WPD, USB, Disk, Media, Phone ===")
for p in wmi.ExecQuery("SELECT Name, DeviceID, PNPClass, Status, Present, Description FROM Win32_PnPEntity"):
    cls = str(p.PNPClass or "")
    name = str(p.Name or "")
    did = str(p.DeviceID or "")
    pres = getattr(p, "Present", None)
    stat = getattr(p, "Status", None)
    
    # Check if USB, WPD, DiskDrive, or any phone/storage related
    if cls in ["WPD", "DiskDrive", "USB", "Volume", "USBDevice", "Modem", "Net"] or any(k in name.lower() for k in ["samsung", "iphone", "phone", "sandisk", "kingston", "cruzer", "flash", "usb", "disk"]):
        print(f"[{cls}] Name='{name}' | Present={pres} | Status={stat} | ID='{did}'")

print("\n=== Win32_DiskDrive ===")
for d in wmi.ExecQuery("SELECT Model, DeviceID, InterfaceType, MediaType, PNPDeviceID FROM Win32_DiskDrive"):
    print(f"Model='{d.Model}' | Interface='{d.InterfaceType}' | MediaType='{d.MediaType}' | PNPID='{d.PNPDeviceID}'")

print("\n=== psutil disk_partitions ===")
for part in psutil.disk_partitions(all=True):
    print(f"Mount='{part.mountpoint}' | Device='{part.device}' | FsType='{part.fstype}' | Opts='{part.opts}'")
