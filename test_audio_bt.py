import win32com.client
import pythoncom
import winreg

pythoncom.CoInitialize()
wmi = win32com.client.GetObject("winmgmts:")

print("=== Win32_SoundDevice ===")
for s in wmi.ExecQuery("SELECT Name, DeviceID, Status, StatusInfo FROM Win32_SoundDevice"):
    print(s.Name, "| Status:", s.Status, "| StatusInfo:", s.StatusInfo)

print("\n=== Win32_PnPEntity AudioEndpoint ===")
for a in wmi.ExecQuery("SELECT Name, DeviceID, Status, ConfigManagerErrorCode, Present FROM Win32_PnPEntity WHERE PNPClass = 'AudioEndpoint'"):
    print(a.Name, "| Status:", a.Status, "| Present:", a.Present, "| ErrCode:", a.ConfigManagerErrorCode)

print("\n=== Bluetooth Registry Active State ===")
try:
    key_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        num_subkeys = winreg.QueryInfoKey(key)[0]
        for i in range(num_subkeys):
            dev_addr = winreg.EnumKey(key, i)
            with winreg.OpenKey(key, dev_addr) as dev_key:
                name = ""
                try:
                    name = winreg.QueryValueEx(dev_key, "Name")[0]
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="ignore").replace("\x00", "")
                except:
                    pass
                print(f"Device: {name} (Addr: {dev_addr})")
                for val_name in ["Connected", "LastConnected", "Authenticated"]:
                    try:
                        val = winreg.QueryValueEx(dev_key, val_name)[0]
                        print(f"   {val_name}: {val}")
                    except:
                        pass
except Exception as e:
    print("Registry error:", e)
