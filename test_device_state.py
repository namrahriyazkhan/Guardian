import subprocess
import json

ps_cmd = "Get-PnpDevice | Where-Object { $_.Class -in @('Bluetooth', 'AudioEndpoint', 'Media', 'USB', 'DiskDrive') } | Select-Object FriendlyName, InstanceId, Status, Class | ConvertTo-Json -Depth 2"
p = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, encoding="utf-8")
try:
    data = json.loads(p.stdout)
    for item in data:
        fn = item.get("FriendlyName") or ""
        st = item.get("Status")
        cl = item.get("Class")
        if any(k in fn.lower() for k in ["airdopes", "harmonics", "m14", "airpods", "buds", "headphone", "audio", "usb", "disk"]):
            print(f"[{cl}] {fn} -> Status: {st}")
except Exception as e:
    print("Error:", e)
