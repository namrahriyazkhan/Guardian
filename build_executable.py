"""
build_executable.py — Standalone Executable Builder for GUARDIAN Security Platform
Bundles all Python modules, PyWebView (EdgeChromium), PyQt5, OpenCV, ML models,
sound files, HTML/CSS/JS assets into a robust dist/GUARDIAN standalone folder.
"""
import os
import sys
import shutil
import subprocess

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

print("=" * 60)
print("  [BUILD] BUILDING GUARDIAN STANDALONE EXECUTABLE WITH PYINSTALLER")
print("=" * 60)

# 1. Terminate any running GUARDIAN processes to free file locks
try:
    import psutil
    curr_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            if proc.pid == curr_pid:
                continue
            name = (proc.info.get('name') or '').lower()
            exe = (proc.info.get('exe') or '').lower()
            cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
            if 'guardian.exe' in name or 'guardian.exe' in exe or ('guardian.py' in cmdline and 'python' in name):
                print(f"Closing running process: {proc.info.get('name')} (PID: {proc.pid})")
                proc.kill()
        except Exception:
            pass
except Exception:
    pass

import time
time.sleep(1)

def safe_rmtree(path):
    if not os.path.exists(path):
        return
    import stat
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            p = os.path.join(root, f)
            try:
                os.chmod(p, stat.S_IWRITE)
                os.remove(p)
            except Exception:
                pass
        for d in dirs:
            p = os.path.join(root, d)
            try:
                os.rmdir(p)
            except Exception:
                pass
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass

# 2. Clean previous build / dist directories if needed
for d in ["build", "dist"]:
    p = os.path.join(BASE_DIR, d)
    if os.path.exists(p):
        print(f"Cleaning {d}/...")
        safe_rmtree(p)

# 2. Data files to collect (src;dst)
data_files = [
    ("index.html", "."),
    ("splash.html", "."),
    ("remote.html", "."),
    ("dossier_report.html", "."),
    ("chart.js", "."),
    ("main.js", "."),
    ("welcome_tour.js", "."),
    ("welcome_tour.css", "."),
    ("guardian_logo.png", "."),
    ("guardian_logo.ico", "."),
    ("guardian_logo.jpg", "."),
    ("sentry_qr.png", "."),
    ("alert_beep.wav", "."),
    ("freesound_community-beep-6-96243.mp3", "."),
    ("templates", "templates"),
    ("static", "static"),
]

add_data_args = []
for src, dst in data_files:
    full_src = os.path.join(BASE_DIR, src)
    if os.path.exists(full_src):
        add_data_args.extend(["--add-data", f"{full_src};{dst}"])

# 3. Hidden imports
hidden_imports = [
    "engineio.async_drivers.threading",
    "jinja2",
    "jinja2.loaders",
    "flask",
    "flask_cors",
    "sklearn",
    "sklearn.ensemble",
    "sklearn.preprocessing",
    "sklearn.tree",
    "sklearn.neighbors",
    "numpy",
    "psutil",
    "PyQt5",
    "PyQt5.QtCore",
    "PyQt5.QtGui",
    "PyQt5.QtWidgets",
    "PyQt5.sip",
    "webview",
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "clr",
    "pythonnet",
    "win32gui",
    "win32con",
    "win32api",
    "win32process",
    "win32file",
    "win32com",
    "win32com.client",
    "pythoncom",
    "reportlab",
    "reportlab.lib",
    "reportlab.platypus",
    "reportlab.pdfgen",
    "reportlab.pdfbase",
    "reportlab.pdfbase.ttfonts",
    "cv2",
    "PIL",
    "PIL.Image",
    "qrcode",
    "requests",
    "notifier",
    "app_monitor",
    "browser_proxy",
    "device_sentinel",
    "sentry_sentinel",
    "winsound",
    "ctypes",
    "ctypes.wintypes"
]

hidden_import_args = []
for hi in hidden_imports:
    hidden_import_args.extend(["--hidden-import", hi])

icon_path = os.path.join(BASE_DIR, "guardian_logo.ico")

import tempfile
temp_work = os.path.join(tempfile.gettempdir(), "pyi_guardian_work")
temp_spec = os.path.join(tempfile.gettempdir(), "pyi_guardian_spec")
temp_dist = os.path.join(tempfile.gettempdir(), "pyi_guardian_dist")
os.makedirs(temp_work, exist_ok=True)
os.makedirs(temp_spec, exist_ok=True)
os.makedirs(temp_dist, exist_ok=True)

cmd = [
    sys.executable, "-m", "PyInstaller",
    "--name=GUARDIAN",
    "--noconfirm",
    "--clean",
    "--onedir",
    "--windowed",
    "--workpath", temp_work,
    "--specpath", temp_spec,
    "--distpath", temp_dist,
]

if os.path.exists(icon_path):
    cmd.extend(["--icon", icon_path])

cmd.extend(add_data_args)
cmd.extend(hidden_import_args)
cmd.append("GUARDIAN.py")

print("Running PyInstaller command:")
print(" ".join(cmd[:10]), "... [and data/hidden-import flags]")

res = subprocess.run(cmd)
if res.returncode != 0:
    print("❌ PyInstaller build failed with code", res.returncode)
    sys.exit(res.returncode)

dist_folder = os.path.join(BASE_DIR, "dist", "GUARDIAN")
os.makedirs(os.path.join(BASE_DIR, "dist"), exist_ok=True)
built_src = os.path.join(temp_dist, "GUARDIAN")
if os.path.exists(built_src):
    print("Copying compiled bundle to dist/GUARDIAN...")
    shutil.copytree(built_src, dist_folder, dirs_exist_ok=True)

internal_folder = os.path.join(dist_folder, "_internal")

# Ensure assets are directly accessible in dist/GUARDIAN root as well as _internal
for src, dst in data_files:
    s = os.path.join(BASE_DIR, src)
    if not os.path.exists(s):
        continue
    # Copy to dist root
    d_root = os.path.join(dist_folder, src)
    if os.path.isdir(s):
        if os.path.exists(d_root):
            shutil.rmtree(d_root, ignore_errors=True)
        shutil.copytree(s, d_root, dirs_exist_ok=True)
        if os.path.exists(internal_folder):
            d_int = os.path.join(internal_folder, src)
            shutil.copytree(s, d_int, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d_root)
        if os.path.exists(internal_folder):
            d_int = os.path.join(internal_folder, src)
            shutil.copy2(s, d_int)

# Synchronize directly to the installed application path (where Desktop shortcut points)
installed_dirs = [
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\GUARDIAN"),
    os.path.expandvars(r"%PROGRAMFILES%\GUARDIAN"),
    os.path.expandvars(r"%ProgramFiles(x86)%\GUARDIAN")
]
for inst in installed_dirs:
    if os.path.exists(inst):
        print(f"Syncing updated bundle to installed directory: {inst}...")
        try:
            shutil.copytree(dist_folder, inst, dirs_exist_ok=True)
            print(f"✅ Successfully updated {inst}")
        except Exception as e:
            print(f"Notice syncing to {inst}: {e}")

print("\n✅ PyInstaller build complete! Standalone and Desktop Shortcut targets updated!")
