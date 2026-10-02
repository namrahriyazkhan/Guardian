import sys
import os
import webbrowser
import threading
import time
import tempfile
import atexit
import ctypes

# Safe stdout/stderr for GUI / noconsole execution
class NullWriter:
    def write(self, s): pass
    def flush(self): pass

if sys.stdout is None:
    sys.stdout = NullWriter()
if sys.stderr is None:
    sys.stderr = NullWriter()

# Ensure UTF-8 output encoding on Windows console/pipes if stdout exists
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Check if launched in notifier subprocess mode
if "--notifier" in sys.argv:
    try:
        import notifier
        notifier.main()
    except Exception as e:
        print(f"Notifier process error: {e}")
    sys.exit(0)

# Check if launched in emergency lockdown blackout mode
if "--lockdown" in sys.argv:
    try:
        import sentry_sentinel
        sentry_sentinel.run_fullscreen_lockdown_shield()
    except Exception as e:
        print(f"Lockdown process error: {e}")
    sys.exit(0)


# ============================================================
# GUARDIAN SINGLE-INSTANCE LOCK (WINDOWS KERNEL MUTEX)
# ============================================================

MUTEX_NAME = "Global\\GuardianSecurityPlatformMutex"
_guardian_mutex_handle = None

def bring_existing_window_to_front():
    """Brings existing native GUARDIAN desktop window to front if already running."""
    try:
        for title in ["GUARDIAN Security Platform", "GUARDIAN"]:
            hwnd = ctypes.windll.user32.FindWindowW(None, title)
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(hwnd)
                return True
    except Exception:
        pass
    return False

def acquire_single_instance_lock():
    """
    Acquires a named Windows kernel mutex to guarantee single instance.
    Windows automatically releases kernel mutexes when the process exits.
    """
    global _guardian_mutex_handle
    try:
        ERROR_ALREADY_EXISTS = 183
        _guardian_mutex_handle = ctypes.windll.kernel32.CreateMutexW(
            None,
            False,
            MUTEX_NAME
        )
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            bring_existing_window_to_front()
            return False

        # Clean legacy lock file if it exists
        legacy_lock = os.path.join(tempfile.gettempdir(), "guardian_running.lock")
        if os.path.exists(legacy_lock):
            try:
                os.remove(legacy_lock)
            except Exception:
                pass

        return True

    except Exception as e:
        print(f"Mutex initialization notice: {e}")
        return True


# Check if Guardian is already running
if not acquire_single_instance_lock():
    sys.exit(0)


# ============================================================
# DISABLE WINDOWS PROXY
# ============================================================

def ensure_proxy_disabled():
    """
    Disables Windows system proxy so Windows services,
    Taskbar Search and Guardian networking work normally.
    """

    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_ALL_ACCESS
        )

        # Disable proxy
        winreg.SetValueEx(
            key,
            "ProxyEnable",
            0,
            winreg.REG_DWORD,
            0
        )

        # Remove proxy-related settings
        for val_name in [
            "ProxyServer",
            "ProxyOverride",
            "AutoConfigURL"
        ]:
            try:
                winreg.DeleteValue(key, val_name)
            except Exception:
                pass

        winreg.CloseKey(key)

        # Refresh Windows Internet settings
        try:
            ctypes.windll.wininet.InternetSetOptionW(
                0,
                39,
                0,
                0
            )

            ctypes.windll.wininet.InternetSetOptionW(
                0,
                37,
                0,
                0
            )

        except Exception:
            pass

    except Exception as e:
        print(f"Proxy configuration skipped: {e}")


ensure_proxy_disabled()


# ============================================================
# GUARDIAN BASE DIRECTORY
# ============================================================

print("Guardian Launcher Started")

if getattr(sys, "frozen", False):

    # Running as compiled EXE
    BASE = os.path.dirname(sys.executable)

else:

    # Running normally with Python
    BASE = os.path.dirname(
        os.path.abspath(__file__)
    )

try:
    os.chdir(BASE)
except Exception:
    pass

# Make sure Guardian folder is available to Python
if BASE not in sys.path:
    sys.path.insert(0, BASE)


# ============================================================
# START FLASK APPLICATION
# ============================================================

try:
    print("Starting Flask application...")

    import app as flask_app

    flask_thread = threading.Thread(
        target=lambda: flask_app.app.run(
            host="0.0.0.0",
            debug=False,
            threaded=True,
            port=5000
        ),
        daemon=True
    )
    flask_thread.start()
    print("Flask application started on 0.0.0.0:5000.")

except Exception as e:
    print(f"Flask application failed to start: {e}")


# ============================================================
# START APP MONITOR
# ============================================================

def start_app_monitor():
    try:
        print("Starting App Monitor...")
        import app_monitor
        print("App Monitor started successfully.")
    except Exception as e:
        print(f"App Monitor failed to start: {e}")


threading.Thread(
    target=start_app_monitor,
    daemon=True
).start()


# ============================================================
# START BROWSER PROXY
# ============================================================

def start_browser_proxy():
    try:
        print("Starting Browser Proxy...")
        import browser_proxy
        if hasattr(browser_proxy, "start"):
            browser_proxy.start()
        print("Browser Proxy started successfully.")
    except Exception as e:
        print(f"Browser Proxy failed to start: {e}")


threading.Thread(
    target=start_browser_proxy,
    daemon=True
).start()


# ============================================================
# START NOTIFIER
# ============================================================

def start_notifier():
    try:
        print("Starting Notifier process...")
        import subprocess
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "--notifier"]
        else:
            cmd = [sys.executable, os.path.join(BASE, "notifier.py")]
        
        flags = 0
        if sys.platform == "win32":
            flags = 0x08000000  # CREATE_NO_WINDOW
        
        subprocess.Popen(cmd, creationflags=flags)
        print("Notifier process started successfully.")
    except Exception as e:
        print(f"Notifier failed to start: {e}")


threading.Thread(
    target=start_notifier,
    daemon=True
).start()


# ============================================================
# GUARDIAN READY & LAUNCH DESKTOP APPLICATION
# ============================================================

print("")
print("==========================================")
print("       GUARDIAN IS RUNNING SUCCESSFULLY   ")
print("==========================================")
print("")

time.sleep(1)

TARGET_URL = "http://127.0.0.1:5000/splash"

def wait_for_flask_ready(url=TARGET_URL, timeout=6):
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status in (200, 302):
                    return True
        except Exception:
            time.sleep(0.15)
    return False

wait_for_flask_ready()

try:
    import webview
    print("Launching Guardian native desktop window...")
    window = webview.create_window(
        "GUARDIAN Security Platform",
        TARGET_URL,
        width=1380,
        height=880,
        min_size=(1024, 680),
        background_color="#0A1F3C",
        text_select=True,
        easy_drag=False
    )
    webview.start(gui="edgechromium", debug=False)
    sys.exit(0)

except Exception as e:
    print(f"Desktop window notice ({e}). Opening web interface...")
    try:
        webbrowser.open(TARGET_URL)
    except Exception:
        pass

    while True:
        time.sleep(60)