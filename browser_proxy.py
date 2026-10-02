"""
browser_proxy.py — Lightweight pure-Python HTTP/HTTPS proxy
Zero extra dependencies. Works on Chrome, Edge, Firefox, ANY browser.
Captures all visited hostnames and reports to Guardian Flask backend in real-time.
Filters out background Windows OS telemetry and analytics noise.
"""
import socket
import threading
import time
import requests
import winreg
import ctypes
import ssl
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Config ────────────────────────────────────────────────────────────
PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8082          # use 8082 to avoid conflicts
FLASK_URL   = "http://127.0.0.1:5000/api/browser_visit"
MAX_THREADS = 50

# ── Hosts / Substrings to silently skip (telemetry, updates, background noise) ──
NOISE_PATTERNS = [
    ".events.data.microsoft.com",
    ".telemetry.microsoft.com",
    ".data.microsoft.com",
    ".trafficmanager.net",
    ".azureedge.net",
    ".azure.com",
    ".azurewebsites.net",
    ".windowsupdate.com",
    "watson.",
    "settings-win.",
    "activity.windows.com",
    "wdcp.microsoft.com",
    "smartscreen.",
    "c.bing.com", "c.msn.com", "api.msn.com", "assets.msn.com", "sb.scorecardresearch.com",
    "datadoghq.com", "datadoghq.eu", "browser-intake",
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "clarity.ms", "sentry.io", "segment.io", "mixpanel.com",
    "telemetry.", "analytics.", "metrics.", "stats.", "logging.",
    "optimizationguide-pa.googleapis.com",
    "chrome-variations.googleapis.com",
    "clientservices.googleapis.com",
    "safebrowsing.",
    "pki.goog", "digicert.com", "lencr.org", "sectigo.com",
    "update.googleapis.com", "gvt1.com",
    "127.0.0.1", "localhost", "0.0.0.0"
]

def _is_noise(hostname):
    if not hostname:
        return True
    h = hostname.lower().strip()
    # Strip port if present
    if ":" in h:
        h = h.split(":")[0]
    # Check IP
    if h.replace(".", "").isdigit():
        return True
    for p in NOISE_PATTERNS:
        if p in h:
            return True
    return False

BROWSER_DEFINITIONS = [
    (['duckduckgo.exe', 'duckduckgo.webview.exe', 'duckduckgobrowser.exe'], 'DuckDuckGo'),
    (['chrome.exe'], 'Google Chrome'),
    (['msedge.exe'], 'Microsoft Edge'),
    (['firefox.exe'], 'Mozilla Firefox'),
    (['brave.exe'], 'Brave Browser'),
    (['operagx.exe'], 'Opera GX'),
    (['opera.exe'], 'Opera'),
    (['vivaldi.exe'], 'Vivaldi'),
    (['arc.exe'], 'Arc'),
    (['tor.exe', 'torbrowser.exe'], 'Tor Browser'),
    (['chromium.exe'], 'Chromium'),
    (['waterfox.exe'], 'Waterfox'),
    (['librewolf.exe'], 'LibreWolf'),
    (['zen.exe'], 'Zen Browser'),
    (['sidekick.exe'], 'Sidekick'),
]

def _get_active_browser():
    try:
        import psutil
        for p in psutil.process_iter(['name']):
            n = (p.info['name'] or '').lower()
            if not n:
                continue
            for exes, b_name in BROWSER_DEFINITIONS:
                if n in exes or ('duckduckgo' in n and b_name == 'DuckDuckGo'):
                    return b_name
    except:
        pass
    return "Browser"

# ── Seen-recently cache (hostname → last reported time) ───────────────
_seen_cache  = {}
_seen_lock   = threading.Lock()
SEEN_TTL_SEC = 20    # re-report same host after 20s (catches revisits)

# ── Proxy running flag ────────────────────────────────────────────────
_running     = False
_server_sock = None


# ══════════════════════════════════════════════════════════════════════
#  REPORT TO FLASK
# ══════════════════════════════════════════════════════════════════════
def _report(hostname, full_url=""):
    """Send visited hostname to Guardian Flask backend (non-blocking)."""
    if _is_noise(hostname):
        return

    now = time.time()
    clean_host = hostname.split(":")[0] if ":" in hostname else hostname

    with _seen_lock:
        last = _seen_cache.get(clean_host, 0)
        if now - last < SEEN_TTL_SEC:
            return
        _seen_cache[clean_host] = now
        # Prune old entries
        if len(_seen_cache) > 500:
            cutoff = now - SEEN_TTL_SEC * 2
            old = [k for k, v in _seen_cache.items() if v < cutoff]
            for k in old:
                del _seen_cache[k]

    browser_name = _get_active_browser()

    def _post():
        try:
            requests.post(FLASK_URL, json={
                "url":       clean_host,
                "full_url":  full_url[:300] if full_url else f"https://{clean_host}/",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "title":     "",
                "browser":   browser_name,
            }, timeout=1.0)
            print(f"[Proxy] 🌐 Reported: {clean_host} ({browser_name})")
        except Exception:
            pass  # Flask might not be ready yet — silently skip

    threading.Thread(target=_post, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════
#  HANDLE ONE CLIENT CONNECTION
# ══════════════════════════════════════════════════════════════════════
def _handle_client(client_sock, client_addr):
    try:
        # Read the first line of the HTTP request
        data = b""
        client_sock.settimeout(5)
        while b"\r\n" not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break

        if not data:
            return

        first_line = data.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        parts = first_line.split(" ")
        if len(parts) < 2:
            return

        method = parts[0].upper()
        url    = parts[1]

        # ── HTTPS CONNECT tunnel ──────────────────────────────────────
        if method == "CONNECT":
            # Format: CONNECT hostname:443 HTTP/1.1
            host_port = url.split(":")
            hostname  = host_port[0]
            port      = int(host_port[1]) if len(host_port) > 1 else 443

            # Report the hostname
            _report(hostname, f"https://{hostname}/")

            # Try to connect to the real server
            try:
                remote = socket.create_connection((hostname, port), timeout=10)
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                # Tunnel raw bytes in both directions
                _tunnel(client_sock, remote)
            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")

        # ── Plain HTTP ────────────────────────────────────────────────
        else:
            parsed   = urlparse(url)
            hostname = parsed.hostname or ""
            port     = parsed.port or 80

            _report(hostname, url)

            try:
                remote = socket.create_connection((hostname, port), timeout=10)
                remote.sendall(data)
                # Relay response back to browser
                while True:
                    chunk = remote.recv(65536)
                    if not chunk:
                        break
                    try:
                        client_sock.sendall(chunk)
                    except Exception:
                        break
                remote.close()
            except Exception:
                pass

    except Exception as e:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def _tunnel(sock_a, sock_b):
    """Bidirectional raw TCP tunnel for HTTPS CONNECT."""
    def _relay(src, dst):
        try:
            src.settimeout(30)
            dst.settimeout(30)
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try: src.close()
            except: pass
            try: dst.close()
            except: pass

    t1 = threading.Thread(target=_relay, args=(sock_a, sock_b), daemon=True)
    t2 = threading.Thread(target=_relay, args=(sock_b, sock_a), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=60)
    t2.join(timeout=60)


# ══════════════════════════════════════════════════════════════════════
#  PROXY SERVER LOOP
# ══════════════════════════════════════════════════════════════════════
def _server_loop():
    global _server_sock, _running
    try:
        _server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _server_sock.bind((PROXY_HOST, PROXY_PORT))
        _server_sock.listen(MAX_THREADS)
        _server_sock.settimeout(2)
        print(f"[Proxy] ✅ Listening on {PROXY_HOST}:{PROXY_PORT}")

        while _running:
            try:
                client_sock, addr = _server_sock.accept()
                t = threading.Thread(
                    target=_handle_client,
                    args=(client_sock, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception as e:
        print(f"[Proxy] Server error: {e}")
    finally:
        if _server_sock:
            try: _server_sock.close()
            except: pass


# ══════════════════════════════════════════════════════════════════════
#  WINDOWS SYSTEM PROXY SAFETY HELPERS (Ensures Windows Search works)
# ══════════════════════════════════════════════════════════════════════
def _clear_windows_proxy():
    """Thoroughly cleans Windows proxy registry and internet options so Taskbar Search and Windows services are never blocked."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_ALL_ACCESS
        )
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        for val_name in ["ProxyServer", "ProxyOverride", "AutoConfigURL"]:
            try:
                winreg.DeleteValue(key, val_name)
            except Exception:
                pass
        winreg.CloseKey(key)

        # Refresh Windows internet options
        try:
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
        except Exception:
            pass
        print("[Proxy] Windows system proxy confirmed disabled (taskbar search protected)")
    except Exception as e:
        print(f"[Proxy] Registry check notice: {e}")


# ══════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════
def start():
    global _running
    _running = True
    _clear_windows_proxy()
    t = threading.Thread(target=_server_loop, daemon=True)
    t.start()
    print("[Proxy] 🌐 Browser monitoring proxy listener active on port 8082")
    return t


def stop():
    global _running
    _running = False
    _clear_windows_proxy()
    if _server_sock:
        try: _server_sock.close()
        except: pass
    print("[Proxy] Stopped. System proxy clear.")


# ══════════════════════════════════════════════════════════════════════
#  STANDALONE MODE
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import atexit
    atexit.register(stop)
    start()
    print("Press Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop()