"""
sentry_sentinel.py - Physical & OS Intrusion Defense System for Laptop Anti-Theft Guard
Handles State Machine, Hardware/Physical Intrusion Detection, Stealth Camera,
Audio Broadcast & Intercom, Ghost Screen Mirroring, Remote Controls & Cryptographic Dossier.
"""

import os
import sys
import time
import json
import math
import socket
import struct
import io
import hashlib
import threading
import subprocess
import tempfile
from collections import deque

import cv2
from PIL import Image
import qrcode
import psutil

try:
    import win32gui
    import win32con
    import win32api
    import win32process
    import winsound
    import win32com.client
except ImportError:
    win32gui = None
    win32con = None
    win32api = None
    win32process = None
    winsound = None
    win32com = None

import ctypes
from ctypes import wintypes
from device_sentinel import DeviceSentinel

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
CAPTURES_DIR = os.path.join(STATIC_DIR, "sentry_captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)

PIN_FILE = os.path.join(BASE_DIR, "sentry_pin.json")
EVENTS_FILE = os.path.join(BASE_DIR, "sentry_events.json")


PROTECTED_SYSTEM_APPS = {
    "searchhost.exe", "searchapp.exe", "searchindexer.exe", "searchfilterhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe",
    "applicationframehost.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
    "ctfmon.exe", "dwm.exe", "explorer.exe", "system", "system idle process",
    "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "fontdrvhost.exe", "spoolsv.exe", "audiodg.exe", "wudfhost.exe",
    "lockapp.exe", "memcompression", "crossdeviceservice.exe", "code.exe",
    "python.exe", "python3.exe", "pythonw.exe", "flask.exe"
}


class SentrySentinel:
    def __init__(self):
        self.lock = threading.Lock()
        
        # State Machine: 'STANDBY', 'ARMING', 'ARMED', 'TRIGGERED'
        self.state = "STANDBY"
        self.arm_grace_seconds = 5
        self.arming_remaining = 0
        self.armed_timestamp = None
        self.triggered_reason = ""
        self.is_lockdown_active = False
        self.is_siren_active = False

        # Persistent PIN & Pairing
        self.pin = self._load_or_create_pin()
        self.lan_ip = self._detect_lan_ip()
        self.port = 5000

        # Telemetry Baselines
        self.last_cursor_pos = self._get_cursor_pos()
        self.last_active_window = self._get_active_window_info()
        self.keystroke_buffer = []
        self.recent_events = deque(maxlen=200)
        self.dossier_id = f"DOSSIER-{time.strftime('%Y%m%d-%H%M%S')}-4098"
        self.last_photo_url = None

        # Camera & Worker threads
        self.camera_busy = False
        self.siren_thread = None
        self.arming_thread = None
        self.monitor_thread = None
        self.lockdown_process = None

        # QR Code initialization
        self.qr_cache_bytes = None
        self.generate_qr_code()

        # Load historical events if available
        self._load_events()

        # Start device hardware sentinel
        self.device_sentinel = DeviceSentinel(on_event_callback=self._on_device_event)
        self.device_sentinel.start()

        # Start continuous sentinel thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self._sentinel_loop, daemon=True, name="SentryMonitorLoop")
        self.monitor_thread.start()

    def _on_device_event(self, evt):
        if self.state == "ARMED":
            self.trigger_alarm(
                reason=f"Hardware Tamper: {evt['title']}",
                severity=evt.get("severity", "HIGH"),
                take_photo=True
            )
        self.log_event(
            event_type=evt.get("type", "hardware_event"),
            title=evt.get("title", "Hardware Event"),
            details=evt.get("details", ""),
            severity=evt.get("severity", "HIGH"),
            photo_url=self.last_photo_url if self.state == "ARMED" else None
        )

    # -------------------------------------------------------------
    # PIN & LAN IP & QR Code
    # -------------------------------------------------------------
    def _load_or_create_pin(self):
        if os.path.exists(PIN_FILE):
            try:
                with open(PIN_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "pin" in data and len(str(data["pin"])) == 4:
                        return str(data["pin"])
            except Exception:
                pass
        
        # Default persistent PIN
        default_pin = "6584"
        try:
            with open(PIN_FILE, "w", encoding="utf-8") as f:
                json.dump({"pin": default_pin, "created_at": time.time()}, f, indent=2)
        except Exception:
            pass
        return default_pin

    def set_pin(self, new_pin):
        new_pin = str(new_pin).strip()
        if len(new_pin) == 4 and new_pin.isdigit():
            self.pin = new_pin
            try:
                with open(PIN_FILE, "w", encoding="utf-8") as f:
                    json.dump({"pin": new_pin, "updated_at": time.time()}, f, indent=2)
            except Exception:
                pass
            return True
        return False

    def verify_pin(self, candidate_pin):
        return str(candidate_pin).strip() == self.pin

    def _detect_lan_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_remote_url(self):
        self.lan_ip = self._detect_lan_ip()
        return f"http://{self.lan_ip}:{self.port}/remote"

    def generate_qr_code(self):
        url = self.get_remote_url()
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00E5FF", back_color="#0A111F")
        
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self.qr_cache_bytes = buf.getvalue()
        
        qr_path = os.path.join(STATIC_DIR, "sentry_qr.png")
        try:
            with open(qr_path, "wb") as f:
                f.write(self.qr_cache_bytes)
        except Exception:
            pass
        return self.qr_cache_bytes

    # -------------------------------------------------------------
    # State Machine: Arm, Grace Countdown, Disarm
    # -------------------------------------------------------------
    def arm(self, grace_seconds=5):
        with self.lock:
            if self.state in ["ARMED", "ARMING"]:
                return True
            
            self.state = "ARMING"
            self.arm_grace_seconds = grace_seconds
            self.arming_remaining = grace_seconds
            self.triggered_reason = ""

        # Launch 5s grace countdown thread
        if self.arming_thread and self.arming_thread.is_alive():
            return True
            
        self.arming_thread = threading.Thread(target=self._arming_countdown, daemon=True, name="SentryArmingWorker")
        self.arming_thread.start()
        
        self.log_event(
            event_type="arming_started",
            title="⏳ Arming Countdown Initialized",
            details=f"System will arm in {grace_seconds} seconds. Step away from the laptop.",
            severity="LOW",
            take_photo=False
        )
        return True

    def _arming_countdown(self):
        while self.arming_remaining > 0:
            time.sleep(1.0)
            with self.lock:
                if self.state != "ARMING":
                    return
                self.arming_remaining -= 1

        with self.lock:
            if self.state == "ARMING":
                self.state = "ARMED"
                self.armed_timestamp = time.time()
                self.last_cursor_pos = self._get_cursor_pos()
                self.last_active_window = self._get_active_window_info()

        self.log_event(
            event_type="system_armed",
            title="🛡️ Anti-Theft Guard ARMED",
            details="Intrusion sentinels active (Motion, Keystroke, Power, Devices). Laptop is protected.",
            severity="LOW",
            take_photo=False
        )

    def disarm(self):
        with self.lock:
            self.state = "STANDBY"
            self.arming_remaining = 0
            self.triggered_reason = ""
            self.is_siren_active = False

        self.stop_siren()
        self.dismiss_lockdown_shield()

        self.log_event(
            event_type="system_disarmed",
            title="🔓 Anti-Theft Guard DISARMED",
            details="System disarmed by owner. Sentinels returned to Standby.",
            severity="LOW",
            take_photo=False
        )
        return True

    def trigger_alarm(self, reason="Physical Intrusion Detected", severity="CRITICAL", take_photo=True):
        already_triggered = False
        with self.lock:
            if self.state == "TRIGGERED":
                already_triggered = True
            else:
                self.state = "TRIGGERED"
                self.triggered_reason = reason

        photo_path = None
        if take_photo:
            photo_path = self.capture_stealth_photo()

        if not already_triggered:
            self.log_event(
                event_type="intrusion_triggered",
                title=f"🚨 INTRUSION ALERT: {reason}",
                details=f"Tampering detected while ARMED. Immediate remote action recommended.",
                severity=severity,
                photo_url=photo_path
            )

    # -------------------------------------------------------------
    # Intrusion Telemetry Helpers
    # -------------------------------------------------------------
    def _get_cursor_pos(self):
        try:
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            return (pt.x, pt.y)
        except Exception:
            return (0, 0)

    def _get_active_window_info(self):
        try:
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return {"hwnd": 0, "title": "Desktop", "exe": "explorer.exe", "pid": 0}
            
            buf = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buf, 512)
            title = buf.value or "Active Window"
            
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            
            exe_name = "unknown.exe"
            try:
                proc = psutil.Process(pid.value)
                exe_name = proc.name().lower()
            except Exception:
                pass
                
            return {"hwnd": hwnd, "title": title, "exe": exe_name, "pid": pid.value}
        except Exception:
            return {"hwnd": 0, "title": "Unknown", "exe": "unknown.exe", "pid": 0}

    # -------------------------------------------------------------
    # Keystroke Sequence Decoder & Action Monitor
    # -------------------------------------------------------------
    def _scan_keystrokes(self):
        typed_chars = []
        if not win32api:
            return typed_chars

        # Scan printable virtual key codes
        for vk in range(0x08, 0xDE):
            try:
                # Bit 0 indicates pressed since last check
                state = win32api.GetAsyncKeyState(vk)
                if state & 0x0001:
                    char_repr = None
                    if vk == 0x08:
                        char_repr = "[⌫]"
                    elif vk == 0x0D:
                        char_repr = "[↵ Enter]"
                    elif vk == 0x20:
                        char_repr = " "
                    elif vk == 0x09:
                        char_repr = "[Tab]"
                    elif vk == 0x1B:
                        char_repr = "[Esc]"
                    elif 0x30 <= vk <= 0x39:  # 0-9
                        char_repr = chr(vk)
                    elif 0x41 <= vk <= 0x5A:  # A-Z
                        is_shift = bool(win32api.GetAsyncKeyState(win32con.VK_SHIFT) & 0x8000)
                        is_caps = bool(win32api.GetKeyState(win32con.VK_CAPITAL) & 0x0001)
                        upper = is_shift ^ is_caps
                        char_repr = chr(vk) if upper else chr(vk + 32)
                    elif 0x60 <= vk <= 0x69:  # Numpad 0-9
                        char_repr = str(vk - 0x60)
                    elif vk in [0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xDB, 0xDC, 0xDD, 0xDE]:
                        sym_map = {0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/", 0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'"}
                        char_repr = sym_map.get(vk, "[Symbol]")
                    
                    if char_repr:
                        typed_chars.append(char_repr)
            except Exception:
                continue
        return typed_chars

    # -------------------------------------------------------------
    # Continuous Sentinel Loop (Real-time Full Action Telemetry)
    # -------------------------------------------------------------
    def _sentinel_loop(self):
        user32.SetProcessDPIAware()
        current_typing_word = []
        last_typing_time = 0
        last_photo_time = 0

        while self.running:
            try:
                if self.state in ["ARMED", "TRIGGERED"]:
                    now = time.time()
                    active_win = self._get_active_window_info()

                    # 1. Check Active Window / App Focus Changed
                    if active_win["hwnd"] != self.last_active_window.get("hwnd"):
                        app_name = active_win.get("exe", "unknown.exe")
                        win_title = active_win.get("title", "Active Window")
                        
                        # Trigger alarm on first breach if armed
                        if self.state == "ARMED" and app_name not in ["explorer.exe", "shellexperiencehost.exe"]:
                            self.trigger_alarm(
                                reason=f"App Opened / Switched to {app_name} (\"{win_title[:30]}\")",
                                severity="HIGH",
                                take_photo=True
                            )
                        
                        # Log every app focus / opened
                        self.log_event(
                            event_type="app_opened",
                            title=f"🪟 App Opened / Focused: {app_name}",
                            details=f"Active Window: \"{win_title}\" | Process: {app_name} [PID: {active_win['pid']}]",
                            severity="HIGH",
                            photo_url=self.last_photo_url if (now - last_photo_time > 15) else None
                        )
                        self.last_active_window = active_win

                    # 2. Check Mouse / Touchpad Delta & Clicks
                    curr_pos = self._get_cursor_pos()
                    dx = curr_pos[0] - self.last_cursor_pos[0]
                    dy = curr_pos[1] - self.last_cursor_pos[1]
                    delta = math.hypot(dx, dy)
                    
                    if delta > 45:
                        if self.state == "ARMED":
                            self.trigger_alarm(
                                reason=f"Mouse Movement Detected ({int(delta)}px from {self.last_cursor_pos} to {curr_pos})",
                                severity="CRITICAL",
                                take_photo=True
                            )
                        self.log_event(
                            event_type="mouse_moved",
                            title="🖱️ Mouse / Touchpad Moved",
                            details=f"Cursor moved from {self.last_cursor_pos} to {curr_pos} (Δ {int(delta)}px) in {active_win['exe']}",
                            severity="MEDIUM" if self.state == "TRIGGERED" else "HIGH"
                        )
                        self.last_cursor_pos = curr_pos

                    # Check Mouse Clicks
                    if win32api:
                        try:
                            l_click = win32api.GetAsyncKeyState(0x01) & 0x0001
                            r_click = win32api.GetAsyncKeyState(0x02) & 0x0001
                            if l_click or r_click:
                                click_type = "Left Click" if l_click else "Right Click"
                                if self.state == "ARMED":
                                    self.trigger_alarm(reason=f"Mouse {click_type} in {active_win['exe']}", severity="CRITICAL", take_photo=True)
                                self.log_event(
                                    event_type="mouse_click",
                                    title=f"🖱️ Mouse {click_type} in {active_win['exe']}",
                                    details=f"Clicked at ({curr_pos[0]}, {curr_pos[1]}) on window \"{active_win['title'][:35]}\"",
                                    severity="HIGH"
                                )
                        except Exception:
                            pass

                    # 3. Check Keystrokes & Build Word Stream
                    keys = self._scan_keystrokes()
                    if keys:
                        text_frag = "".join(keys)
                        self.keystroke_buffer.append(text_frag)
                        current_typing_word.append(text_frag)
                        last_typing_time = now

                        if self.state == "ARMED":
                            self.trigger_alarm(
                                reason=f"Keyboard Keystrokes Detected (\"{text_frag[:15]}\")",
                                severity="CRITICAL",
                                take_photo=True
                            )
                            last_photo_time = now

                        # If Enter or buffer exceeds threshold, flush word event immediately
                        if "[↵ Enter]" in text_frag or len("".join(current_typing_word)) >= 12:
                            flushed_word = "".join(current_typing_word)
                            self.log_event(
                                event_type="key_typed",
                                title=f"⌨️ Keystrokes Typed: \"{flushed_word.replace('[↵ Enter]', '')}\"",
                                details=f"Typed in {active_win['exe']} (\"{active_win['title'][:35]}\") | Raw: {flushed_word}",
                                severity="CRITICAL",
                                photo_url=self.last_photo_url if (now - last_photo_time > 10) else None
                            )
                            current_typing_word = []
                    
                    # Periodic flush of typed buffer after pause (0.9s pause)
                    elif current_typing_word and (now - last_typing_time > 0.9):
                        flushed_word = "".join(current_typing_word).strip()
                        if flushed_word:
                            self.log_event(
                                event_type="key_typed",
                                title=f"⌨️ Keystrokes Typed: \"{flushed_word}\"",
                                details=f"Typed in {active_win['exe']} (\"{active_win['title'][:35]}\")",
                                severity="CRITICAL"
                            )
                        current_typing_word = []

            except Exception as e:
                pass

            time.sleep(0.1)

    # -------------------------------------------------------------
    # Stealth Camera Capture (DirectShow 0ms freeze)
    # -------------------------------------------------------------
    def capture_stealth_photo(self):
        if self.camera_busy:
            return self.last_photo_url

        self.camera_busy = True
        photo_rel_url = None
        try:
            # OpenCV DirectShow
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            if not cap.isOpened():
                cap = cv2.VideoCapture(0)
            
            if cap.isOpened():
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                
                # Grab a few frames to let auto-exposure adjust
                ret = False
                frame = None
                for _ in range(3):
                    ret, frame = cap.read()
                    if ret:
                        break
                
                cap.release()
                
                if ret and frame is not None:
                    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
                    rand_id = hex(int(time.time() * 1000) % 0xFFFF)[2:].upper()
                    filename = f"photo_{timestamp_str}_{rand_id}.jpg"
                    filepath = os.path.join(CAPTURES_DIR, filename)
                    
                    # Save JPEG with Q=85
                    cv2.imwrite(filepath, frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
                    photo_rel_url = f"/static/sentry_captures/{filename}"
                    self.last_photo_url = photo_rel_url
        except Exception as e:
            print(f"[SentrySentinel] Camera error: {e}")
        finally:
            self.camera_busy = False

        return photo_rel_url

    # -------------------------------------------------------------
    # Volume Booster & Audio / Walkie-Talkie / TTS Engine
    # -------------------------------------------------------------
    def force_max_volume(self):
        try:
            # VK_VOLUME_UP = 0xAF
            for _ in range(50):
                user32.keybd_event(0xAF, 0, 0, 0)
                user32.keybd_event(0xAF, 0, 2, 0)
        except Exception:
            pass

    def speak_text(self, text, force_volume=True):
        if force_volume:
            self.force_max_volume()

        def _tts():
            try:
                # 1. Try SAPI via COM
                if win32com:
                    speaker = win32com.client.Dispatch("SAPI.SpVoice")
                    speaker.Speak(text)
                    return
            except Exception:
                pass

            # 2. PowerShell SpeechSynthesizer Fallback
            try:
                safe_txt = text.replace('"', ' ').replace("'", " ")
                cmd = f'powershell -c "Add-Type –AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Speak(\'{safe_txt}\')"'
                subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            except Exception:
                pass

        threading.Thread(target=_tts, daemon=True).start()

    def play_voice_shout(self, shout_index=1):
        shouts = {
            1: "Chor hai! Laptop chhod do turant! Step away from my laptop right now!",
            2: "Step away from my laptop right now! Security alert triggered!",
            3: "I see you on the camera! Leave my laptop immediately!",
            4: "Security Alert! Your photo and keystrokes have been sent to the police!"
        }
        text = shouts.get(int(shout_index), shouts[1])
        self.speak_text(text, force_volume=True)
        self.log_event(
            event_type="voice_shout",
            title=f"📢 Voice Warning Broadcasted (Preset #{shout_index})",
            details=f"Spoken at 100% Volume: \"{text}\"",
            severity="HIGH",
            take_photo=False
        )

    def play_intercom_audio(self, audio_bytes):
        self.force_max_volume()
        
        # Save temp WAV file and play asynchronously
        try:
            temp_wav = os.path.join(tempfile.gettempdir(), f"sentry_intercom_{int(time.time()*1000)}.wav")
            with open(temp_wav, "wb") as f:
                f.write(audio_bytes)
            
            if winsound:
                winsound.PlaySound(temp_wav, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                cmd = f'powershell -c "(New-Object Media.SoundPlayer \'{temp_wav}\').PlaySync()"'
                subprocess.Popen(cmd, shell=True)
                
            self.log_event(
                event_type="intercom_voice",
                title="🎙️ Live Intercom Voice Broadcasted",
                details="User spoke via phone walkie-talkie streamed directly to laptop speakers.",
                severity="HIGH",
                take_photo=False
            )
            return True
        except Exception as e:
            print(f"[SentrySentinel] Intercom play error: {e}")
            return False

    # -------------------------------------------------------------
    # Ghost Screen Live Capture & OSD Banner
    # -------------------------------------------------------------
    def capture_screen_frame(self, quality=60):
        try:
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            
            hdc_src = user32.GetDC(0)
            hdc_mem = gdi32.CreateCompatibleDC(hdc_src)
            hbmp = gdi32.CreateCompatibleBitmap(hdc_src, width, height)
            gdi32.SelectObject(hdc_mem, hbmp)
            gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_src, 0, 0, 0x00CC0020)
            
            bmi = bytearray(40)
            struct.pack_into('<IiiHHIIIIII', bmi, 0, 40, width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0)
            buf = bytearray(width * height * 4)
            gdi32.GetDIBits(hdc_mem, hbmp, 0, height, (ctypes.c_char * len(buf)).from_buffer(buf), (ctypes.c_char * len(bmi)).from_buffer(bmi), 0)
            
            img = Image.frombytes('RGBA', (width, height), bytes(buf), 'raw', 'BGRA').convert('RGB')
            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(0, hdc_src)
            
            # Resize slightly for ultra fast phone streaming
            if width > 1280:
                scale = 1280.0 / width
                img = img.resize((1280, int(height * scale)), Image.Resampling.BILINEAR)
                
            out = io.BytesIO()
            img.save(out, format='JPEG', quality=quality)
            return out.getvalue()
        except Exception as e:
            print(f"[SentrySentinel] Screen grab error: {e}")
            return None

    def show_screen_banner(self, message="INTRUDER ALERT: LAPTOP IS BEING MONITORED REMOTELY"):
        def _banner():
            try:
                # Topmost notification / banner dialog
                cmd = f'powershell -c "[System.Windows.Forms.MessageBox]::Show(\'{message}\', \'GUARDIAN SECURITY SENTINEL\', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)"'
                subprocess.Popen(cmd, shell=True)
            except Exception:
                pass
        threading.Thread(target=_banner, daemon=True).start()

    # -------------------------------------------------------------
    # Remote Laptop Workstation Controls
    # -------------------------------------------------------------
    def lock_workstation(self):
        try:
            user32.LockWorkStation()
            self.log_event(
                event_type="remote_lock",
                title="🔒 Laptop Workstation Locked Remotely",
                details="Windows session locked via mobile phone command.",
                severity="HIGH"
            )
            return True
        except Exception as e:
            return False

    def sleep_workstation(self):
        try:
            self.log_event(
                event_type="remote_sleep",
                title="💤 Laptop Put to Sleep Remotely",
                details="Suspension state requested via mobile phone command.",
                severity="HIGH"
            )
            subprocess.Popen("rundll32.exe powrprof.dll,SetSuspendState 0,1,0", shell=True)
            return True
        except Exception as e:
            return False

    def change_windows_password(self, new_password):
        new_pass = str(new_password).strip()
        if not new_pass:
            return False, "Password cannot be empty"

        username = os.environ.get("USERNAME", "")
        if not username:
            return False, "Could not determine local Windows username"

        try:
            # 1. Try net user
            res = subprocess.run(f'net user "{username}" "{new_pass}"', shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                self.lock_workstation()
                self.log_event(
                    event_type="password_changed",
                    title="🔑 Windows Account Password Changed Remotely",
                    details=f"Account password for user '{username}' changed and workstation locked.",
                    severity="CRITICAL"
                )
                return True, "Password successfully updated & workstation locked"
            else:
                # 2. ADSI PowerShell Fallback
                ps_cmd = f'$user = [ADSI]"WinNT://$env:COMPUTERNAME/$env:USERNAME,user"; $user.SetPassword("{new_pass}"); $user.SetInfo()'
                res2 = subprocess.run(f'powershell -c "{ps_cmd}"', shell=True, capture_output=True, text=True)
                if res2.returncode == 0:
                    self.lock_workstation()
                    return True, "Password updated via ADSI & workstation locked"
                return False, res.stderr or res2.stderr or "Requires Administrator privilege"
        except Exception as e:
            return False, str(e)

    def kill_active_app(self):
        try:
            info = self._get_active_window_info()
            pid = info["pid"]
            exe = info["exe"]
            
            if exe in PROTECTED_SYSTEM_APPS or pid <= 4:
                return False, f"Cannot terminate protected system process '{exe}'"

            proc = psutil.Process(pid)
            proc.terminate()
            
            self.log_event(
                event_type="app_terminated",
                title=f"🛑 Intruder App Terminated: {exe}",
                details=f"Killed process PID {pid} (Window: \"{info['title']}\")",
                severity="HIGH"
            )
            return True, f"Terminated process '{exe}' (PID {pid})"
        except Exception as e:
            return False, str(e)

    def toggle_siren(self, enable=None):
        if enable is None:
            self.is_siren_active = not self.is_siren_active
        else:
            self.is_siren_active = bool(enable)

        if self.is_siren_active:
            self.force_max_volume()
            if not self.siren_thread or not self.siren_thread.is_alive():
                self.siren_thread = threading.Thread(target=self._siren_loop, daemon=True, name="SirenWorker")
                self.siren_thread.start()
            self.log_event(
                event_type="siren_activated",
                title="🚨 Piercing Siren Alarm Activated",
                details="Oscillating warble alarm blasting at 100% speaker volume.",
                severity="CRITICAL"
            )
        else:
            self.stop_siren()
            self.log_event(
                event_type="siren_deactivated",
                title="🔇 Siren Alarm Muted",
                details="Alarm stopped by owner.",
                severity="LOW"
            )
        return self.is_siren_active

    def stop_siren(self):
        self.is_siren_active = False

    def _siren_loop(self):
        while self.is_siren_active and self.running:
            try:
                if winsound:
                    # High-low alternating siren frequencies
                    for freq in [2400, 1800, 3000, 2100, 3200]:
                        if not self.is_siren_active:
                            break
                        winsound.Beep(freq, 160)
                else:
                    time.sleep(0.3)
            except Exception:
                time.sleep(0.5)

    def toggle_lockdown(self, enable=None):
        if enable is None:
            self.is_lockdown_active = not self.is_lockdown_active
        else:
            self.is_lockdown_active = bool(enable)

        if self.is_lockdown_active:
            self.launch_lockdown_shield()
            self.log_event(
                event_type="lockdown_enabled",
                title="🛡️ Emergency Lockdown Blackout Shield Active",
                details="Fullscreen pitch blackout barrier deployed on laptop screen. Requires 4-digit PIN or phone remote to release.",
                severity="CRITICAL"
            )
        else:
            self.dismiss_lockdown_shield()
            self.log_event(
                event_type="lockdown_disabled",
                title="🔓 Emergency Lockdown Shield Dismissed",
                details="Blackout barrier unlocked and workstation restored.",
                severity="LOW"
            )
        return self.is_lockdown_active

    def launch_lockdown_shield(self):
        if self.lockdown_process and self.lockdown_process.poll() is None:
            return  # Already active

        try:
            if getattr(sys, "frozen", False):
                cmd = [sys.executable, "--lockdown"]
            else:
                guardian_py = os.path.join(BASE_DIR, "GUARDIAN.py")
                if os.path.exists(guardian_py):
                    cmd = [sys.executable, guardian_py, "--lockdown"]
                else:
                    cmd = [sys.executable, "-c", "import sentry_sentinel; sentry_sentinel.run_fullscreen_lockdown_shield()"]
            
            flags = 0
            self.lockdown_process = subprocess.Popen(cmd, creationflags=flags)
        except Exception as e:
            print(f"[SentrySentinel] Lockdown launch error: {e}")

    def dismiss_lockdown_shield(self):
        self.is_lockdown_active = False
        if self.lockdown_process:
            try:
                self.lockdown_process.terminate()
                self.lockdown_process = None
            except Exception:
                pass

    # -------------------------------------------------------------
    # Logging & Forensic Dossier
    # -------------------------------------------------------------
    def log_event(self, event_type, title, details, severity="MEDIUM", photo_url=None, take_photo=False):
        if take_photo and not photo_url:
            photo_url = self.capture_stealth_photo()

        event = {
            "id": f"EVT-{int(time.time()*1000)%1000000}",
            "type": event_type,
            "title": title,
            "details": details,
            "severity": severity,
            "photo_url": photo_url,
            "timestamp": time.strftime("%I:%M:%S %p"),
            "date": time.strftime("%Y-%m-%d"),
            "epoch": time.time()
        }
        
        self.recent_events.appendleft(event)
        self._save_events()
        return event

    def clear_events(self):
        self.recent_events.clear()
        self.keystroke_buffer.clear()
        self._save_events()

    def _save_events(self):
        try:
            with open(EVENTS_FILE, "w", encoding="utf-8") as f:
                json.dump(list(self.recent_events)[:100], f, indent=2)
        except Exception:
            pass

    def _load_events(self):
        if os.path.exists(EVENTS_FILE):
            try:
                with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in reversed(data):
                        self.recent_events.appendleft(item)
            except Exception:
                pass

    def generate_dossier(self):
        events_list = list(self.recent_events)
        raw_telemetry = json.dumps(events_list, sort_keys=True)
        sha256_seal = hashlib.sha256(raw_telemetry.encode("utf-8")).hexdigest()

        critical_count = sum(1 for e in events_list if e.get("severity") == "CRITICAL")
        high_count = sum(1 for e in events_list if e.get("severity") == "HIGH")
        
        if critical_count > 0:
            threat_level = "CRITICAL BREACH ATTEMPT"
        elif high_count > 0:
            threat_level = "HIGH-RISK PHYSICAL ACCESS"
        else:
            threat_level = "ELEVATED ANOMALY"

        photos = [e["photo_url"] for e in events_list if e.get("photo_url")]

        return {
            "dossier_id": self.dossier_id,
            "generated_at": time.strftime("%Y-%m-%d %I:%M:%S %p"),
            "sha256_seal": sha256_seal,
            "threat_level": threat_level,
            "total_events": len(events_list),
            "critical_events": critical_count,
            "keystrokes_captured": "".join(self.keystroke_buffer),
            "photos": photos,
            "events": events_list
        }

    def get_state(self):
        with self.lock:
            state = self.state
            remaining = self.arming_remaining
            reason = self.triggered_reason

        return {
            "state": state,
            "is_armed": state in ["ARMED", "TRIGGERED"],
            "arming_remaining": remaining,
            "triggered_reason": reason,
            "pin": self.pin,
            "lan_ip": self.lan_ip,
            "host_url": f"http://{self.lan_ip}:{self.port}",
            "remote_url": self.get_remote_url(),
            "is_lockdown_active": self.is_lockdown_active,
            "is_siren_active": self.is_siren_active,
            "last_photo_url": self.last_photo_url,
            "events": list(self.recent_events)[:50]
        }

    def test_demo_intruder(self):
        # Simulates a full realistic intruder action sequence
        photo = self.capture_stealth_photo()
        self.keystroke_buffer.append("victim_user@gmail.com | Secret#Pass2026")
        
        self.trigger_alarm(reason="Demo Intruder Simulation Test", severity="CRITICAL", take_photo=False)
        self.log_event(
            event_type="app_opened",
            title="🪟 App Opened / Focused: msedge.exe",
            details="Active Window: \"Gmail - Inbox • Personal Mail\" [PID: 10424]",
            severity="HIGH",
            photo_url=photo
        )
        self.log_event(
            event_type="key_typed",
            title="⌨️ Keystrokes Typed: \"victim_user@gmail.com\"",
            details="Typed in msedge.exe (\"Gmail - Login / Sign in\")",
            severity="CRITICAL",
            photo_url=photo
        )
        self.log_event(
            event_type="mouse_click",
            title="🖱️ Mouse Left Click in msedge.exe",
            details="Clicked at (540, 480) on \"Password field • Sign in\"",
            severity="HIGH"
        )
        self.log_event(
            event_type="key_typed",
            title="⌨️ Keystrokes Typed: \"Secret#Pass2026\"",
            details="Typed in msedge.exe (\"Password Input Field\")",
            severity="CRITICAL"
        )
        self.log_event(
            event_type="app_opened",
            title="🪟 App Opened / Focused: notepad.exe",
            details="Active Window: \"passwords_backup.txt - Notepad\" [PID: 8812]",
            severity="HIGH"
        )
        self.log_event(
            event_type="mouse_moved",
            title="🖱️ Mouse / Touchpad Moved",
            details="Cursor moved from (120, 340) to (890, 720) in notepad.exe",
            severity="MEDIUM"
        )
        return True


# =============================================================
# STANDALONE FULLSCREEN BLACKOUT SHIELD PROCESS
# =============================================================
def run_fullscreen_lockdown_shield():
    """
    Impenetrable fullscreen blackout barrier on Windows laptop screen.
    Turns screen 100% pitch black, blocks intruder interactions, stays topmost,
    and allows unlock via 4-digit Owner PIN or Phone Remote Controller.
    """
    import tkinter as tk
    import urllib.request
    import json

    pin = "6584"
    if os.path.exists(PIN_FILE):
        try:
            with open(PIN_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if "pin" in d:
                    pin = str(d["pin"])
        except Exception:
            pass

    root = tk.Tk()
    root.title("GUARDIAN EMERGENCY LOCKDOWN")
    root.configure(bg="#000000")
    root.attributes("-fullscreen", True)
    root.attributes("-topmost", True)
    root.overrideredirect(True)

    # Cover full virtual screen across multi-monitors if available
    try:
        vx = user32.GetSystemMetrics(76) # SM_XVIRTUALSCREEN
        vy = user32.GetSystemMetrics(77) # SM_YVIRTUALSCREEN
        vw = user32.GetSystemMetrics(78) # SM_CXVIRTUALSCREEN
        vh = user32.GetSystemMetrics(79) # SM_CYVIRTUALSCREEN
        if vw > 0 and vh > 0:
            root.geometry(f"{vw}x{vh}+{vx}+{vy}")
    except Exception:
        pass

    # Force topmost loop
    def keep_top():
        try:
            root.lift()
            root.attributes("-topmost", True)
            try:
                hwnd = root.winfo_id()
                user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0040)
            except Exception:
                pass
            root.after(200, keep_top)
        except Exception:
            pass
    keep_top()

    # Block special system keys
    def block_key(e):
        return "break"
    root.bind("<Alt-F4>", block_key)
    root.bind("<Escape>", block_key)
    root.bind("<Tab>", block_key)

    # Blackout Shield Container
    frame = tk.Frame(root, bg="#000000")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    lbl_icon = tk.Label(frame, text="🔒", font=("Segoe UI Emoji", 56), bg="#000000", fg="#FF3366")
    lbl_icon.pack(pady=6)

    lbl_title = tk.Label(frame, text="EMERGENCY BLACKOUT LOCKDOWN", font=("Helvetica", 24, "bold"), bg="#000000", fg="#FF3366")
    lbl_title.pack(pady=4)

    lbl_sub = tk.Label(
        frame,
        text="This laptop has been remotely locked and blacked out by the owner.\nIntruder actions, webcam captures and keystrokes are being recorded.",
        font=("Helvetica", 11),
        bg="#000000",
        fg="#94A3B8",
        justify="center"
    )
    lbl_sub.pack(pady=10)

    entry_pin = tk.Entry(
        frame,
        font=("Courier", 22, "bold"),
        justify="center",
        show="*",
        width=8,
        bg="#0A1120",
        fg="#00E5FF",
        insertbackground="#00E5FF",
        relief="flat",
        highlightthickness=2,
        highlightbackground="#00E5FF",
        highlightcolor="#FF3366"
    )
    entry_pin.pack(pady=12)
    entry_pin.focus_force()

    lbl_err = tk.Label(frame, text="", font=("Helvetica", 11, "bold"), bg="#000000", fg="#FF3366")
    lbl_err.pack(pady=4)

    def unlock_action(event=None):
        entered = entry_pin.get().strip()
        # Verify PIN against backend
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:5000/api/sentry/verify_pin",
                data=json.dumps({"pin": entered}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=2)
            data = json.loads(resp.read().decode())
            is_valid = data.get("success", False)
        except Exception:
            is_valid = (entered == pin)

        if is_valid:
            try:
                # Notify backend to disable lockdown
                req = urllib.request.Request(
                    "http://127.0.0.1:5000/api/sentry/action",
                    data=json.dumps({"action": "toggle_lockdown", "enable": False, "pin": entered}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass
            root.destroy()
            sys.exit(0)
        else:
            lbl_err.config(text="❌ INCORRECT PIN — INTRUDER PHOTO CAPTURED")
            entry_pin.delete(0, tk.END)
            try:
                # Trigger photo on failed pin
                req = urllib.request.Request(
                    "http://127.0.0.1:5000/api/sentry/action",
                    data=json.dumps({"action": "snap_photo"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                pass

    entry_pin.bind("<Return>", unlock_action)

    btn_unlock = tk.Button(
        frame,
        text="UNLOCK WORKSTATION",
        font=("Helvetica", 11, "bold"),
        bg="#4F46E5",
        fg="#FFFFFF",
        padx=24,
        pady=8,
        borderwidth=0,
        cursor="hand2",
        activebackground="#4338CA",
        activeforeground="#FFFFFF",
        command=unlock_action
    )
    btn_unlock.pack(pady=10)

    # Periodic poll: If owner disarmed or disabled lockdown via mobile phone, close shield!
    def poll_remote_state():
        try:
            req = urllib.request.Request("http://127.0.0.1:5000/api/sentry/state")
            resp = urllib.request.urlopen(req, timeout=1)
            data = json.loads(resp.read().decode())
            if not data.get("is_lockdown_active", True):
                root.destroy()
                sys.exit(0)
        except Exception:
            pass
        root.after(600, poll_remote_state)

    poll_remote_state()
    root.mainloop()


# Global Singleton Instance
sentinel_engine = SentrySentinel()

