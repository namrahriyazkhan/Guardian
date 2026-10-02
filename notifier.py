"""
notifier.py — Security Alert Notifier  (PyQt5 edition)
=======================================================
INSTALL:   pip install PyQt5 pygame requests flask

CHANGES FROM ORIGINAL:
  • Every popup button click (Ignore/Ack/Snooze/Block/Kill/Trust)
    → automatically calls POST /api/killchain/add on app.py
  • Kill Chain event includes: app, action, reasons, severity, source="notifier"
  • Ignore counter still tracks critical escalation (unchanged)
  • Everything else (UI, sounds, dashboard sync) unchanged
"""

import sys, os, time, random, threading, json
import requests
from flask import Flask, jsonify, request

# Ensure UTF-8 output encoding on Windows console/pipes to prevent UnicodeEncodeError with emoji prints
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QPushButton,
                              QVBoxLayout, QHBoxLayout, QFrame, QProgressBar)
from PyQt5.QtCore    import (Qt, QTimer, QPropertyAnimation, QRect,
                              QEasingCurve, pyqtSignal, QObject,
                              QThread, pyqtSlot)
from PyQt5.QtGui     import QPainter, QColor, QPen, QLinearGradient, QFont, QPixmap, QPainterPath, QBrush
import datetime

# ═══════════════════════════════════════════════════════════════════════
#  SOUND
# ═══════════════════════════════════════════════════════════════════════
if getattr(sys, "frozen", False):
    _SCRIPT_DIR = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
else:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_sound_candidates = [
    os.path.join(_SCRIPT_DIR, "alert_beep.wav"),
    os.path.join(_SCRIPT_DIR, "static", "alert_beep.wav"),
    os.path.join(_SCRIPT_DIR, "freesound_community-beep-6-96243.mp3"),
    os.path.join(_SCRIPT_DIR, "static", "freesound_community-beep-6-96243.mp3"),
]
SOUND_FILE = next((p for p in _sound_candidates if os.path.exists(p)), _sound_candidates[0])

_pygame_ok = False
_sound_obj = None
try:
    import pygame
    pygame.mixer.pre_init(44100, -16, 2, 512)
    pygame.mixer.init()
    if os.path.exists(SOUND_FILE):
        _sound_obj = pygame.mixer.Sound(SOUND_FILE)
        _pygame_ok = True
        print(f"[Notifier] ✅ Sound loaded: {SOUND_FILE}")
except Exception as e:
    print(f"[Notifier] Pygame sound notice ({e}) — will use Windows system audio fallback")

def play_beep():
    if _pygame_ok and _sound_obj:
        try:
            _sound_obj.stop()
            _sound_obj.play()
            return
        except Exception:
            pass
    try:
        import winsound
        if os.path.exists(SOUND_FILE) and SOUND_FILE.endswith(".wav"):
            winsound.PlaySound(SOUND_FILE, winsound.SND_ASYNC | winsound.SND_FILENAME)
        else:
            winsound.Beep(880, 200)
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════
FLASK_BASE    = "http://127.0.0.1:5000"
POLL_INTERVAL = 4
AUTO_CLOSE_MS = 12000
W, H          = 460, 340
TRIGGER_PORT  = 5001

# ═══════════════════════════════════════════════════════════════════════
#  ATTACK TRIGGER FLAG (Active by default for continuous threat notifications)
# ═══════════════════════════════════════════════════════════════════════
_attack_active = True
_attack_lock   = threading.Lock()

# ═══════════════════════════════════════════════════════════════════════
#  IGNORE COUNTER FOR CRITICAL ESCALATION
# ═══════════════════════════════════════════════════════════════════════
_ignore_counter      = 0
_ignore_counter_lock = threading.Lock()
_ignored_app_names   = []
CRITICAL_THRESHOLD   = 3
AUTO_PAUSE_THRESHOLD = 3

def _increment_ignore(app_name):
    global _ignore_counter, _ignored_app_names
    with _ignore_counter_lock:
        _ignore_counter += 1
        if app_name not in _ignored_app_names:
            _ignored_app_names.append(app_name)
        current_count  = _ignore_counter
        ignored_names  = list(_ignored_app_names)

    print(f"[Notifier] ⚠  Ignore #{current_count} — App: {app_name}")
    if current_count == AUTO_PAUSE_THRESHOLD:
        threading.Thread(
            target=_show_auto_pause_popup,
            args=(app_name,),
            daemon=True
        ).start()

    if current_count >= CRITICAL_THRESHOLD:
        threading.Thread(
            target=_call_critical_escalation,
            args=(current_count, ignored_names),
            daemon=True
        ).start()

def _call_critical_escalation(count, ignored_names):
    try:
        payload = {
            "ignored_count": count,
            "ignored_apps":  ignored_names,
            "fatigue_score": count * 3.0,
        }
        r = requests.post(FLASK_BASE + "/critical_escalation", json=payload, timeout=3)
        print(f"[Notifier] 🚨 Critical escalation sent! Response: {r.status_code}")
    except Exception as e:
        print(f"[Notifier] ❌ Critical escalation call failed: {e}")
def _show_auto_pause_popup(app_name):
    time.sleep(1)
    try:
        res = requests.get(FLASK_BASE + "/get_report", timeout=3).json()
        all_apps = res.get("high_risk", []) + res.get("suspicious", [])
        reasons = []
        for obj in all_apps:
            if obj.get("app", "").lower() == app_name.lower():
                reasons = obj.get("reasons", [])
                break
        if not reasons:
            reasons = ["Repeated alert ignores detected", "Automatic protection activated"]
        print(f"[Notifier] ⏸ Showing auto pause for: {app_name}")
        bridge.show_pause.emit(app_name, reasons)
    except Exception as e:
        print(f"[Notifier] Auto pause popup error: {e}")

# ═══════════════════════════════════════════════════════════════════════
#  ── NEW: KILL CHAIN EVENT LOGGER ─────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════
def _log_kill_chain_event(app_name, action, reasons, severity):
    """
    POST to app.py /api/killchain/add after every popup button click.
    Non-blocking (runs in daemon thread).
    """
    def _do_post():
        try:
            payload = {
                "app":      app_name,
                "action":   action,
                "reasons":  reasons,
                "severity": severity,
                "source":   "notifier",
            }
            r = requests.post(
                FLASK_BASE + "/api/killchain/add",
                json=payload,
                timeout=3
            )
            data = r.json()
            tactic = data.get("event", {}).get("tactic", "?")
            print(f"[Notifier] 🔗 Kill Chain → [{tactic}] {app_name} / {action}")
        except Exception as e:
            print(f"[Notifier] ⚠  Kill chain log failed: {e}")

    threading.Thread(target=_do_post, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════════
#  ALERT POOLS
# ═══════════════════════════════════════════════════════════════════════
HIGH_RISK_POOL = [
    {"app": "trojan.exe",        "reasons": ["⚠ Behavior violation: Running at unusual time", "Thread explosion detected"],               "severity": 92},
    {"app": "keylogger.exe",     "reasons": ["Keystroke capture detected", "Hidden process — not in task list"],                          "severity": 95},
    {"app": "ransomware.exe",    "reasons": ["Mass file encryption started", "Shadow copy deletion attempt"],                              "severity": 98},
    {"app": "rootkit.dll",       "reasons": ["Kernel memory injection detected", "AV process termination attempt"],                        "severity": 90},
    {"app": "cryptominer.exe",   "reasons": ["CPU pegged at 99% continuously", "Outbound connection to mining pool"],                      "severity": 85},
    {"app": "spyware.exe",       "reasons": ["Screen capture every 5 s", "Clipboard snooping detected"],                                   "severity": 88},
    {"app": "backdoor.exe",      "reasons": ["Reverse shell spawned on port 4444", "Persistence via registry Run key"],                    "severity": 94},
    {"app": "worm.exe",          "reasons": ["LAN scan on 192.168.x.x", "Self-replicating to network shares"],                             "severity": 91},
    {"app": "malware.exe",       "reasons": ["Injected into explorer.exe", "Deleted own original file after launch"],                      "severity": 89},
    {"app": "exploit_kit.exe",   "reasons": ["CVE-2024-1234 exploitation attempt", "Privilege escalation via token impersonation"],        "severity": 96},
]

SUSPICIOUS_POOL = [
    {"app": "weird_script.exe",  "reasons": ["ML anomaly detected", "CPU spike (85% vs normal 10%)"],                                     "severity": 58},
    {"app": "svchost32.exe",     "reasons": ["Impersonating svchost.exe", "Unusual parent process: cmd.exe"],                              "severity": 62},
    {"app": "updater_fake.exe",  "reasons": ["Connects to unknown IP 45.33.32.156", "No digital signature"],                              "severity": 55},
    {"app": "psexec_copy.exe",   "reasons": ["Lateral movement tool signature", "Admin share access attempt"],                             "severity": 70},
    {"app": "powershell_enc.exe","reasons": ["Base64 encoded command detected", "Downloaded 3 MB from pastebin.com"],                      "severity": 65},
    {"app": "rundll_hook.exe",   "reasons": ["DLL hijacking path found", "Unsigned DLL loaded into trusted process"],                      "severity": 60},
    {"app": "netcat.exe",        "reasons": ["Raw TCP listener on port 1337", "Unusual outbound traffic pattern"],                         "severity": 57},
    {"app": "mimikatz_mod.exe",  "reasons": ["LSASS memory read attempt", "Credential dump pattern matched"],                              "severity": 75},
    {"app": "browser_ext.exe",   "reasons": ["Intercepting HTTPS traffic", "Injected into Chrome renderer process"],                      "severity": 53},
    {"app": "macro_runner.exe",  "reasons": ["Office macro spawned shell", "Child process: cmd.exe /c powershell"],                        "severity": 68},
]

_hr_idx  = 0
_sus_idx = 0

def _next_diverse_alerts():
    global _hr_idx, _sus_idx
    hr_obj  = dict(HIGH_RISK_POOL[_hr_idx  % len(HIGH_RISK_POOL)])
    sus_obj = dict(SUSPICIOUS_POOL[_sus_idx % len(SUSPICIOUS_POOL)])
    _hr_idx  += 1
    _sus_idx += 1
    return {"high_risk": [hr_obj], "suspicious": [sus_obj]}

# ═══════════════════════════════════════════════════════════════════════
#  FLASK API HELPERS
# ═══════════════════════════════════════════════════════════════════════
def call_api(path, method="GET", payload=None):
    try:
        if method == "POST":
            r = requests.post(FLASK_BASE + path, json=payload, timeout=3)
        else:
            r = requests.get(FLASK_BASE + path, timeout=3)
        return r.json()
    except Exception as e:
        print(f"[Notifier] API error {path}: {e}")
        return {}

def enc(s):
    return requests.utils.quote(str(s), safe="")

def push_dashboard_update(app_name, risk, action, reasons, severity):
    e = enc(app_name)
    call_api(f"/respond/{e}/{action}")
    if action == "block":
        call_api(f"/block/{e}")
    elif action == "kill":
        call_api(f"/kill/{e}")
    elif action == "trust":
        call_api(f"/trust/{e}")

    level     = "High" if "HIGH" in risk else "Medium" if severity >= 60 else "Low"
    new_entry = {
        "app":     app_name,
        "reasons": reasons,
        "severity": severity,
        "level":   level,
        "action":  action,
        "time":    time.strftime("%H:%M:%S"),
    }
    call_api("/update_report", method="POST", payload={
        "running":    [app_name],
        "suspicious": [new_entry] if level != "High" else [],
        "high_risk":  [new_entry] if level == "High"  else [],
        "profile_summary": {
            app_name: {
                "avg_cpu":    round(random.uniform(5, 90), 1),
                "avg_mem":    round(random.uniform(10, 200), 1),
                "run_count":  random.randint(1, 20),
                "last_action": action,
                "confidence": round(random.uniform(0.6, 0.99), 2),
                "level":      level,
            }
        },
    })
    print(f"[Notifier] ✅ Dashboard updated → {app_name} / {action} / {level}")

# ═══════════════════════════════════════════════════════════════════════
#  COLOR PALETTE
# ═══════════════════════════════════════════════════════════════════════
C = {
    "bg":        "#0d1117",
    "hdr":       "#080b10",
    "content":   "#0d1117",
    "reasons_bg":"#080b10",
    "sep":       "#141c26",
    "fg":        "#c0c8d8",
    "muted":     "#6b7a8d",
    "red":       "#e5534b",
    "amber":     "#f5a623",
    "ign_bg":    "#111827",   "ign_fg":  "#8a9bb0",
    "ack_bg":    "#0d3320",   "ack_fg":  "#22c55e",
    "snz_bg":    "#2d1f07",   "snz_fg":  "#f59e0b",
    "blk_bg":    "#2d0a0a",   "blk_fg":  "#ef4444",
    "kil_bg":    "#3d0f0f",   "kil_fg":  "#fca5a5",
    "trs_bg":    "#0a1a3d",   "trs_fg":  "#60a5fa",
}

def _hex_to_rgb(h):
    h = h.lstrip("#")
    return int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)

def lighten(hex_color, amt=30):
    r,g,b = _hex_to_rgb(hex_color)
    return f"#{min(255,r+amt):02x}{min(255,g+amt):02x}{min(255,b+amt):02x}"

# ═══════════════════════════════════════════════════════════════════════
#  SIGNAL BRIDGE
# ═══════════════════════════════════════════════════════════════════════
class _Bridge(QObject):
    show_alert      = pyqtSignal(str, str, list, int)
    show_pause      = pyqtSignal(str, list)
    show_bundle     = pyqtSignal(list, int)
    show_peripheral = pyqtSignal(str, str, str, str, str)

bridge = _Bridge()

# ═══════════════════════════════════════════════════════════════════════
#  CIRCULAR RISK GAUGE WIDGET (Option B VisionOS Crystal Design)
# ═══════════════════════════════════════════════════════════════════════
class CircularRiskGauge(QWidget):
    def __init__(self, severity, is_high=True, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.is_high  = is_high
        self.setFixedSize(92, 92)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        rect = QRect(8, 8, 76, 76)

        if self.is_high:
            track_color = QColor(255, 255, 255, 22)
            glow_color  = QColor(255, 59, 78, 65)
            arc_color   = QColor(255, 59, 78)
            sub_color   = QColor(255, 95, 115)
        else:
            track_color = QColor(255, 255, 255, 22)
            glow_color  = QColor(245, 166, 35, 65)
            arc_color   = QColor(245, 166, 35)
            sub_color   = QColor(245, 185, 70)

        start_angle = 225 * 16
        span_total  = -270 * 16

        # Background track
        pen_track = QPen(track_color, 4.5, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_track)
        painter.drawArc(rect, start_angle, span_total)

        # Dynamic glowing arc
        frac = max(0.05, min(1.0, self.severity / 100.0))
        span_val = int(span_total * frac)

        # Outer soft glow
        pen_glow = QPen(glow_color, 9.0, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_glow)
        painter.drawArc(rect, start_angle, span_val)

        # Bright sharp arc
        pen_arc = QPen(arc_color, 4.5, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen_arc)
        painter.drawArc(rect, start_angle, span_val)

        # Center Text: Percentage & Risk Label
        painter.setPen(QColor(255, 255, 255))
        font_pct = QFont("Segoe UI", 13, QFont.Bold)
        painter.setFont(font_pct)
        painter.drawText(QRect(0, 22, 92, 24), Qt.AlignCenter, f"{self.severity}%")

        painter.setPen(sub_color)
        font_sub = QFont("Segoe UI", 6, QFont.Bold)
        font_sub.setLetterSpacing(QFont.AbsoluteSpacing, 0.5)
        painter.setFont(font_sub)
        lbl_text = "HIGH RISK" if self.is_high else "SUSPICIOUS"
        painter.drawText(QRect(0, 46, 92, 16), Qt.AlignCenter, lbl_text)
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
#  GLOWING BEACON DOT WIDGET
# ═══════════════════════════════════════════════════════════════════════
class GlowingBeaconDot(QWidget):
    def __init__(self, is_high=True, parent=None):
        super().__init__(parent)
        self.is_high = is_high
        self.setFixedSize(20, 20)
        self._on = True

    def set_state(self, on):
        self._on = on
        self.update()

    def paintEvent(self, event):
        if not self._on:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        c = QColor(255, 59, 48) if self.is_high else QColor(245, 166, 35)

        # Outer soft halo
        halo = QColor(c.red(), c.green(), c.blue(), 65)
        painter.setPen(Qt.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(1, 1, 18, 18)

        # Core bright dot
        painter.setBrush(c)
        painter.drawEllipse(4, 4, 12, 12)
        painter.end()


# ═══════════════════════════════════════════════════════════════════════
#  POPUP WIDGET — OPTION B (VISIONOS FROSTED CRYSTAL GLASS)
# ═══════════════════════════════════════════════════════════════════════
W, H = 470, 395

class AlertPopup(QWidget):

    def __init__(self, app_name, risk, reasons, severity):
        super().__init__()
        self.app_name  = app_name
        self.risk      = risk
        self.reasons   = reasons
        self.severity  = severity
        self.is_high   = "HIGH" in risk
        self.rc        = C["red"] if self.is_high else C["amber"]
        self.risk_lbl  = "HIGH RISK" if self.is_high else "SUSPICIOUS"
        self._countdown = AUTO_CLOSE_MS // 1000

        # Load Logo for Header and Background Watermark
        logo_path = os.path.join(getattr(sys, "_MEIPASS", _SCRIPT_DIR), "static", "guardian_logo.png")
        if not os.path.exists(logo_path):
            logo_path = os.path.join(_SCRIPT_DIR, "static", "guardian_logo.png")
        self._logo_pixmap = QPixmap(logo_path) if os.path.exists(logo_path) else None

        self._build_ui()
        self._position_and_slide()
        self._start_timers()
        play_beep()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        path = QPainterPath()
        path.addRoundedRect(1.0, 1.0, float(self.width() - 2.0), float(self.height() - 2.0), 22.0, 22.0)

        # Deep obsidian translucent frosted crystal background
        grad = QLinearGradient(0, 0, self.width(), self.height())
        grad.setColorAt(0.0, QColor(16, 20, 30, 245))
        grad.setColorAt(0.5, QColor(12, 16, 24, 248))
        grad.setColorAt(1.0, QColor(8, 11, 18, 252))
        painter.fillPath(path, QBrush(grad))

        # Background Watermark: Guardian Phoenix Crystal Logo
        if self._logo_pixmap and not self._logo_pixmap.isNull():
            painter.save()
            painter.setClipPath(path)
            painter.setOpacity(0.18)
            wm_size = 250
            wm_x = self.width() - wm_size + 15
            wm_y = (self.height() - wm_size) // 2 + 15
            painter.drawPixmap(wm_x, wm_y, wm_size, wm_size, self._logo_pixmap)
            painter.restore()

        # Subtle luminous frosted glass border
        border_pen = QPen(QColor(255, 255, 255, 38), 1.2)
        painter.strokePath(path, border_pen)
        painter.end()

    def _build_ui(self):
        self.setFixedSize(W, H)
        self.setWindowFlags(Qt.FramelessWindowHint |
                            Qt.WindowStaysOnTopHint |
                            Qt.Tool |
                            Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(8)

        # ── 1. HEADER (Official Guardian Shield Logo + Guardian Security Alert + Live Beacon + Close) ──
        hl = QHBoxLayout()
        hl.setContentsMargins(2, 0, 2, 0)
        hl.setSpacing(10)

        # Top-Left Official 3D Crystalline Guardian Logo
        logo_lbl = QLabel()
        if self._logo_pixmap and not self._logo_pixmap.isNull():
            logo_lbl.setPixmap(self._logo_pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo_lbl.setText("🛡️")
            logo_lbl.setStyleSheet("font-size: 16pt;")
        logo_lbl.setFixedSize(40, 40)
        hl.addWidget(logo_lbl)

        # Title: Guardian Security Alert
        title_hdr = QLabel("Guardian Security Alert")
        title_hdr.setStyleSheet("color: #FFFFFF; font-size: 13.5pt; font-weight: 700; font-family: 'Segoe UI', sans-serif; letter-spacing: -0.01em;")
        hl.addWidget(title_hdr)

        # Pulsing Red Beacon Dot next to title
        self._live_beacon = GlowingBeaconDot(self.is_high)
        hl.addWidget(self._live_beacon)

        hl.addStretch()

        # Circular Frosted Close Button
        x_btn = QPushButton("✕")
        x_btn.setFixedSize(28, 28)
        x_btn.setFocusPolicy(Qt.NoFocus)
        x_btn.setCursor(Qt.PointingHandCursor)
        x_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.08);
                color: #94A3B8;
                font-size: 9.5pt;
                font-weight: bold;
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 14px;
                padding: 0;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.22);
                color: #FFFFFF;
                border-color: rgba(255, 255, 255, 0.35);
            }
        """)
        x_btn.clicked.connect(self.close)
        hl.addWidget(x_btn)
        root.addLayout(hl)

        # ── 2. THREAT CARD CAPSULE (Frosted Glass Container with Circular Gauge & Metadata) ──
        threat_card = QFrame()
        threat_card.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.045);
                border: 1px solid rgba(255, 255, 255, 0.09);
                border-radius: 16px;
            }
        """)
        cl = QVBoxLayout(threat_card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(8)

        # Top section: Circular Arc Risk Gauge + Threat Title & Reason Pills
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        # Left: Circular Arc Risk Gauge
        gauge = CircularRiskGauge(self.severity, self.is_high)
        top_row.addWidget(gauge)

        # Right: App Name + Reason capsules
        right_info = QVBoxLayout()
        right_info.setSpacing(5)

        self.app_lbl = QLabel(self.app_name)
        self.app_lbl.setStyleSheet("color: #FFFFFF; font-size: 14.5pt; font-weight: 800; font-family: 'Segoe UI', sans-serif;")
        right_info.addWidget(self.app_lbl)

        # Frosted Reason Capsules
        lines = self.reasons[:2] if self.reasons else ["Suspicious activity detected"]
        for line in lines:
            clean_line = line.replace("⚠ Behavior violation: ", "")
            r_box = QLabel(clean_line)
            r_box.setStyleSheet("""
                QLabel {
                    background: rgba(255, 255, 255, 0.07);
                    border: 1px solid rgba(255, 255, 255, 0.09);
                    border-radius: 9px;
                    color: #D1D5DB;
                    font-size: 8.5pt;
                    font-family: 'Segoe UI', sans-serif;
                    padding: 3px 10px;
                }
            """)
            right_info.addWidget(r_box)

        top_row.addLayout(right_info, 1)
        cl.addLayout(top_row)

        # Divider Line
        div = QFrame()
        div.setStyleSheet("background: rgba(255, 255, 255, 0.08); max-height: 1px; min-height: 1px; border: none;")
        cl.addWidget(div)

        # Bottom section: Process ID & Location Path
        meta_layout = QVBoxLayout()
        meta_layout.setSpacing(3)

        # Derive realistic PID and Location
        pid_val = random.randint(10200, 28900)
        proc_lbl = QLabel(f"Process: {pid_val}")
        proc_lbl.setStyleSheet("color: #8E95A5; font-size: 8.5pt; font-family: 'Segoe UI', sans-serif; background: transparent; border: none;")
        meta_layout.addWidget(proc_lbl)

        loc_val = r"C:\Users\User\AppData..."
        loc_lbl = QLabel(f"Location: {loc_val}")
        loc_lbl.setStyleSheet("color: #8E95A5; font-size: 8.5pt; font-family: 'Segoe UI', sans-serif; background: transparent; border: none;")
        meta_layout.addWidget(loc_lbl)

        cl.addLayout(meta_layout)
        root.addWidget(threat_card)

        # ── 3. LIVE PROGRESS BAR (Auto-closing countdown) ──
        self.pbar = QProgressBar()
        self.pbar.setRange(0, 1000)
        self.pbar.setValue(1000)
        self.pbar.setTextVisible(False)
        self.pbar.setStyleSheet("""
            QProgressBar {
                border: none;
                background: rgba(255, 255, 255, 0.12);
                border-radius: 2px;
                max-height: 4px; min-height: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #E2E8F0, stop:1 #94A3B8);
                border-radius: 2px;
            }
        """)
        root.addWidget(self.pbar)

        # ── 4. 2x3 ACTION BUTTONS GRID (Option B Frosted Glass & Glowing Accents) ──
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(7)

        def mk(label, act, style_qss):
            b = QPushButton(label)
            b.setFocusPolicy(Qt.NoFocus)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(style_qss)
            b.clicked.connect(lambda _, a=act: self._action(a))
            return b

        row1 = QHBoxLayout()
        row1.setSpacing(7)
        row1.addWidget(mk("Ignore", "ignore", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.14), stop:1 rgba(255,255,255,0.06));
                color: #E2E8F0;
                border: 1px solid rgba(255, 255, 255, 0.18);
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 600;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.22), stop:1 rgba(255,255,255,0.10));
                color: #FFFFFF;
                border-color: rgba(255, 255, 255, 0.35);
            }
        """))
        row1.addWidget(mk("Acknowledge", "ack", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.20), stop:1 rgba(255,255,255,0.08));
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.28);
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 600;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.30), stop:1 rgba(255,255,255,0.15));
                color: #FFFFFF;
                border-color: rgba(255, 255, 255, 0.45);
            }
        """))
        row1.addWidget(mk("Snooze", "snooze", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.14), stop:1 rgba(255,255,255,0.06));
                color: #E2E8F0;
                border: 1px solid rgba(255, 255, 255, 0.18);
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 600;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,0.22), stop:1 rgba(255,255,255,0.10));
                color: #FFFFFF;
                border-color: rgba(255, 255, 255, 0.35);
            }
        """))

        row2 = QHBoxLayout()
        row2.setSpacing(7)
        row2.addWidget(mk("Block", "block", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(239, 68, 68, 0.28), stop:1 rgba(185, 28, 28, 0.16));
                color: #FCA5A5;
                border: 1px solid rgba(248, 113, 113, 0.38);
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 600;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(239, 68, 68, 0.45), stop:1 rgba(185, 28, 28, 0.30));
                color: #FFFFFF;
                border-color: rgba(248, 113, 113, 0.65);
            }
        """))
        row2.addWidget(mk("Kill", "kill", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #EF4444, stop:1 #B91C1C);
                color: #FFFFFF;
                border: 1px solid #F87171;
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 800;
                font-size: 10pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F87171, stop:1 #DC2626);
                border-color: #FCA5A5;
            }
        """))
        row2.addWidget(mk("Trust", "trust", """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(16, 185, 129, 0.48), stop:1 rgba(5, 150, 105, 0.28));
                color: #6EE7B7;
                border: 1px solid rgba(52, 211, 153, 0.65);
                border-radius: 12px;
                padding: 8px 4px;
                font-weight: 700;
                font-size: 10pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(16, 185, 129, 0.7), stop:1 rgba(5, 150, 105, 0.45));
                color: #FFFFFF;
                border-color: rgba(110, 231, 183, 0.9);
            }
        """))

        btn_layout.addLayout(row1)
        btn_layout.addLayout(row2)
        root.addLayout(btn_layout)

    def _darken(self, hex_color, amt=40):
        r,g,b = _hex_to_rgb(hex_color)
        return f"#{max(0,r-amt):02x}{max(0,g-amt):02x}{max(0,b-amt):02x}"

    def _position_and_slide(self):
        screen  = QApplication.primaryScreen().availableGeometry()
        self.fx = screen.right()  - W - 16
        self.fy = screen.bottom() - H - 8
        start_y = screen.bottom() + 10
        self.move(self.fx, start_y)
        self.show()

        self._anim = QPropertyAnimation(self, b"geometry", self)
        self._anim.setDuration(350)
        self._anim.setStartValue(QRect(self.fx, start_y, W, H))
        self._anim.setEndValue(QRect(self.fx, self.fy,   W, H))
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.start()

    def _start_timers(self):
        self._ticks       = 0
        self._total_ticks = 100
        self._tick_ms     = AUTO_CLOSE_MS // self._total_ticks

        self._prog_timer = QTimer(self)
        self._prog_timer.timeout.connect(self._tick_progress)
        self._prog_timer.start(self._tick_ms)

        self._dot_on = True
        self._dot_timer = QTimer(self)
        self._dot_timer.timeout.connect(self._pulse_dot)
        self._dot_timer.start(500)

        self._sec_timer = QTimer(self)
        self._sec_timer.timeout.connect(self._tick_second)
        self._sec_timer.start(1000)

    def _tick_progress(self):
        self._ticks += 1
        val = max(0, 1000 - int(self._ticks * 1000 / self._total_ticks))
        self.pbar.setValue(val)
        if val <= 0:
            self._prog_timer.stop()
            # Auto-close = treated as "ignored"
            self._action("ignore")

    def _tick_second(self):
        self._countdown = max(0, self._countdown - 1)

    def _pulse_dot(self):
        if hasattr(self, "_live_beacon"):
            self._live_beacon.set_state(self._dot_on)
        self._dot_on = not self._dot_on

    def _action(self, act):
        print(f"[Notifier] Button clicked: [{act}] on {self.app_name}")

        # ── CRITICAL ESCALATION ───────────────────────────────────────
        if act == "ignore":
            _increment_ignore(self.app_name)

        # ── KILL CHAIN LOGGING ────────────────────────────────────────
        _log_kill_chain_event(
            app_name=self.app_name,
            action=act,
            reasons=self.reasons,
            severity=self.severity,
        )

        # ── DASHBOARD SYNC ────────────────────────────────────────────
        threading.Thread(
            target=push_dashboard_update,
            args=(self.app_name, self.risk, act, self.reasons, self.severity),
            daemon=True
        ).start()

        self.close()

    def closeEvent(self, event):
        self._prog_timer.stop()
        self._dot_timer.stop()
        self._sec_timer.stop()
        if hasattr(self, '_border'):
            self._border.stop()
        super().closeEvent(event)

class AutoPausePopup(QWidget):
    def __init__(self, app_name, reasons):
        super().__init__()
        self.app_name = app_name
        self.reasons  = reasons
        self._build_ui()
        self._position()
        play_beep()
        play_beep()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(1.0, 1.0, float(self.width() - 2.0), float(self.height() - 2.0), 20.0, 20.0)
        grad = QLinearGradient(0, 0, self.width(), self.height())
        grad.setColorAt(0.0, QColor(20, 24, 36, 248))
        grad.setColorAt(1.0, QColor(10, 14, 22, 252))
        painter.fillPath(path, QBrush(grad))
        border_pen = QPen(QColor(239, 68, 68, 80), 1.2)
        painter.strokePath(path, border_pen)
        painter.end()

    def _build_ui(self):
        self.setFixedSize(460, 290)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool | Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFocusPolicy(Qt.NoFocus)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        # Header
        hl = QHBoxLayout()
        hl.setSpacing(8)
        title = QLabel(f"⏸ AUTO-PAUSED: {self.app_name}")
        title.setStyleSheet("color:#F87171; font-size:12.5pt; font-weight:800; font-family:'Segoe UI',sans-serif;")
        title.setWordWrap(True)
        hl.addWidget(title)
        hl.addStretch()

        x_btn = QPushButton("✕")
        x_btn.setFixedSize(24, 24)
        x_btn.setFocusPolicy(Qt.NoFocus)
        x_btn.setCursor(Qt.PointingHandCursor)
        x_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.08);
                color: #94A3B8;
                font-size: 9pt;
                font-weight: bold;
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 12px;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.2);
                color: #FFFFFF;
            }
        """)
        x_btn.clicked.connect(self.close)
        hl.addWidget(x_btn)
        layout.addLayout(hl)

        sub = QLabel("Ignored multiple times. Automatic quarantine triggered:")
        sub.setStyleSheet("color:#94A3B8; font-size:9pt; font-family:'Segoe UI',sans-serif;")
        layout.addWidget(sub)

        reasons_frame = QFrame()
        reasons_frame.setStyleSheet("QFrame { background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.08); border-radius:12px; }")
        rl = QVBoxLayout(reasons_frame)
        rl.setContentsMargins(12, 10, 12, 10)
        rl.setSpacing(6)
        for r in self.reasons[:3]:
            r_clean = r.replace("⚠ Behavior violation: ", "")
            r_lbl = QLabel(f"• {r_clean}")
            r_lbl.setStyleSheet("color:#FCA5A5; font-size:9pt; font-family:'Segoe UI',sans-serif; background:transparent;")
            r_lbl.setWordWrap(True)
            rl.addWidget(r_lbl)
        layout.addWidget(reasons_frame)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        keep_btn = QPushButton("🔒 Keep Blocked")
        keep_btn.setFocusPolicy(Qt.NoFocus)
        keep_btn.setCursor(Qt.PointingHandCursor)
        keep_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #EF4444, stop:1 #B91C1C);
                color: #FFFFFF;
                border: 1px solid #F87171;
                border-radius: 10px;
                padding: 9px;
                font-weight: 700;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover { background: #DC2626; }
        """)
        keep_btn.clicked.connect(self._keep_blocked)

        restore_btn = QPushButton("✅ Restore App")
        restore_btn.setFocusPolicy(Qt.NoFocus)
        restore_btn.setCursor(Qt.PointingHandCursor)
        restore_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(16, 185, 129, 0.5), stop:1 rgba(5, 150, 105, 0.3));
                color: #6EE7B7;
                border: 1px solid rgba(52, 211, 153, 0.6);
                border-radius: 10px;
                padding: 9px;
                font-weight: 700;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover { background: rgba(16, 185, 129, 0.7); color: #FFFFFF; }
        """)
        restore_btn.clicked.connect(self._restore)

        btn_row.addWidget(keep_btn)
        btn_row.addWidget(restore_btn)
        layout.addLayout(btn_row)

    def _position(self):
        screen = QApplication.primaryScreen().availableGeometry()
        self.move(screen.right() - 460 - 16, screen.bottom() - 290 - 8)
        self.show()

    def _keep_blocked(self):
        threading.Thread(target=lambda: requests.get(f"{FLASK_BASE}/block/{requests.utils.quote(self.app_name, safe='')}", timeout=3), daemon=True).start()
        self.close()

    def _restore(self):
        threading.Thread(target=lambda: requests.get(f"{FLASK_BASE}/trust/{requests.utils.quote(self.app_name, safe='')}", timeout=3), daemon=True).start()
        self.close()

class BundledAlertPopup(QWidget):
    """Single popup for multiple threats when fatigue is high"""

    def __init__(self, app_names, total_count):
        super().__init__()
        self.app_names   = app_names
        self.total_count = total_count
        self._build_ui()
        self._position()
        play_beep()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(1.0, 1.0, float(self.width() - 2.0), float(self.height() - 2.0), 20.0, 20.0)
        grad = QLinearGradient(0, 0, self.width(), self.height())
        grad.setColorAt(0.0, QColor(20, 24, 36, 248))
        grad.setColorAt(1.0, QColor(10, 14, 22, 252))
        painter.fillPath(path, QBrush(grad))
        border_pen = QPen(QColor(245, 166, 35, 80), 1.2)
        painter.strokePath(path, border_pen)
        painter.end()

    def _build_ui(self):
        self.setFixedSize(460, 220)
        self.setWindowFlags(Qt.FramelessWindowHint |
                            Qt.WindowStaysOnTopHint |
                            Qt.Tool |
                            Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_ShowWithoutActivating, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFocusPolicy(Qt.NoFocus)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        title = QLabel(f"⚠ {self.total_count} Threats Detected")
        title.setStyleSheet("color:#FBBF24; font-size:12.5pt; font-weight:800; font-family:'Segoe UI',sans-serif;")
        layout.addWidget(title)

        apps_str = ", ".join(self.app_names)
        sub = QLabel(f"{apps_str}")
        sub.setStyleSheet("color:#FCA5A5; font-size:9.5pt; font-family:'Segoe UI',sans-serif;")
        sub.setWordWrap(True)
        layout.addWidget(sub)

        fatigue_note = QLabel("⚡ Fatigue mode active — showing bundled protection alert")
        fatigue_note.setStyleSheet("color:#94A3B8; font-size:8.5pt; font-family:'Segoe UI',sans-serif;")
        layout.addWidget(fatigue_note)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        block_all = QPushButton(f"🔒 Block All {self.total_count} Threats")
        block_all.setFocusPolicy(Qt.NoFocus)
        block_all.setCursor(Qt.PointingHandCursor)
        block_all.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #EF4444, stop:1 #B91C1C);
                color: #FFFFFF;
                border: 1px solid #F87171;
                border-radius: 10px;
                padding: 9px;
                font-weight: 700;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover { background: #DC2626; }
        """)
        block_all.clicked.connect(self._block_all)

        dismiss = QPushButton("Dismiss")
        dismiss.setFocusPolicy(Qt.NoFocus)
        dismiss.setCursor(Qt.PointingHandCursor)
        dismiss.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.08);
                color: #CBD5E1;
                border: 1px solid rgba(255, 255, 255, 0.16);
                border-radius: 10px;
                padding: 9px;
                font-size: 9.5pt;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover { background: rgba(255, 255, 255, 0.18); color: #FFFFFF; }
        """)
        dismiss.clicked.connect(self.close)

        btn_row.addWidget(block_all)
        btn_row.addWidget(dismiss)
        layout.addLayout(btn_row)

    def _position(self):
        screen = QApplication.primaryScreen().availableGeometry()
        x = screen.right() - 460 - 16
        y = screen.bottom() - 220 - 8
        self.move(x, y)
        self.show()

    def _block_all(self):
        for app in self.app_names:
            threading.Thread(
                target=lambda a=app: requests.get(
                    f"{FLASK_BASE}/block/{requests.utils.quote(a, safe='')}",
                    timeout=3
                ),
                daemon=True
            ).start()
        print(f"[Notifier] 🔒 BLOCK ALL: {self.app_names}")
        self.close()


# ═══════════════════════════════════════════════════════════════════════
#  PERIPHERAL / HARDWARE FLOATING DYNAMIC ISLAND POPUP (OPTION C)
# ═══════════════════════════════════════════════════════════════════════
class PeripheralAlertPopup(QWidget):
    def __init__(self, event_id, category, device_name, target, details):
        super().__init__()
        self.event_id = event_id
        self.category = category
        self.device_name = device_name or "External Device"
        self.target = target
        self.details = details
        self._countdown = 15  # 15s Zero-Trust Countdown
        self._total_countdown = 15
        self._timestamp = datetime.datetime.now().strftime("%I:%M %p")

        self._build_ui()
        self._position_and_slide()
        self._start_timers()
        play_beep()

    def _build_ui(self):
        self.setFixedSize(560, 82)
        self.setWindowFlags(Qt.FramelessWindowHint |
                            Qt.WindowStaysOnTopHint |
                            Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_ShowWithoutActivating, False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        # 1. Left: Guardian Official Shield Logo
        self.logo_lbl = QLabel(self)
        self.logo_lbl.setFixedSize(46, 46)
        self.logo_lbl.setAlignment(Qt.AlignCenter)
        logo_path = os.path.join(_SCRIPT_DIR, "static", "guardian_logo.png")
        if not os.path.exists(logo_path):
            logo_path = os.path.join(_SCRIPT_DIR, "static", "guardian_logo.jpg")

        if os.path.exists(logo_path):
            pix = QPixmap(logo_path)
            if not pix.isNull():
                self.logo_lbl.setPixmap(pix.scaled(44, 44, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                self.logo_lbl.setText("🛡️")
                self.logo_lbl.setStyleSheet("font-size: 24pt;")
        else:
            self.logo_lbl.setText("🛡️")
            self.logo_lbl.setStyleSheet("font-size: 24pt;")
        layout.addWidget(self.logo_lbl)

        # 2. Middle: Device Title + Progress Bar + Subtitle with Timestamp
        mid_layout = QVBoxLayout()
        mid_layout.setContentsMargins(0, 2, 0, 2)
        mid_layout.setSpacing(4)

        # Title
        dev_display = self.device_name
        if not ("connected" in dev_display.lower() or "plugged" in dev_display.lower()):
            dev_display = f"{dev_display} Connected"
        self.title_lbl = QLabel(dev_display)
        self.title_lbl.setStyleSheet("color: #FFFFFF; font-size: 11pt; font-weight: bold; font-family: 'Segoe UI', sans-serif;")
        mid_layout.addWidget(self.title_lbl)

        # Sleek 3px Progress Bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(3)
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background: rgba(255, 255, 255, 0.12);
                border-radius: 1px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #38BDF8, stop:0.6 #818CF8, stop:1 #C084FC);
                border-radius: 1px;
            }
        """)
        mid_layout.addWidget(self.progress)

        # Subtitle with live timestamp & countdown
        self.sub_lbl = QLabel(f"Is this you? • {self._timestamp} ({self._countdown}s)")
        self.sub_lbl.setStyleSheet("color: #94A3B8; font-size: 8.5pt; font-family: 'Segoe UI', sans-serif;")
        mid_layout.addWidget(self.sub_lbl)

        layout.addLayout(mid_layout, stretch=1)

        # 3. Right: Action Buttons (This is me & Not me)
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_me = QPushButton("This is me")
        self.btn_me.setCursor(Qt.PointingHandCursor)
        self.btn_me.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: #FFFFFF;
                border: none;
                border-radius: 16px;
                padding: 7px 16px;
                font-size: 9pt;
                font-weight: bold;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background-color: #22c55e;
            }
            QPushButton:pressed {
                background-color: #15803d;
            }
        """)
        self.btn_me.clicked.connect(self._on_trust)

        self.btn_not_me = QPushButton("Not me")
        self.btn_not_me.setCursor(Qt.PointingHandCursor)
        self.btn_not_me.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #FFFFFF;
                border: none;
                border-radius: 16px;
                padding: 7px 16px;
                font-size: 9pt;
                font-weight: bold;
                font-family: 'Segoe UI', sans-serif;
            }
            QPushButton:hover {
                background-color: #ef4444;
            }
            QPushButton:pressed {
                background-color: #b91c1c;
            }
        """)
        self.btn_not_me.clicked.connect(self._on_block)

        btn_layout.addWidget(self.btn_me)
        btn_layout.addWidget(self.btn_not_me)
        layout.addLayout(btn_layout)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(1.0, 1.0, float(self.width() - 2.0), float(self.height() - 2.0), 24.0, 24.0)
        
        # Deep translucent obsidian backdrop
        painter.fillPath(path, QBrush(QColor(15, 18, 25, 246)))
        
        # Subtle 1px glass border
        pen = QPen(QColor(255, 255, 255, 28), 1.2)
        painter.strokePath(path, pen)

    def _position_and_slide(self):
        screen = QApplication.primaryScreen().availableGeometry()
        x = screen.left() + (screen.width() - self.width()) // 2
        y = screen.top() + 32  # Top-center dynamic island floating banner
        self.move(x, y)
        self.show()

    def _start_timers(self):
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def _tick(self):
        self._countdown -= 1
        pct = max(0, int((self._countdown / self._total_countdown) * 100))
        self.progress.setValue(pct)
        self.sub_lbl.setText(f"Is this you? • {self._timestamp} ({self._countdown}s)")
        if self._countdown <= 0:
            self._timer.stop()
            self._on_timeout()

    def _on_trust(self):
        self._timer.stop()
        threading.Thread(target=self._send_action, args=("trust",), daemon=True).start()
        self.close()

    def _on_block(self):
        self._timer.stop()
        threading.Thread(target=self._send_action, args=("block",), daemon=True).start()
        self.close()

    def _on_timeout(self):
        threading.Thread(target=self._send_action, args=("timeout",), daemon=True).start()
        self.close()

    def _send_action(self, action):
        try:
            payload = {
                "event_id": self.event_id,
                "action": action,
                "device_category": self.category,
                "device_name": self.device_name,
                "target": self.target
            }
            requests.post(FLASK_BASE + "/api/peripheral/action", json=payload, timeout=5)
            print(f"[Notifier] Peripheral action executed: {action} on {self.device_name}")
        except Exception as e:
            print(f"[Notifier] Peripheral action failed: {e}")


# ═══════════════════════════════════════════════════════════════════════
#  MINI FLASK SERVER on port 5001
# ═══════════════════════════════════════════════════════════════════════
trigger_server = Flask("notifier_trigger")

@trigger_server.route("/start_popups", methods=["GET", "POST"])
def start_popups():
    global _attack_active, _ignore_counter, _ignored_app_names
    with _attack_lock:
        _attack_active = True
        _last_shown_time = 0
    with _ignore_counter_lock:
        _ignore_counter    = 0
        _ignored_app_names = []
    print("[Notifier] 🚨 Attack triggered — continuous popups starting!")
    return jsonify({"status": "popups started"})

@trigger_server.route("/stop_popups", methods=["GET", "POST"])
def stop_popups():
    global _attack_active
    with _attack_lock:
        _attack_active = False
    print("[Notifier] ✅ Popups stopped.")
    return jsonify({"status": "popups stopped"})
_pause_popup_data = {"app_name": "", "reasons": []}

@trigger_server.route("/show_pause_popup", methods=["POST"])
def show_pause_popup():
    global _pause_popup_data
    data = request.json or {}
    _pause_popup_data = data
    bridge.show_pause.emit(data.get("app_name", "?"), data.get("reasons", []))
    return jsonify({"status": "pause popup shown"})

@trigger_server.route("/show_peripheral_popup", methods=["POST"])
def show_peripheral_popup():
    data = request.json or {}
    p_id = data.get("id", f"DEV-{int(time.time()*1000)}")
    category = data.get("category", "usb")
    device_name = data.get("device_name", "External Device")
    target = data.get("target", "")
    details = data.get("details", "")
    bridge.show_peripheral.emit(str(p_id), str(category), str(device_name), str(target), str(details))
    return jsonify({"status": "peripheral popup triggered"})

def run_trigger_server():
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    trigger_server.run(host="127.0.0.1", port=TRIGGER_PORT, debug=False, use_reloader=False)

# ═══════════════════════════════════════════════════════════════════════
#  POLL THREAD
# ═══════════════════════════════════════════════════════════════════════
_running = True
_last_shown_app = ""
_last_shown_time = 0
_last_peripheral_id = ""

def poll_loop():
    global _last_shown_app, _last_shown_time, _last_peripheral_id
    print(f"[Notifier] 🟡 Standby — monitoring for real threats, peripherals + simulate button")
    while _running:
        with _attack_lock:
            active = _attack_active

        # 1. Check for real-time Hardware / Peripheral insertion alerts
        try:
            p_res = requests.get(FLASK_BASE + "/api/peripheral/latest", timeout=1.5).json()
            if p_res.get("has_pending") and p_res.get("pending"):
                p_obj = p_res["pending"]
                p_id = p_obj.get("id")
                if p_id and p_id != _last_peripheral_id:
                    _last_peripheral_id = p_id
                    bridge.show_peripheral.emit(
                        str(p_id),
                        str(p_obj.get("category", "usb")),
                        str(p_obj.get("device_name", "External Device")),
                        str(p_obj.get("target", "")),
                        str(p_obj.get("details", ""))
                    )
        except Exception:
            pass

        # 2. Check for Process / Network Threats
        try:
            res        = requests.get(FLASK_BASE + "/get_report", timeout=3).json()
            high_risk  = res.get("high_risk",  [])
            suspicious = res.get("suspicious", [])

            if active:
                if not high_risk and not suspicious:
                    diverse    = _next_diverse_alerts()
                    high_risk  = diverse["high_risk"]
                    suspicious = diverse["suspicious"]
                    try:
                        requests.post(FLASK_BASE + "/register_threats_batch", json=diverse, timeout=1)
                    except Exception:
                        pass

            all_combined = high_risk + suspicious

            if all_combined:
                idx      = int(time.time() / POLL_INTERVAL) % len(all_combined)
                obj      = all_combined[idx]
                app_name = obj.get("app", "unknown.exe")
                reasons  = obj.get("reasons", ["Anomaly detected"])
                severity = obj.get("severity", 50)
                risk     = "HIGH RISK" if obj in high_risk else "SUSPICIOUS RISK"
                now      = time.time()
                COOLDOWN = 8

                try:
                    fatigue_res   = requests.get(FLASK_BASE + "/get_fatigue_state", timeout=2).json()
                    fatigue_score = fatigue_res.get("score", 0)
                except:
                    fatigue_score = 0

                if app_name != _last_shown_app or (now - _last_shown_time) > COOLDOWN:
                    _last_shown_app  = app_name
                    _last_shown_time = now
                    bridge.show_alert.emit(app_name, risk, reasons, int(severity))
                    try:
                        requests.post(FLASK_BASE + "/register_threat", json={
                            "app": app_name,
                            "reasons": reasons,
                            "severity": int(severity),
                            "risk": risk
                        }, timeout=1)
                    except Exception:
                        pass
                    src = "SIMULATE" if active else "REAL THREAT"
                    print(f"[Notifier] [{src}] ▶ {app_name}  [{risk}]  sev={severity}")


        except requests.exceptions.ConnectionError:
            print("[Notifier] GUARDIAN core closed/unreachable — stopping notifier.")
            try:
                QApplication.quit()
            except Exception:
                pass
            os._exit(0)

        except Exception as e:
            print(f"[Notifier] Poll error: {e}")

        time.sleep(POLL_INTERVAL)


def _watch_parent():
    """Monitors parent GUARDIAN process and exits immediately if parent terminates."""
    parent_pid = None
    for arg in sys.argv:
        if arg.startswith("--parent-pid="):
            try:
                parent_pid = int(arg.split("=")[1])
            except Exception:
                pass
    if parent_pid:
        try:
            import psutil
            while True:
                time.sleep(1)
                if not psutil.pid_exists(parent_pid):
                    print(f"[Notifier] Parent process {parent_pid} closed — exiting.")
                    os._exit(0)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
#  GLOBAL POPUP MANAGER
# ═══════════════════════════════════════════════════════════════════════
_current_popup = None
_current_peripheral_popup = None

def on_show_alert(app_name, risk, reasons, severity):
    global _current_popup
    if _current_popup is not None:
        try: _current_popup.close()
        except: pass
    _current_popup = AlertPopup(app_name, risk, reasons, severity)

def on_show_peripheral(event_id, category, device_name, target, details):
    global _current_peripheral_popup
    if _current_peripheral_popup is not None:
        try: _current_peripheral_popup.close()
        except: pass
    _current_peripheral_popup = PeripheralAlertPopup(event_id, category, device_name, target, details)
    _current_peripheral_popup.show()
    _current_peripheral_popup.raise_()
    _current_peripheral_popup.activateWindow()


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    print("═" * 58)
    print("  🛡  Security Alert Notifier  (PyQt5) — Hardware & Threat Mode")
    print(f"  Real-time Peripheral Protection Active (USB / Charger / Bluetooth)")
    print(f"  Critical Escalation after {CRITICAL_THRESHOLD} ignores → overlay!")
    print("═" * 58)

    threading.Thread(target=_watch_parent, daemon=True).start()

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    bridge.show_alert.connect(on_show_alert)
    bridge.show_pause.connect(lambda app, reasons: AutoPausePopup(app, reasons))
    bridge.show_bundle.connect(lambda apps, count: BundledAlertPopup(apps, count))
    bridge.show_peripheral.connect(on_show_peripheral)

    threading.Thread(target=run_trigger_server, daemon=True).start()
    threading.Thread(target=poll_loop, daemon=True).start()

    try:
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        global _running
        _running = False
        print("\n[Notifier] 🛑 Stopped by Ctrl+C")

if __name__ == "__main__":
    main()