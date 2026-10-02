from flask import Flask, render_template, request, jsonify, make_response, send_file
from flask_cors import CORS
import sys
import json
import os
import psutil
import time
import threading
import requests
import math
import re
import base64
import io
from collections import defaultdict

import tempfile, os
_DATA_DIR = os.path.join(tempfile.gettempdir(), "guardian_data")
os.makedirs(_DATA_DIR, exist_ok=True)

def _ensure_windows_proxy_safe():
    """Guarantees Windows proxy is disabled so Taskbar Search and Windows services are never blocked."""
    try:
        import winreg, ctypes
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0, winreg.KEY_WRITE
        )
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        try:
            ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
        except Exception:
            pass
    except Exception:
        pass

_ensure_windows_proxy_safe()

def _get_downloads_dir():
    """Returns the absolute path to the user's system Downloads folder on Windows."""
    if sys.platform == "win32":
        try:
            import winreg
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                downloads = winreg.QueryValueEx(key, '{374DE290-123F-4565-9164-39C4925E467B}')[0]
                if os.path.exists(downloads):
                    return downloads
        except Exception:
            pass
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    if os.path.exists(downloads):
        return downloads
    return home

PROTECTED_SYSTEM_APPS = {
    # Windows Search & Shell Experience
    "searchhost.exe", "searchapp.exe", "searchindexer.exe", "searchfilterhost.exe",
    "searchprotocolhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "applicationframehost.exe", "runtimebroker.exe", "sihost.exe",
    "taskhostw.exe", "ctfmon.exe", "dwm.exe", "explorer.exe",
    # Windows Core System
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "spoolsv.exe",
    "audiodg.exe", "wudfhost.exe", "lockapp.exe", "memcompression", "crossdeviceservice.exe",
    # Core IDE & Runtime
    "code.exe", "python.exe", "python3.exe", "pythonw.exe"
}

BLOCK_FILE    = os.path.join(_DATA_DIR, "blocked_apps.json")
KILLED_FILE   = os.path.join(_DATA_DIR, "killed_apps.json")
TRUSTED_FILE  = os.path.join(_DATA_DIR, "trusted_apps.json")
TIMELINE_FILE = os.path.join(_DATA_DIR, "timeline.json")
PROFILE_FILE  = os.path.join(_DATA_DIR, "app_profiles.json")
BROWSER_THREAT_FILE = os.path.join(_DATA_DIR, "browser_threats.json")
KILL_CHAIN_FILE = os.path.join(_DATA_DIR, "kill_chain.json")

# ---------------- LOAD BLOCKED ----------------
if os.path.exists(BLOCK_FILE):
    with open(BLOCK_FILE, "r") as f:
        BLOCKED_APPS = {a.lower() for a in json.load(f) if a.lower() not in PROTECTED_SYSTEM_APPS}
else:
    BLOCKED_APPS = set()

# ---------------- LOAD KILLED ----------------
if os.path.exists(KILLED_FILE):
    with open(KILLED_FILE, "r") as f:
        KILLED_APPS = {a.lower() for a in json.load(f) if a.lower() not in PROTECTED_SYSTEM_APPS}
else:
    KILLED_APPS = set()

TEMP_KILLED = set()

def save_blocked():
    with open(BLOCK_FILE, "w") as f: json.dump(list(BLOCKED_APPS), f)
def save_killed():
    with open(KILLED_FILE, "w") as f: json.dump(list(KILLED_APPS), f)

save_blocked()
save_killed()

# ---------------- LOAD TRUSTED ----------------
if os.path.exists(TRUSTED_FILE):
    with open(TRUSTED_FILE, "r") as f:
        TRUSTED_APPS = set(json.load(f))
else:
    TRUSTED_APPS = set()

# ---------------- LOAD TIMELINE ----------------
if os.path.exists(TIMELINE_FILE):
    with open(TIMELINE_FILE, "r") as f:
        try:
            TIMELINE_DATA = json.load(f)
        except:
            TIMELINE_DATA = {"history":[],"blocked":0,"killed":0,"trusted":0,"score":0,"appCounts":{}}
else:
    TIMELINE_DATA = {"history":[],"blocked":0,"killed":0,"trusted":0,"score":0,"appCounts":{}}

# ── In-memory fatigue state ──────────────────────────────────────────────────
fatigue_state = {
    "score":0.0,"total":0,"ignored":0,"actions":0,
    "ignore_streak":0,"heat":{"Low":0,"Medium":0,"High":0},
}

# ── Thread-safe lock ─────────────────────────────────────────────────────────
data_lock = threading.Lock()

# ── Shared live data ─────────────────────────────────────────────────────────
latest_data = {"running":[],"suspicious":[],"high_risk":[],"profile_summary":{}}

# Behavior violation alerts
behavior_alerts     = []
MAX_BEHAVIOR_ALERTS = 50

# Simulate attack state
_sim_attack_active = False
_sim_data          = {"suspicious":[],"high_risk":[]}

# ════════════════════════════════════════════════════════════════
# ── Critical Escalation State ───────────────────────────────────
# ════════════════════════════════════════════════════════════════
_critical_escalation_state = {
    "active":        False,
    "ignored_count": 0,
    "ignored_apps":  [],
    "fatigue_score": 0.0,
    "triggered_at":  None,
}
_critical_lock = threading.Lock()

# ════════════════════════════════════════════════════════════════
# ── KILL CHAIN STATE ────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════

MITRE_TACTIC_MAP = {
    "trojan":        {"tactic": "Execution",          "technique": "T1204", "color": "danger"},
    "keylogger":     {"tactic": "Credential Access",  "technique": "T1056", "color": "danger"},
    "ransomware":    {"tactic": "Impact",              "technique": "T1486", "color": "danger"},
    "rootkit":       {"tactic": "Defense Evasion",     "technique": "T1014", "color": "danger"},
    "cryptominer":   {"tactic": "Resource Hijacking",  "technique": "T1496", "color": "warn"},
    "spyware":       {"tactic": "Collection",          "technique": "T1005", "color": "warn"},
    "backdoor":      {"tactic": "Persistence",         "technique": "T1543", "color": "danger"},
    "worm":          {"tactic": "Lateral Movement",    "technique": "T1570", "color": "danger"},
    "malware":       {"tactic": "Execution",           "technique": "T1204", "color": "danger"},
    "exploit":       {"tactic": "Initial Access",      "technique": "T1190", "color": "danger"},
    "mimikatz":      {"tactic": "Credential Access",   "technique": "T1003", "color": "danger"},
    "psexec":        {"tactic": "Lateral Movement",    "technique": "T1021", "color": "warn"},
    "powershell":    {"tactic": "Execution",           "technique": "T1059", "color": "warn"},
    "netcat":        {"tactic": "Command & Control",   "technique": "T1095", "color": "warn"},
    "macro":         {"tactic": "Initial Access",      "technique": "T1566", "color": "warn"},
    "svchost":       {"tactic": "Defense Evasion",     "technique": "T1036", "color": "warn"},
    "updater":       {"tactic": "Persistence",         "technique": "T1547", "color": "warn"},
    "rundll":        {"tactic": "Defense Evasion",     "technique": "T1218", "color": "warn"},
    "browser_ext":   {"tactic": "Collection",          "technique": "T1185", "color": "warn"},
    "weird":         {"tactic": "Discovery",           "technique": "T1057", "color": "ok"},
}

KILL_CHAIN_STAGES = [
    "Reconnaissance","Initial Access","Execution","Persistence",
    "Defense Evasion","Credential Access","Discovery","Lateral Movement",
    "Collection","Command & Control","Exfiltration","Impact","Resource Hijacking",
]

_kill_chain_events = []
_kill_chain_lock   = threading.Lock()

if os.path.exists(KILL_CHAIN_FILE):
    try:
        with open(KILL_CHAIN_FILE) as f:
            _kill_chain_events = json.load(f)
    except:
        _kill_chain_events = []

def _save_kill_chain():
    with open(KILL_CHAIN_FILE, "w") as f:
        json.dump(_kill_chain_events, f, indent=2)

def _assign_mitre(app_name, reasons=None):
    al = (app_name or "").lower()
    for keyword, info in MITRE_TACTIC_MAP.items():
        if keyword in al:
            return info
    if reasons:
        reasons_text = " ".join(reasons).lower()
        if "unusual time" in reasons_text or "time anomaly" in reasons_text:
            return {"tactic": "Discovery", "technique": "T1057", "color": "ok"}
        if "cpu" in reasons_text or "memory" in reasons_text:
            return {"tactic": "Execution", "technique": "T1204", "color": "warn"}
        if "lateral" in reasons_text or "lan scan" in reasons_text:
            return {"tactic": "Lateral Movement", "technique": "T1570", "color": "danger"}
        if "credential" in reasons_text or "lsass" in reasons_text:
            return {"tactic": "Credential Access", "technique": "T1003", "color": "danger"}
        if "persist" in reasons_text or "registry" in reasons_text:
            return {"tactic": "Persistence", "technique": "T1543", "color": "warn"}
        if "encrypt" in reasons_text or "ransom" in reasons_text:
            return {"tactic": "Impact", "technique": "T1486", "color": "danger"}
        if "shell" in reasons_text or "port" in reasons_text or "tcp" in reasons_text:
            return {"tactic": "Command & Control", "technique": "T1095", "color": "warn"}
        if "ml anomaly" in reasons_text or "rare" in reasons_text:
            return {"tactic": "Discovery", "technique": "T1057", "color": "ok"}
    return {"tactic": "Execution", "technique": "T1204", "color": "warn"}


def _add_kill_chain_event(app_name, action, reasons=None, severity=0, source="dashboard"):
    mitre = _assign_mitre(app_name, reasons)
    ts    = time.strftime("%H:%M:%S")
    event = {
        "id":        len(_kill_chain_events) + 1,
        "time":      ts,
        "app":       app_name,
        "action":    action,
        "tactic":    mitre["tactic"],
        "technique": mitre["technique"],
        "color":     mitre["color"],
        "severity":  severity,
        "reasons":   reasons or [],
        "source":    source,
    }
    with _kill_chain_lock:
        _kill_chain_events.append(event)
        if len(_kill_chain_events) > 100:
            _kill_chain_events.pop(0)
        _save_kill_chain()
    return event

# ════════════════════════════════════════════════════════════════

def save_blocked():
    with open(BLOCK_FILE, "w") as f: json.dump(list(BLOCKED_APPS), f)
def save_killed():
    with open(KILLED_FILE, "w") as f: json.dump(list(KILLED_APPS), f)
def save_trusted():
    with open(TRUSTED_FILE, "w") as f: json.dump(list(TRUSTED_APPS), f)
def save_timeline():
    with open(TIMELINE_FILE, "w") as f: json.dump(TIMELINE_DATA, f, indent=2)

def _log_action_internal(app_name, action, score_after=None):
    ts = time.strftime("%H:%M:%S")
    TIMELINE_DATA[action] = TIMELINE_DATA.get(action,0) + 1
    al = app_name.lower()
    if "appCounts" not in TIMELINE_DATA: TIMELINE_DATA["appCounts"] = {}
    if al not in TIMELINE_DATA["appCounts"]:
        TIMELINE_DATA["appCounts"][al] = {"blocked":0,"killed":0,"trusted":0}
    TIMELINE_DATA["appCounts"][al][action] = TIMELINE_DATA["appCounts"][al].get(action,0)+1
    rc = TIMELINE_DATA["appCounts"][al][action]
    TIMELINE_DATA["history"].append({"time":ts,"app":app_name,"action":action,"count":rc})
    if score_after is not None:
        TIMELINE_DATA["score"] = score_after
    else:
        delta = {"blocked":20,"killed":10,"trusted":-5}.get(action,0)
        TIMELINE_DATA["score"] = max(0, TIMELINE_DATA.get("score",0)+delta)
    save_timeline()

def remove_from_data(app_lower):
    with data_lock:
        latest_data["running"]    = [a for a in latest_data["running"]    if a.lower()!=app_lower]
        latest_data["suspicious"] = [o for o in latest_data["suspicious"] if o.get("app","").lower()!=app_lower]
        latest_data["high_risk"]  = [o for o in latest_data["high_risk"]  if o.get("app","").lower()!=app_lower]
        _sim_data["suspicious"]   = [o for o in _sim_data.get("suspicious",[]) if o.get("app","").lower()!=app_lower]
        _sim_data["high_risk"]    = [o for o in _sim_data.get("high_risk",[]) if o.get("app","").lower()!=app_lower]


def is_hidden(al): return al in BLOCKED_APPS or al in TEMP_KILLED
if getattr(sys, 'frozen', False):
    _exe_dir = os.path.dirname(sys.executable)
    _meipass = getattr(sys, '_MEIPASS', _exe_dir)
    _internal_dir = os.path.join(_exe_dir, '_internal')
    _tpl_paths = [
        os.path.join(_meipass, 'templates'),
        os.path.join(_internal_dir, 'templates'),
        os.path.join(_exe_dir, 'templates'),
        _meipass, _internal_dir, _exe_dir
    ]
    _st_paths = [
        os.path.join(_meipass, 'static'),
        os.path.join(_internal_dir, 'static'),
        os.path.join(_exe_dir, 'static'),
        _meipass, _internal_dir, _exe_dir
    ]
    _base_dir = _meipass
else:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
    _tpl_paths = [os.path.join(_base_dir, 'templates'), _base_dir]
    _st_paths = [os.path.join(_base_dir, 'static'), _base_dir]

_primary_tpl = next((p for p in _tpl_paths if os.path.exists(p)), _base_dir)
_primary_st = next((p for p in _st_paths if os.path.exists(p)), _base_dir)

from jinja2 import ChoiceLoader, FileSystemLoader
app = Flask(__name__, template_folder=_primary_tpl, static_folder=_primary_st, static_url_path='/static')
app.jinja_loader = ChoiceLoader([FileSystemLoader(p) for p in _tpl_paths if os.path.exists(p)])
CORS(app)

@app.route('/static/<path:filename>')
def custom_static(filename):
    from flask import send_from_directory
    for p in _st_paths:
        if os.path.exists(os.path.join(p, filename)):
            return send_from_directory(p, filename)
    return "Asset not found", 404

SAFE_APPS      = {"chrome.exe","msedge.exe","explorer.exe","code.exe","python.exe","duckduckgo.exe","duckduckgo.webview.exe"} | PROTECTED_SYSTEM_APPS
HIGH_RISK_APPS = {"trojan.exe","malware.exe","ransomware.exe","exploit_kit.exe","keylogger.exe","backdoor.exe","cryptominer.exe","calculatorapp.exe","windowscamera.exe"}


@app.route("/splash")
def splash(): return render_template("splash.html")

@app.route("/audio")
def serve_audio():
    import os
    files = os.listdir(_primary_st) if os.path.exists(_primary_st) else []
    return f"Files in static: {files}"

@app.route("/")
def index(): return render_template("index.html")

@app.route("/health")
def health(): return "Backend Security Engine Running"

# ── update_report ────────────────────────────────────────────────────────────
@app.route("/update_report", methods=["POST"])
def update_report():
    global _sim_attack_active
    data = request.json or {}
    with data_lock:
        incoming_running = [a for a in data.get("running",[]) if not is_hidden(a.lower())]
        incoming_sus     = [o for o in data.get("suspicious",[]) if not is_hidden(o.get("app","").lower())]
        incoming_hi      = [o for o in data.get("high_risk",[])  if not is_hidden(o.get("app","").lower())]

        # If simulation or active registered threats exist, retain them
        if _sim_attack_active:
            existing_sus_names = {o.get("app","").lower() for o in incoming_sus}
            for s in _sim_data.get("suspicious", []):
                al = s.get("app","").lower()
                if al and al not in existing_sus_names and not is_hidden(al):
                    incoming_sus.append(s)
                    existing_sus_names.add(al)

            existing_hi_names = {o.get("app","").lower() for o in incoming_hi}
            for h in _sim_data.get("high_risk", []):
                al = h.get("app","").lower()
                if al and al not in existing_hi_names and not is_hidden(al):
                    incoming_hi.append(h)
                    existing_hi_names.add(al)

            for item in incoming_sus + incoming_hi:
                iapp = item.get("app")
                if iapp and iapp not in incoming_running and not is_hidden(iapp.lower()):
                    incoming_running.append(iapp)

        latest_data["running"]    = incoming_running
        latest_data["suspicious"] = incoming_sus
        latest_data["high_risk"]  = incoming_hi

        if "profile_summary" in data and data["profile_summary"]:
            latest_data["profile_summary"].update(data["profile_summary"])

    now = time.strftime("%H:%M:%S")
    all_flagged = latest_data["suspicious"] + latest_data["high_risk"]
    for obj in all_flagged:
        for reason in obj.get("reasons",[]):
            if "Behavior violation" in reason or "Time anomaly" in reason:
                behavior_alerts.append({"app":obj["app"],"violation":reason,"time":now,"severity":obj.get("severity",0)})
    while len(behavior_alerts) > MAX_BEHAVIOR_ALERTS:
        behavior_alerts.pop(0)
    return jsonify({"status":"updated"})

@app.route("/register_threat", methods=["POST"])
def register_threat():
    global _sim_attack_active
    data = request.json or {}
    app_name = data.get("app", "")
    if not app_name:
        return jsonify({"error": "missing app name"}), 400
    
    reasons  = data.get("reasons", ["Anomaly detected"])
    severity = int(data.get("severity", 75))
    risk     = str(data.get("risk", "HIGH RISK"))
    
    threat_obj = {
        "app":      app_name,
        "reasons":  reasons,
        "severity": severity
    }
    
    with data_lock:
        al = app_name.lower()
        if not is_hidden(al):
            if app_name not in latest_data["running"]:
                latest_data["running"].append(app_name)
            
            is_high = severity >= 70 or "HIGH" in risk.upper()
            target_list = "high_risk" if is_high else "suspicious"
            other_list  = "suspicious" if is_high else "high_risk"
            
            latest_data[target_list] = [o for o in latest_data[target_list] if o.get("app","").lower() != al]
            latest_data[other_list]  = [o for o in latest_data[other_list] if o.get("app","").lower() != al]
            latest_data[target_list].append(threat_obj)
            
            _sim_data[target_list] = [o for o in _sim_data.get(target_list, []) if o.get("app","").lower() != al]
            _sim_data[other_list]  = [o for o in _sim_data.get(other_list, []) if o.get("app","").lower() != al]
            _sim_data[target_list].append(threat_obj)
            _sim_attack_active = True

    now = time.strftime("%H:%M:%S")
    for r in reasons:
        behavior_alerts.append({"app": app_name, "violation": f"⚠ Behavior violation: {r}" if "Behavior violation" not in r else r, "time": now, "severity": severity})
    while len(behavior_alerts) > MAX_BEHAVIOR_ALERTS:
        behavior_alerts.pop(0)
        
    return jsonify({"status": "registered", "threat": threat_obj})

@app.route("/register_threats_batch", methods=["POST"])
def register_threats_batch():
    global _sim_attack_active
    data = request.json or {}
    hi_list  = data.get("high_risk", [])
    sus_list = data.get("suspicious", [])
    
    with data_lock:
        _sim_attack_active = True
        for h in hi_list:
            aname = h.get("app", "")
            al = aname.lower()
            if aname and not is_hidden(al):
                if aname not in latest_data["running"]:
                    latest_data["running"].append(aname)
                latest_data["high_risk"] = [o for o in latest_data["high_risk"] if o.get("app","").lower() != al]
                latest_data["high_risk"].append(h)
                _sim_data["high_risk"] = [o for o in _sim_data.get("high_risk", []) if o.get("app","").lower() != al]
                _sim_data["high_risk"].append(h)
                
        for s in sus_list:
            aname = s.get("app", "")
            al = aname.lower()
            if aname and not is_hidden(al):
                if aname not in latest_data["running"]:
                    latest_data["running"].append(aname)
                latest_data["suspicious"] = [o for o in latest_data["suspicious"] if o.get("app","").lower() != al]
                latest_data["suspicious"].append(s)
                _sim_data["suspicious"] = [o for o in _sim_data.get("suspicious", []) if o.get("app","").lower() != al]
                _sim_data["suspicious"].append(s)
                
    return jsonify({"status": "registered_batch", "high_risk_count": len(latest_data["high_risk"]), "suspicious_count": len(latest_data["suspicious"])})

@app.route("/scan_processes", methods=["GET", "POST"])
def scan_processes_route():
    procs = []
    try:
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info.get('name')
                if not name: continue
                nl = name.lower()
                if nl in PROTECTED_SYSTEM_APPS or is_hidden(nl): continue
                if name not in procs:
                    procs.append(name)
            except Exception:
                pass
    except Exception:
        pass
        
    with data_lock:
        latest_data["running"] = procs
        if _sim_attack_active:
            for sim_item in _sim_data.get("suspicious", []) + _sim_data.get("high_risk", []):
                s_app = sim_item.get("app")
                if s_app and s_app not in latest_data["running"] and not is_hidden(s_app.lower()):
                    latest_data["running"].append(s_app)
                    
    return jsonify({"status": "scanned", "count": len(latest_data["running"]), "running": latest_data["running"]})

@app.route("/get_report")
def get_report():
    with data_lock:
        running_out    = [a for a in latest_data["running"]    if not is_hidden(a.lower())]
        suspicious_out = [o for o in latest_data["suspicious"] if not is_hidden(o.get("app","").lower())]
        high_risk_out  = [o for o in latest_data["high_risk"]  if not is_hidden(o.get("app","").lower())]
        
        if not running_out:
            try:
                for proc in psutil.process_iter(['name']):
                    n = proc.info.get('name')
                    if n and not is_hidden(n.lower()) and n.lower() not in PROTECTED_SYSTEM_APPS and n not in running_out:
                        running_out.append(n)
                latest_data["running"] = running_out
            except Exception:
                pass

        profile_out = dict(latest_data.get("profile_summary", {}))

    return jsonify({
        "running":running_out,"suspicious":suspicious_out,"high_risk":high_risk_out,
        "blocked":list(BLOCKED_APPS),"killed":list(TEMP_KILLED),"trusted":list(TRUSTED_APPS),
        "profile_summary":profile_out,
    })


# ── Profiles ─────────────────────────────────────────────────────────────────
@app.route("/get_profiles")
def get_profiles():
    if os.path.exists(PROFILE_FILE):
        try:
            profiles = json.load(open(PROFILE_FILE))
            return jsonify({"profiles":profiles,"count":len(profiles)})
        except: pass
    return jsonify({"profiles":{},"count":0})

@app.route("/get_profile/<app_name>")
def get_profile(app_name):
    if os.path.exists(PROFILE_FILE):
        try:
            profiles = json.load(open(PROFILE_FILE))
            key = app_name.lower()
            if key in profiles:
                return jsonify({"app":app_name,"profile":profiles[key]})
        except: pass
    return jsonify({"app":app_name,"profile":None}), 404

@app.route("/get_behavior_alerts")
def get_behavior_alerts():
    return jsonify({"alerts":behavior_alerts[-20:],"total":len(behavior_alerts)})

@app.route("/get_timeline")
def get_timeline(): return jsonify(TIMELINE_DATA)

@app.route("/log_action", methods=["POST"])
def log_action_route():
    data = request.json or {}
    app_name = data.get("app","unknown")
    action   = data.get("action","unknown")
    score    = data.get("score", None)
    if action not in ("blocked","killed","trusted"):
        return jsonify({"error":"invalid action"}), 400
    _log_action_internal(app_name, action, score)
    return jsonify({"status":"logged","history_length":len(TIMELINE_DATA["history"])})

@app.route("/clear_timeline", methods=["POST"])
def clear_timeline():
    global TIMELINE_DATA
    TIMELINE_DATA = {"history":[],"blocked":0,"killed":0,"trusted":0,"score":0,"appCounts":{}}
    save_timeline()
    return jsonify({"status":"cleared"})

# ── Kill / Block / Trust ──────────────────────────────────────────────────────
def _kill_proc(name):
    if not name or name.lower() in PROTECTED_SYSTEM_APPS:
        return
    for p in psutil.process_iter(['name']):
        try:
            if p.info['name'] and p.info['name'].lower()==name: p.kill()
        except: pass

@app.route("/kill/<app_name>")
def kill(app_name):
    al = app_name.lower()
    if al in PROTECTED_SYSTEM_APPS:
        return jsonify({"msg": f"{app_name} is a protected system component", "fatigue": fatigue_state}), 400
    _kill_proc(al)
    TEMP_KILLED.add(al)
    remove_from_data(al)
    _log_action_internal(app_name,"killed")
    fatigue_state["actions"]+=1; fatigue_state["total"]+=1; fatigue_state["ignore_streak"]=0
    _add_kill_chain_event(app_name, "killed", source="dashboard")
    return jsonify({"msg":f"{app_name} killed","fatigue":fatigue_state})

@app.route("/block/<app_name>")
def block(app_name):
    al = app_name.lower()
    if al in PROTECTED_SYSTEM_APPS:
        return jsonify({"msg": f"{app_name} is a protected system component", "fatigue": fatigue_state}), 400
    _kill_proc(al)
    BLOCKED_APPS.add(al); KILLED_APPS.add(al); TEMP_KILLED.add(al)
    save_blocked(); save_killed()
    remove_from_data(al)
    _log_action_internal(app_name,"blocked")
    fatigue_state["actions"]+=1; fatigue_state["total"]+=1; fatigue_state["ignore_streak"]=0
    _add_kill_chain_event(app_name, "blocked", source="dashboard")
    return jsonify({"msg":f"{app_name} blocked","fatigue":fatigue_state})

@app.route("/trust/<app_name>")
def trust(app_name):
    al = app_name.lower()
    TRUSTED_APPS.add(al)
    BLOCKED_APPS.discard(al); KILLED_APPS.discard(al); TEMP_KILLED.discard(al)
    save_trusted(); save_blocked(); save_killed()
    _log_action_internal(app_name,"trusted")
    fatigue_state["actions"]+=1; fatigue_state["total"]+=1; fatigue_state["ignore_streak"]=0
    _add_kill_chain_event(app_name, "trusted", source="dashboard")
    return jsonify({"msg":"trusted","fatigue":fatigue_state})

@app.route("/respond/<alert_msg>/<action>")
def respond(alert_msg, action):
    if action=="ignore":
        fatigue_state["score"]         = min(20.0, fatigue_state["score"]+3.0)
        fatigue_state["ignored"]      += 1
        fatigue_state["total"]        += 1
        fatigue_state["ignore_streak"]+= 1
        lvl = "High" if "HIGH" in alert_msg.upper() else "Medium" if "MEDIUM" in alert_msg.upper() else "Low"
        fatigue_state["heat"][lvl] = fatigue_state["heat"].get(lvl,0)+1
    elif action=="ack":
        fatigue_state["score"]         = max(0.0, fatigue_state["score"]-1.0)
        fatigue_state["actions"]      += 1
        fatigue_state["total"]        += 1
        fatigue_state["ignore_streak"] = 0
    elif action=="snooze":
        fatigue_state["total"] += 1
    return jsonify({"status":"ok","alert":alert_msg,"action":action,"fatigue":fatigue_state})

@app.route("/get_fatigue_state")
def get_fatigue_state():
    with _critical_lock:
        crit = dict(_critical_escalation_state)
    resp = dict(fatigue_state)
    resp["critical_escalation"] = crit
    return jsonify(resp)

# ── simulate_attack ───────────────────────────────────────────────────────────
@app.route("/simulate_attack")
def simulate_attack():
    global _sim_attack_active, _sim_data

    with _kill_chain_lock:
        _kill_chain_events.clear()
        _save_kill_chain()

    sim_sus = [
        {"app":"weird_script.exe","reasons":["ML anomaly detected","CPU spike (85% vs normal 10%)"],"severity":58},
        {"app":"svchost32.exe","reasons":["Impersonating svchost.exe","Unusual parent process: cmd.exe"],"severity":62},
        {"app":"updater_fake.exe","reasons":["Connects to unknown IP 45.33.32.156","No digital signature"],"severity":55},
        {"app":"mimikatz_mod.exe","reasons":["LSASS memory read attempt","Credential dump pattern matched"],"severity":75}
    ]
    sim_hi  = [
        {"app":"exploit_kit.exe","reasons":["CVE-2024-1234 exploitation attempt","Privilege escalation via token impersonation"],"severity":96},
        {"app":"trojan.exe","reasons":["⚠ Behavior violation: Running at unusual time","Thread explosion detected"],"severity":92},
        {"app":"keylogger.exe","reasons":["Keystroke capture detected","Hidden process — not in task list"],"severity":95},
        {"app":"ransomware.exe","reasons":["Mass file encryption started","Shadow copy deletion attempt"],"severity":98},
        {"app":"backdoor.exe","reasons":["Reverse shell spawned on port 4444","Persistence via registry Run key"],"severity":94}
    ]
    with data_lock:
        _sim_attack_active        = True
        _sim_data["suspicious"]   = list(sim_sus)
        _sim_data["high_risk"]    = list(sim_hi)
        latest_data["suspicious"] = list(sim_sus)
        latest_data["high_risk"]  = list(sim_hi)
        for s in sim_sus + sim_hi:
            if s["app"] not in latest_data["running"]:
                latest_data["running"].append(s["app"])

    now = time.strftime("%H:%M:%S")
    for s in sim_hi + sim_sus:
        for r in s.get("reasons", []):
            behavior_alerts.append({"app": s["app"], "violation": f"⚠ Behavior violation: {r}" if "Behavior violation" not in r else r, "time": now, "severity": s.get("severity", 80)})
    while len(behavior_alerts) > MAX_BEHAVIOR_ALERTS:
        behavior_alerts.pop(0)

    with _critical_lock:
        _critical_escalation_state["active"]        = False
        _critical_escalation_state["ignored_count"] = 0
        _critical_escalation_state["ignored_apps"]  = []
        _critical_escalation_state["fatigue_score"] = 0.0
        _critical_escalation_state["triggered_at"]  = None

    try:
        requests.get("http://127.0.0.1:5001/start_popups", timeout=1)
    except Exception:
        pass

    return jsonify({"status":"simulated", "high_risk": sim_hi, "suspicious": sim_sus})


# ════════════════════════════════════════════════════════════════
# ── KILL CHAIN API ROUTES ────────────────────────────────────────
# ════════════════════════════════════════════════════════════════

@app.route("/api/killchain", methods=["GET"])
def api_get_killchain():
    with _kill_chain_lock:
        events = list(_kill_chain_events)

    stage_counts = {s: 0 for s in KILL_CHAIN_STAGES}
    for ev in events:
        tactic = ev.get("tactic", "")
        if tactic in stage_counts:
            stage_counts[tactic] += 1

    active_stages = [s for s in KILL_CHAIN_STAGES if stage_counts[s] > 0]

    return jsonify({
        "events":        events,
        "total":         len(events),
        "stage_counts":  stage_counts,
        "active_stages": active_stages,
        "stages":        KILL_CHAIN_STAGES,
    })

@app.route("/api/killchain/add", methods=["POST"])
def api_add_killchain():
    data    = request.json or {}
    app_nm  = data.get("app", "unknown.exe")
    action  = data.get("action", "ignored")
    reasons = data.get("reasons", [])
    sev     = data.get("severity", 50)
    source  = data.get("source", "notifier")

    event = _add_kill_chain_event(app_nm, action, reasons, sev, source)

    if action == "ignored":
        fatigue_state["score"]         = min(20.0, fatigue_state["score"] + 3.0)
        fatigue_state["ignored"]      += 1
        fatigue_state["total"]        += 1
        fatigue_state["ignore_streak"]+= 1

    print(f"[App] 🔗 Kill Chain event: {app_nm} → {action} [{event['tactic']}]")
    return jsonify({"status": "added", "event": event})
@app.route("/api/sync_fatigue", methods=["POST"])
def api_sync_fatigue():
    """Called by dashboard to sync its frontend fatigue counters to backend."""
    data = request.json or {}
    total   = data.get("total",   None)
    ignored = data.get("ignored", None)
    actions = data.get("actions", None)
    score   = data.get("score",   None)
    streak  = data.get("streak",  None)

    if total   is not None: fatigue_state["total"]          = total
    if ignored is not None: fatigue_state["ignored"]        = ignored
    if actions is not None: fatigue_state["actions"]        = actions
    if score   is not None: fatigue_state["score"]          = float(score)
    if streak  is not None: fatigue_state["ignore_streak"]  = streak

    return jsonify({"status": "synced", "fatigue": fatigue_state})

@app.route("/api/killchain/clear", methods=["POST"])
def api_clear_killchain():
    with _kill_chain_lock:
        _kill_chain_events.clear()
        _save_kill_chain()
    return jsonify({"status": "cleared"})

@app.route("/api/killchain/reconstruct", methods=["GET"])
def api_reconstruct_killchain():
    with _kill_chain_lock:
        events = list(_kill_chain_events)

    if not events:
        return jsonify({"story": [], "summary": "No events recorded yet."})

    tactic_groups = {}
    for ev in events:
        t = ev.get("tactic", "Unknown")
        if t not in tactic_groups:
            tactic_groups[t] = []
        tactic_groups[t].append(ev)

    story = []
    for stage in KILL_CHAIN_STAGES:
        if stage in tactic_groups:
            evs = tactic_groups[stage]
            apps_list = list({e["app"] for e in evs})
            actions   = [e["action"] for e in evs]
            times     = [e["time"]   for e in evs]
            color     = evs[0].get("color", "warn")
            story.append({
                "stage":       stage,
                "technique":   evs[0].get("technique", "T????"),
                "apps":        apps_list,
                "actions":     actions,
                "times":       times,
                "count":       len(evs),
                "color":       color,
                "description": _stage_description(stage, apps_list, actions),
            })

    ignored  = sum(1 for e in events if e["action"] == "ignored")
    actioned = sum(1 for e in events if e["action"] in ("blocked","killed","trusted"))
    summary  = (
        f"Attack used {len(story)} MITRE tactic(s) across {len(events)} events. "
        f"{ignored} ignored, {actioned} actioned."
    )

    return jsonify({"story": story, "summary": summary, "total_events": len(events)})


def _stage_description(stage, apps, actions):
    app_str = ", ".join(apps[:3])
    ign     = actions.count("ignored")
    blk     = actions.count("blocked")
    kil     = actions.count("killed")
    trs     = actions.count("trusted")

    base = {
        "Reconnaissance":    f"Attacker probed system via {app_str}.",
        "Initial Access":    f"Entry gained through {app_str}.",
        "Execution":         f"Malicious code ran: {app_str}.",
        "Persistence":       f"Persistence established by {app_str}.",
        "Defense Evasion":   f"Detection avoided by {app_str}.",
        "Credential Access": f"Credentials targeted by {app_str}.",
        "Discovery":         f"System info gathered by {app_str}.",
        "Lateral Movement":  f"Network spread attempted via {app_str}.",
        "Collection":        f"Data collected by {app_str}.",
        "Command & Control": f"C2 channel opened by {app_str}.",
        "Exfiltration":      f"Data exfiltrated by {app_str}.",
        "Impact":            f"System damage caused by {app_str}.",
        "Resource Hijacking":f"Resources hijacked by {app_str}.",
    }.get(stage, f"{app_str} triggered this stage.")

    notes = []
    if ign > 0:  notes.append(f"! {ign} alert(s) ignored")
    if blk > 0:  notes.append(f"OK {blk} blocked")
    if kil > 0:  notes.append(f"OK {kil} killed")
    if trs > 0:  notes.append(f"OK {trs} trusted")
    return base + (" | " + " · ".join(notes) if notes else "")


# ════════════════════════════════════════════════════════════════════════════════
# ── SECURITY COPILOT BRAIN  (Upgraded Guardian — Analyst Tone)
# ════════════════════════════════════════════════════════════════════════════════

# ── Memory Brain ──────────────────────────────────────────────────────────────
soc_memory = {
    "incidents":        [],
    "app_history":      {},
    "analyst_actions":  [],
    "unresolved_alerts":[],
    "conversation":     [],
    "session_start":    time.strftime("%H:%M:%S"),
    "achievements":     [],
    "alerts_reviewed":  0,
    "consecutive_actions": 0,
    "last_achievement_time": 0,
    "startup_sent":     False,
}

# ── Trust Brain ────────────────────────────────────────────────────────────────
trust_scores = {}

KNOWN_SAFE = {"chrome.exe","msedge.exe","explorer.exe","code.exe","python.exe",
              "notepad.exe","taskmgr.exe","svchost.exe","system"}
KNOWN_BAD  = {"trojan.exe","malware.exe","ransomware.exe","keylogger.exe",
              "mimikatz.exe","backdoor.exe","cryptominer.exe","spyware.exe",
              "worm.exe","rootkit.dll","netcat.exe","nc.exe","meterpreter.exe"}

def _get_trust_score(app_name):
    al = app_name.lower()
    if al in trust_scores:
        return trust_scores[al]
    if al in KNOWN_SAFE:
        trust_scores[al] = 95
    elif al in KNOWN_BAD:
        trust_scores[al] = 5
    else:
        trust_scores[al] = 60
    return trust_scores[al]

def _decay_trust(app_name, reason_text):
    al = app_name.lower()
    score = _get_trust_score(app_name)
    r = reason_text.lower()
    if "trojan" in al or "malware" in al or "ransom" in al:
        score = max(0, score - 40)
    elif "cpu spike" in r or "behavior violation" in r:
        score = max(0, score - 20)
    elif "ml anomaly" in r:
        score = max(0, score - 10)
    elif "time anomaly" in r:
        score = max(0, score - 15)
    elif "thread" in r:
        score = max(0, score - 12)
    trust_scores[al] = score
    return score

def _compute_trust_from_data():
    with data_lock:
        sus  = list(latest_data["suspicious"])
        high = list(latest_data["high_risk"])
    for obj in sus + high:
        name = obj.get("app","")
        for r in obj.get("reasons",[]):
            _decay_trust(name, r)

# ── Threat Brain ───────────────────────────────────────────────────────────────
def _compute_threat_level():
    ts = TIMELINE_DATA.get("score", 0)
    with data_lock:
        hr = len(latest_data["high_risk"])
        sus = len(latest_data["suspicious"])
    fatigue = fatigue_state.get("score", 0)
    ignored = fatigue_state.get("ignored", 0)

    combined = ts + hr * 15 + sus * 5 + ignored * 3
    if combined >= 70 or hr >= 3:
        return "CRITICAL", combined
    elif combined >= 40 or hr >= 1:
        return "HIGH", combined
    elif combined >= 20 or sus >= 2:
        return "MEDIUM", combined
    else:
        return "LOW", combined

def _compute_threat_breakdown():
    ts = TIMELINE_DATA.get("score", 0)
    with data_lock:
        hr  = len(latest_data["high_risk"])
        sus = len(latest_data["suspicious"])
    with _kill_chain_lock:
        kc = list(_kill_chain_events)
    fatigue = fatigue_state.get("score", 0)
    ignored = fatigue_state.get("ignored", 0)

    items = []
    tactic_contributions = {}
    for ev in kc:
        t = ev.get("tactic","")
        if t:
            tactic_contributions[t] = tactic_contributions.get(t,0) + 1

    sorted_tactics = sorted(tactic_contributions.items(), key=lambda x: x[1], reverse=True)[:4]
    for tactic, count in sorted_tactics:
        pts = count * 10
        items.append({"label": tactic, "points": pts, "type": "tactic"})

    if hr > 0:
        items.append({"label": f"{hr} High-Risk Application(s)", "points": hr*15, "type": "hr"})
    if sus > 0:
        items.append({"label": f"{sus} Suspicious Application(s)", "points": sus*5, "type": "sus"})
    if ignored > 0:
        items.append({"label": f"{ignored} Ignored Alert(s)", "points": ignored*3, "type": "ignored"})

    total = sum(i["points"] for i in items)
    return items, min(total, 100)

# ── Prediction Brain ───────────────────────────────────────────────────────────
ATTACK_PROGRESSIONS = {
    "Execution":         [("Persistence", 75), ("Defense Evasion", 60), ("Credential Access", 50)],
    "Initial Access":    [("Execution", 85), ("Persistence", 65)],
    "Persistence":       [("Credential Access", 70), ("Lateral Movement", 55), ("Defense Evasion", 60)],
    "Credential Access": [("Lateral Movement", 80), ("Collection", 65), ("Command & Control", 55)],
    "Lateral Movement":  [("Collection", 70), ("Command & Control", 65), ("Exfiltration", 50)],
    "Command & Control": [("Exfiltration", 75), ("Impact", 60), ("Collection", 55)],
    "Collection":        [("Exfiltration", 80), ("Command & Control", 55)],
    "Defense Evasion":   [("Credential Access", 60), ("Lateral Movement", 50)],
    "Discovery":         [("Lateral Movement", 55), ("Credential Access", 45)],
    "Exfiltration":      [("Impact", 70)],
}

def _predict_next_steps():
    with _kill_chain_lock:
        events = list(_kill_chain_events)
    if not events:
        return []
    active_tactics = list({e.get("tactic","") for e in events[-5:]})
    predictions = []
    seen = set()
    for tactic in active_tactics:
        nexts = ATTACK_PROGRESSIONS.get(tactic, [])
        for next_tactic, prob in nexts:
            if next_tactic not in seen:
                seen.add(next_tactic)
                predictions.append((next_tactic, prob))
    predictions.sort(key=lambda x: x[1], reverse=True)
    return predictions[:3]

# ── Fatigue Brain ──────────────────────────────────────────────────────────────
def _get_fatigue_level():
    score = fatigue_state.get("score", 0)
    ignored = fatigue_state.get("ignored", 0)
    streak = fatigue_state.get("ignore_streak", 0)
    if score >= 15 or streak >= 5:
        return "CRITICAL_FATIGUE"
    elif score >= 8 or streak >= 3:
        return "HIGH_FATIGUE"
    elif score >= 4 or ignored >= 3:
        return "MODERATE_FATIGUE"
    else:
        return "NORMAL"

# ── Attack Correlation Brain ───────────────────────────────────────────────────
ATTACK_PATTERNS = [
    {
        "name": "Ransomware Attack Chain",
        "tactics": {"Execution","Persistence","Impact"},
        "description": "A ransomware chain is forming. Files may be encrypted soon.",
        "priority": "CRITICAL",
        "actions": ["Kill the ransomware process IMMEDIATELY", "Disconnect from network", "Do NOT pay ransom — contact IT Security"],
    },
    {
        "name": "Credential Harvesting Operation",
        "tactics": {"Execution","Credential Access","Lateral Movement"},
        "description": "Attacker is harvesting credentials and moving laterally across the network.",
        "priority": "CRITICAL",
        "actions": ["Block credential-dumping tools", "Change all passwords NOW", "Isolate affected machines"],
    },
    {
        "name": "Persistence & Backdoor Installation",
        "tactics": {"Execution","Persistence","Defense Evasion"},
        "description": "Attacker is planting a backdoor to maintain long-term access.",
        "priority": "HIGH",
        "actions": ["Kill suspicious processes", "Audit startup items and registry", "Run a full malware scan"],
    },
    {
        "name": "Command & Control Beaconing",
        "tactics": {"Command & Control","Exfiltration"},
        "description": "A C2 channel is open. Data may already be leaving your network.",
        "priority": "HIGH",
        "actions": ["Block outbound connections on suspicious ports", "Review network logs", "Disconnect affected host from LAN"],
    },
    {
        "name": "Lateral Movement Campaign",
        "tactics": {"Lateral Movement","Discovery","Credential Access"},
        "description": "Attacker is spreading through your network using stolen credentials.",
        "priority": "CRITICAL",
        "actions": ["Isolate affected endpoints", "Revoke compromised credentials", "Enable network segmentation"],
    },
    {
        "name": "Data Exfiltration Attempt",
        "tactics": {"Collection","Exfiltration","Command & Control"},
        "description": "Sensitive data is being staged and transferred out of your environment.",
        "priority": "CRITICAL",
        "actions": ["Block outbound traffic immediately", "Identify what data was accessed", "File incident report"],
    },
]

def _correlate_attacks():
    with _kill_chain_lock:
        events = list(_kill_chain_events)
    if not events:
        return []
    active_tactics = set(e.get("tactic","") for e in events)
    matched = []
    for pattern in ATTACK_PATTERNS:
        overlap = pattern["tactics"] & active_tactics
        if len(overlap) >= 2:
            confidence = int((len(overlap) / len(pattern["tactics"])) * 100)
            matched.append({**pattern, "confidence": confidence, "matched_tactics": list(overlap)})
    matched.sort(key=lambda x: x["confidence"], reverse=True)
    return matched

# ── Timeline Brain ─────────────────────────────────────────────────────────────
_event_timeline = []
_timeline_lock  = threading.Lock()

def _add_timeline_event(app_name, description, severity=0):
    with _timeline_lock:
        _event_timeline.append({
            "time": time.strftime("%H:%M:%S"),
            "app": app_name,
            "description": description,
            "severity": severity,
        })
        if len(_event_timeline) > 200:
            _event_timeline.pop(0)

def _get_recent_events(minutes=10):
    with _timeline_lock:
        events = list(_event_timeline)
    return events[-20:]

# ── Achievement Engine ─────────────────────────────────────────────────────────
ACHIEVEMENTS_POOL = [
    {"id":"alert_guardian",    "icon":"🏆", "title":"Alert Guardian",      "desc":"Reviewed 10 alerts without ignoring any.",   "condition": lambda ctx: ctx["actions_count"] >= 10 and ctx["ignored_count"] == 0},
    {"id":"threat_hunter",     "icon":"🔍", "title":"Threat Hunter",        "desc":"Successfully investigated 5 suspicious apps.", "condition": lambda ctx: ctx["actions_count"] >= 5},
    {"id":"fatigue_resistant", "icon":"💪", "title":"Fatigue Resistant",    "desc":"No alert fatigue detected this session.",    "condition": lambda ctx: ctx["fatigue_score"] < 4 and ctx["actions_count"] >= 3},
    {"id":"first_block",       "icon":"🛡", "title":"First Line of Defense","desc":"Blocked your first malicious application.",  "condition": lambda ctx: TIMELINE_DATA.get("blocked",0) >= 1},
    {"id":"chain_breaker",     "icon":"⛓", "title":"Chain Breaker",        "desc":"Disrupted an active kill chain.",            "condition": lambda ctx: len(ctx["kc_events"]) >= 3 and ctx["actions_count"] >= 1},
    {"id":"zero_tolerance",    "icon":"🎯", "title":"Zero Tolerance",       "desc":"Blocked 3+ apps in one session.",            "condition": lambda ctx: TIMELINE_DATA.get("blocked",0) >= 3},
]

def _check_achievements(ctx):
    earned = []
    now = time.time()
    if now - soc_memory.get("last_achievement_time", 0) < 30:
        return []
    for ach in ACHIEVEMENTS_POOL:
        aid = ach["id"]
        if aid not in soc_memory["achievements"]:
            try:
                if ach["condition"](ctx):
                    soc_memory["achievements"].append(aid)
                    soc_memory["last_achievement_time"] = now
                    earned.append({
                        "id": ach["id"],
                        "icon": ach["icon"],
                        "title": ach["title"],
                        "desc": ach["desc"]
                    })
                    break
            except: pass
    return earned

# ── Next Best Action Engine ────────────────────────────────────────────────────
def _next_best_action(ctx):
    hr  = ctx["high_risk"]
    sus = ctx["suspicious"]
    kc  = ctx["kc_events"]
    corrs = ctx["correlations"]

    if not hr and not sus:
        return None

    all_apps = hr + sus
    all_apps.sort(key=lambda x: x.get("severity",0), reverse=True)
    top = all_apps[0]
    ts  = _get_trust_score(top.get("app",""))
    sev = top.get("severity",0)

    total_sev = sum(a.get("severity",0) for a in all_apps) or 1
    reduction = round((sev / total_sev) * 100)

    if ts < 25 or sev >= 80:
        recommended = f"BLOCK {top.get('app','?')} immediately"
        priority = "CRITICAL"
    elif sev >= 50:
        recommended = f"Kill and investigate {top.get('app','?')}"
        priority = "HIGH"
    else:
        recommended = f"Monitor {top.get('app','?')} closely"
        priority = "MEDIUM"

    return {
        "app": top.get("app","?"),
        "action": recommended,
        "risk_reduction": reduction,
        "priority": priority,
        "reason": top.get("reasons",["Unknown activity"])[0] if top.get("reasons") else "Anomaly detected",
    }

# ── Attack Storyteller ─────────────────────────────────────────────────────────
TACTIC_STORY_MAP = {
    "Reconnaissance":    "The attacker began by exploring your system — gathering information quietly.",
    "Initial Access":    "A foothold was established. The attacker found a way in.",
    "Execution":         "Malicious code started running on your system.",
    "Persistence":       "The attacker planted a backdoor to survive reboots and stay hidden.",
    "Defense Evasion":   "Steps were taken to hide from your security tools.",
    "Credential Access": "The attacker started stealing credentials — usernames and passwords.",
    "Discovery":         "Your system's layout, users, and data were being mapped out.",
    "Lateral Movement":  "The attacker began moving to other machines on your network.",
    "Collection":        "Valuable data is being gathered and prepared for theft.",
    "Command & Control": "A secret communication channel was opened with the attacker's server.",
    "Exfiltration":      "Data started leaving your network — possibly already stolen.",
    "Impact":            "The attacker is now causing direct damage — encryption, deletion, or disruption.",
    "Resource Hijacking":"Your computing power is being stolen — possibly for crypto mining.",
}

def _build_attack_story(kc_events):
    if not kc_events:
        return []
    seen_tactics = {}
    for ev in kc_events:
        t = ev.get("tactic","")
        if t and t not in seen_tactics:
            seen_tactics[t] = ev
    story = []
    for stage in KILL_CHAIN_STAGES:
        if stage in seen_tactics:
            ev = seen_tactics[stage]
            story.append({
                "tactic": stage,
                "app": ev.get("app","?"),
                "narrative": TACTIC_STORY_MAP.get(stage, f"Activity detected at {stage} stage."),
                "action": ev.get("action","unknown"),
                "color": ev.get("color","warn"),
            })
    return story

# ── Impact Analysis Engine ─────────────────────────────────────────────────────
def _impact_if_ignored(ctx):
    hr  = ctx["high_risk"]
    sus = ctx["suspicious"]
    threat_level = ctx["threat_level"]
    preds = ctx["predictions"]
    corrs = ctx["correlations"]

    if not hr and not sus:
        return {
            "risk_increase": 0,
            "consequence": "No active threats to worry about right now.",
            "recommendation": "Continue monitoring.",
            "severity": "LOW",
        }

    top = (hr + sus)[0] if (hr + sus) else None
    sev = top.get("severity",0) if top else 0

    if threat_level == "CRITICAL":
        risk_increase = 35
        consequence = "The attacker could gain full control of your system. Data theft or ransomware encryption is highly likely."
        severity = "CRITICAL"
    elif threat_level == "HIGH":
        risk_increase = 22
        consequence = "The threat will escalate. Lateral movement or credential theft could begin within minutes."
        severity = "HIGH"
    elif sev >= 60:
        risk_increase = 15
        consequence = "The suspicious process will continue unchecked and may escalate to a full attack."
        severity = "MEDIUM"
    else:
        risk_increase = 8
        consequence = "Low-level activity may grow. It's worth a quick look."
        severity = "LOW"

    next_step = preds[0][0] if preds else None
    rec = f"Investigate and take action now to prevent {next_step}." if next_step else "Investigate the flagged process immediately."

    return {
        "risk_increase": risk_increase,
        "consequence": consequence,
        "recommendation": rec,
        "severity": severity,
    }

# ── Analyst Performance Engine ─────────────────────────────────────────────────
def _analyst_performance(ctx):
    total     = fatigue_state.get("total", 0)
    ignored   = fatigue_state.get("ignored", 0)
    actions   = fatigue_state.get("actions", 0)
    fatigue   = fatigue_state.get("score", 0)

    reviewed  = total
    efficiency = round(((actions / total) * 100) if total > 0 else 100)

    if efficiency >= 80 and fatigue < 5:
        rating = "EXCELLENT"
        rating_emoji = "🌟"
        msg = "You are performing exceptionally well. Sharp focus, decisive actions."
    elif efficiency >= 60 and fatigue < 10:
        rating = "GOOD"
        rating_emoji = "✅"
        msg = "Solid performance. Keep an eye on your fatigue level."
    elif efficiency >= 40 or fatigue < 15:
        rating = "FAIR"
        rating_emoji = "⚠"
        msg = "Some alerts are being missed. Consider slowing down and reviewing more carefully."
    else:
        rating = "NEEDS ATTENTION"
        rating_emoji = "🔴"
        msg = "High fatigue detected. You may be missing critical threats. Take a short break."

    return {
        "reviewed": reviewed,
        "efficiency": efficiency,
        "ignored": ignored,
        "actions": actions,
        "rating": rating,
        "rating_emoji": rating_emoji,
        "message": msg,
        "fatigue_score": fatigue,
    }

# ── History Memory Engine ──────────────────────────────────────────────────────
def _historical_comparison(app_name, ctx):
    hist = TIMELINE_DATA.get("history", [])
    app_lower = app_name.lower()
    past_events = [e for e in hist if e.get("app","").lower() == app_lower]

    if not past_events:
        return None

    actions_taken = [e.get("action","") for e in past_events]
    blocked_count = actions_taken.count("blocked")
    killed_count  = actions_taken.count("killed")
    trusted_count = actions_taken.count("trusted")

    last_action = past_events[-1]
    times_seen  = len(past_events)

    return {
        "app": app_name,
        "times_seen": times_seen,
        "blocked": blocked_count,
        "killed": killed_count,
        "trusted": trusted_count,
        "last_action": last_action.get("action","unknown"),
        "last_time": last_action.get("time","?"),
        "similar_now": True,
    }

# ── Confidence Engine ──────────────────────────────────────────────────────────
def _compute_confidence(ctx):
    kc = ctx["kc_events"]
    hr = ctx["high_risk"]
    sus = ctx["suspicious"]
    corrs = ctx["correlations"]

    base = 55
    if len(kc) >= 5:  base += 15
    elif len(kc) >= 2: base += 8
    if hr:  base += 12
    if sus: base += 6
    if corrs and corrs[0].get("confidence",0) >= 70: base += 10
    return min(base, 97)

# ── Build Full Security Context ────────────────────────────────────────────────
def _build_soc_context():
    with data_lock:
        running    = list(latest_data["running"])
        suspicious = list(latest_data["suspicious"])
        high_risk  = list(latest_data["high_risk"])

    with _kill_chain_lock:
        kc_events = list(_kill_chain_events)

    timeline_hist = TIMELINE_DATA.get("history", [])
    threat_level, threat_score = _compute_threat_level()
    fatigue_level = _get_fatigue_level()
    predictions   = _predict_next_steps()
    correlations  = _correlate_attacks()
    _compute_trust_from_data()

    active_tactics = list({e.get("tactic","") for e in kc_events})
    ignored_count  = fatigue_state.get("ignored", 0)
    actions_count  = fatigue_state.get("actions", 0)
    streak         = fatigue_state.get("ignore_streak", 0)
    fatigue_score  = fatigue_state.get("score", 0)
    recent_bv      = behavior_alerts[-5:]
    confidence     = _compute_confidence({
        "kc_events": kc_events, "high_risk": high_risk,
        "suspicious": suspicious, "correlations": correlations,
    })

    return {
        "running": running,
        "suspicious": suspicious,
        "high_risk": high_risk,
        "kc_events": kc_events,
        "active_tactics": active_tactics,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "fatigue_level": fatigue_level,
        "fatigue_score": fatigue_score,
        "ignored_count": ignored_count,
        "actions_count": actions_count,
        "ignore_streak": streak,
        "predictions": predictions,
        "correlations": correlations,
        "recent_bv": recent_bv,
        "timeline_hist": timeline_hist[-10:],
        "blocked": list(BLOCKED_APPS),
        "trusted": list(TRUSTED_APPS),
        "confidence": confidence,
    }


# ════════════════════════════════════════════════════════════════════════════════
# ── GUARDIAN RESPONSE ENGINE  (Upgraded Analyst Tone)
# ════════════════════════════════════════════════════════════════════════════════

def _copilot_respond(question, ctx):
    q = question.lower().strip()
    hr  = ctx["high_risk"]
    sus = ctx["suspicious"]
    kc  = ctx["kc_events"]
    threat_level  = ctx["threat_level"]
    fatigue_level = ctx["fatigue_level"]
    preds  = ctx["predictions"]
    corrs  = ctx["correlations"]
    ignored = ctx["ignored_count"]
    streak  = ctx["ignore_streak"]
    bv      = ctx["recent_bv"]
    running = ctx["running"]
    blocked = ctx["blocked"]
    trusted = ctx["trusted"]
    fatigue_score = ctx["fatigue_score"]
    actions_count = ctx["actions_count"]
    threat_score  = ctx["threat_score"]
    confidence    = ctx.get("confidence", 70)

    simple_mode = fatigue_level in ("CRITICAL_FATIGUE", "HIGH_FATIGUE")

    prev_conv = soc_memory.get("conversation", [])
    last_q = prev_conv[-1]["question"].lower() if prev_conv else ""

    def fmt_reasons(obj, max_r=2):
        reasons = obj.get("reasons", [])[:max_r]
        return " | ".join(reasons) if reasons else "unusual activity detected"

    def trust_label(score):
        if score >= 80: return "Trusted ✅"
        elif score >= 50: return "Watching ⚠"
        elif score >= 30: return "Suspicious 🔶"
        else: return "Dangerous 🚫"

    def threat_emoji(level):
        return {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(level,"⚪")

    def risk_word(sev):
        if sev >= 80: return "extremely dangerous"
        elif sev >= 60: return "quite dangerous"
        elif sev >= 40: return "moderately suspicious"
        else: return "mildly suspicious"

    def translate_reason(r):
        r = r.lower()
        if "ml anomaly" in r:
            return "it's behaving in a way our behavioral model has never seen before"
        if "cpu spike" in r:
            return "it's suddenly using much more CPU power than normal"
        if "time anomaly" in r or "unusual time" in r:
            return "it's running at an unexpected hour when it normally shouldn't be active"
        if "thread explosion" in r:
            return "it spawned an abnormally large number of threads — a classic malware sign"
        if "memory surge" in r:
            return "it's consuming far more memory than its baseline"
        if "behavior violation" in r:
            return "it deviated significantly from its normal behavioral pattern"
        if "rare app" in r or "rarely seen" in r:
            return "this app has barely been seen on this system before"
        if "lateral" in r or "lan scan" in r:
            return "it's scanning other machines on your network — a sign of spreading"
        if "credential" in r or "lsass" in r:
            return "it's trying to steal stored passwords"
        if "encryption" in r or "ransom" in r:
            return "it appears to be encrypting files — ransomware behavior"
        if "reverse shell" in r or "port 4444" in r:
            return "it opened a backdoor shell for remote control"
        if "c2" in r or "command" in r:
            return "it's communicating with an external attacker's server"
        return r

    def confidence_line(conf):
        return f"\nAssessment Confidence: {conf}%"

    app_in_q = None
    for obj in (hr + sus):
        name = obj.get("app","").lower()
        if name in q or name.replace(".exe","") in q:
            app_in_q = obj
            break

    # ═══════════════════════════════════════════════════════════════════
    # 0. GREETING DETECTION
    # ═══════════════════════════════════════════════════════════════════
    greeting_words = ["hi", "hello", "hey", "yo", "good morning", "good evening",
                      "good afternoon", "howdy", "sup", "what's up", "greetings",
                      "namaste", "hola", "bonjour"]
    is_greeting = any(q == w or q.startswith(w+" ") or q.startswith(w+",") for w in greeting_words)

    if is_greeting:
        emoji = threat_emoji(threat_level)
        parts = ["🟢 Guardian Online\n\n"]
        hour = int(time.strftime("%H"))
        if hour < 12:
            parts.append("Good morning.\n\n")
        elif hour < 17:
            parts.append("Good afternoon.\n\n")
        else:
            parts.append("Good evening.\n\n")

        if threat_level in ("CRITICAL","HIGH"):
            parts.append(f"I've been tracking some concerning activity while you were away.\n\n")
            parts.append(f"Current Status:\n")
            parts.append(f"  • Threat Level: {threat_level} {emoji}\n")
            if kc:
                active_t = list({e.get("tactic","") for e in kc[-5:]})
                parts.append(f"  • Active Kill Chain Stages: {len(active_t)}\n")
            if hr:
                parts.append(f"  • High-Risk Applications: {len(hr)}\n")
            if sus:
                parts.append(f"  • Suspicious Applications: {len(sus)}\n")
            parts.append(f"  • Analyst Fatigue: {'Low' if fatigue_score<5 else 'Medium' if fatigue_score<10 else 'High'}\n")
            if hr:
                parts.append(f"\nPriority Focus:\n{hr[0].get('app','?')} needs your attention immediately.\n")
                parts.append(f"Reason: {translate_reason(fmt_reasons(hr[0],1))}\n")
            parts.append(f"\nI'll continue monitoring. What would you like to investigate?")
        else:
            parts.append(f"Your environment appears stable at the moment.\n\n")
            parts.append(f"Monitoring:\n")
            parts.append(f"  • {len(running)} processes\n")
            if sus: parts.append(f"  • {len(sus)} applications under watch\n")
            parts.append(f"  • Threat Level: {threat_level} {emoji}\n")
            parts.append(f"\nNo suspicious activity detected recently.\n")
            parts.append(f"What would you like me to analyze?")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 0b. STARTUP MESSAGE
    # ═══════════════════════════════════════════════════════════════════
    if q == "__startup__":
        emoji = threat_emoji(threat_level)
        hour = int(time.strftime("%H"))
        greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"
        parts = [f"🟢 Guardian Online\n\n{greeting}. Security monitoring has started.\n\n"]

        parts.append(f"Environment Summary:\n")
        parts.append(f"  • Threat Level: {threat_level} {emoji}\n")
        if kc:
            active_t = list({e.get("tactic","") for e in kc[-5:]})
            parts.append(f"  • Kill Chain Stages Active: {len(active_t)}\n")
        else:
            parts.append(f"  • Kill Chain: No events recorded\n")
        parts.append(f"  • Suspicious Applications: {len(sus)}\n")
        parts.append(f"  • High-Risk Applications: {len(hr)}\n")
        parts.append(f"  • Analyst Fatigue: {'Low' if fatigue_score<5 else 'Medium' if fatigue_score<10 else 'High'}\n")

        if hr:
            parts.append(f"\nPriority Focus:\nInvestigate {hr[0].get('app','?')} — {translate_reason(fmt_reasons(hr[0],1))}.\n")
        elif sus:
            parts.append(f"\nPriority Focus:\nMonitor {sus[0].get('app','?')} — {translate_reason(fmt_reasons(sus[0],1))}.\n")
        else:
            parts.append(f"\nAll processes appear normal at this time.\n")

        parts.append(f"\nI'll continue monitoring and will alert you if anything changes.\n\n")
        parts.append(f"💡 Tip: You can also upload screenshots, PDFs, or behavior profiling images and ask me about them!")
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 1. STATUS / WHAT IS HAPPENING
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["what is happening","what's happening","what happened","going on","right now","current situation","status","what do i see","overview","situation"]):
        emoji = threat_emoji(threat_level)
        parts = []

        if threat_level == "CRITICAL":
            parts.append(f"🚨 My Assessment: Active Attack in Progress\n\n")
            parts.append(f"I'm seeing activity across multiple attack stages. This doesn't look like random noise — the pattern is consistent with a coordinated intrusion.\n\n")
        elif threat_level == "HIGH":
            parts.append(f"🟠 My Assessment: Significant Threat Activity\n\n")
            parts.append(f"There's meaningful threat activity happening right now. One or more processes are behaving in ways that concern me.\n\n")
        elif threat_level == "MEDIUM":
            parts.append(f"🟡 My Assessment: Elevated Risk\n\n")
            parts.append(f"Your environment is showing elevated risk. Nothing confirmed yet, but the activity is worth investigating.\n\n")
        else:
            parts.append(f"🟢 My Assessment: Environment Stable\n\n")
            parts.append(f"I'm not seeing evidence of compromise right now. All running processes are operating within normal behavioral ranges.\n\n")

        if hr:
            top = hr[0]
            parts.append(f"What concerns me most:\n{top.get('app','?')} — Severity {top.get('severity',0)}%\n")
            parts.append(f"Reason: {translate_reason(fmt_reasons(top, 1))}.\n")

        if sus and not hr:
            top = sus[0]
            parts.append(f"Process under watch:\n{top.get('app','?')} is behaving oddly.\n")
            parts.append(f"Reason: {translate_reason(fmt_reasons(top, 1))}.\n")

        if kc:
            active_t = list({e.get("tactic","") for e in kc[-5:]})
            parts.append(f"\nIf the pattern continues, {preds[0][0]} is likely next." if preds else "")
            parts.append(f"\nKill chain is active: {', '.join(active_t[:3])}.\n")

        if corrs:
            c = corrs[0]
            parts.append(f"\nAttack pattern identified: {c['name']} ({c['confidence']}% confidence).\n")

        parts.append(confidence_line(confidence))
        parts.append(f"\nSession: {ignored} ignored · {actions_count} actions · Fatigue {fatigue_score:.1f}/20")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 2. WHAT SHOULD I DO / NEXT BEST ACTION
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["what should i do","what do i do","what to do","next step","recommend","advise","help me","guide me","next best","action"]):
        nba = _next_best_action(ctx)

        if not nba:
            return "✅ No immediate action needed.\n\nYour environment looks stable. Keep monitoring, and don't ignore any new alerts that appear.\n\nIf you want to stay sharp, try asking me about the kill chain or any behavior violations."

        parts = [f"🎯 My Recommendation\n\n"]
        parts.append(f"→ {nba['action']}\n\n")
        parts.append(f"Why: {translate_reason(nba['reason'])}\n")
        parts.append(f"Expected risk reduction: ~{nba['risk_reduction']}%\n")
        parts.append(f"Priority: {nba['priority']}\n")

        if prev_conv and ("what is happening" in last_q or "situation" in last_q):
            parts.append(f"\nBased on the activity I described earlier, this is the single most impactful step you can take right now.\n")

        if len(hr) > 1:
            parts.append(f"\nAfter that, also address:")
            for obj in hr[1:3]:
                parts.append(f"\n  • {obj.get('app','?')} — {translate_reason(fmt_reasons(obj,1))}")

        if corrs:
            c = corrs[0]
            parts.append(f"\n\nGiven the {c['name']} pattern, also consider:")
            for i, act in enumerate(c.get("actions",[])[:2], 1):
                parts.append(f"\n  {i}. {act}")

        if simple_mode:
            parts.append(f"\n\n⚠ You've ignored {ignored} alerts. Stay focused — one missed alert at this stage could be costly.")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 2b. SUSPICIOUS APPS LIST
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["which apps are","suspicious apps","suspicious applications","list suspicious","show suspicious","what apps","watchlist","application watchlist","applications"]):
        if not hr and not sus:
            parts = ["Application Watchlist\n\n"]
            if running:
                for r in running[:8]:
                    ts = _get_trust_score(r)
                    parts.append(f"🟢 {r}\n   Normal (Trust: {ts}/100)\n\n")
            parts.append(f"I am not currently tracking any suspicious applications.\n\n")
            parts.append(f"Processes monitored: {len(running)}\n")
            parts.append(f"Flagged processes: 0\n\n")
            threat_lvl, threat_sc = _compute_threat_level()
            if threat_sc > 10:
                parts.append(f"Current threat score remains at {min(int(threat_sc),100)}/100 because of recent kill chain activity, not because of active malicious applications.")
            else:
                parts.append(f"All {len(running)} monitored processes are operating within their normal behavioral ranges.")
            return "".join(parts)

        parts = ["Application Watchlist\n\n"]
        all_apps = sorted(hr + sus, key=lambda x: x.get("severity",0), reverse=True)
        for i, obj in enumerate(all_apps[:6], 1):
            sev = obj.get("severity",0)
            ts  = _get_trust_score(obj.get("app",""))
            if sev >= 70:
                icon = "🔴"; risk = "HIGH"
            elif sev >= 40:
                icon = "🟡"; risk = "MEDIUM"
            else:
                icon = "🟡"; risk = "LOW"
            parts.append(f"{icon} {obj.get('app','?')}\n")
            parts.append(f"   Risk: {risk} (Severity {sev}%)\n")
            reasons_list = obj.get("reasons",[])
            if reasons_list:
                parts.append(f"   Reason: {translate_reason(reasons_list[0])}\n")
            parts.append(f"\n")

        most_dangerous = all_apps[0].get("app","?")
        parts.append(f"Most dangerous: {most_dangerous}")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 3. ATTACK STORY / KILL CHAIN
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["explain the attack","attack story","tell me the attack","what happened","attack progression","kill chain","mitre","attack chain","what stage","which stage","progression","how did"]):
        if not kc:
            return "🔗 No attack events recorded yet.\n\nOnce you simulate an attack or real threats appear, I'll walk you through exactly what's happening — step by step, in plain English.\n\nTry clicking 'Simulate Demo Attack' to see this in action."

        story = _build_attack_story(kc)
        if not story:
            return "🔗 Kill chain data exists but I couldn't reconstruct a clear story yet. Try again in a moment."

        parts = [f"🔗 Here's what happened — {len(kc)} events, {len(story)} MITRE stages.\n"]

        for i, step in enumerate(story, 1):
            icon = "🔴" if step["color"] == "danger" else "🟠" if step["color"] == "warn" else "🟡"
            action_txt = f" (you {step['action']} it)" if step["action"] not in ("ignored","unknown") else " ← ⚠ this was ignored"
            parts.append(f"\n{icon} Step {i} — {step['tactic']}")
            parts.append(f"\n   {step['narrative']}")
            parts.append(f"\n   App: {step['app']}{action_txt}")

        if preds:
            parts.append(f"\n\nIf the pattern continues:")
            for tactic, prob in preds[:2]:
                parts.append(f"\n  → {tactic} is {prob}% likely next")
            parts.append(f"\n\nDon't let this go further.")

        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 4. FATIGUE CHECK
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["fatigue","ignored","ignore","missed","tired","exhausted","overload","burnout","am i","analyst health","how am i holding"]):
        fl = fatigue_level

        if fl == "NORMAL":
            return f"🧠 Analyst Health\n\nYou're doing well — no signs of alert fatigue.\n\nStats:\n  • Alerts ignored: {ignored}\n  • Actions taken: {actions_count}\n  • Consecutive ignores: {streak}\n  • Fatigue score: {fatigue_score:.1f}/20\n\nStatus: FOCUSED ✅\n\nYou're on top of things. Keep it up."

        elif fl == "MODERATE_FATIGUE":
            return f"🧠 Analyst Health\n\nI'm noticing some fatigue starting to creep in.\n\nYou've ignored {ignored} alert(s) this session. Your score is at {fatigue_score:.1f}/20.\n\nThis isn't critical yet, but worth watching. It's easy to miss something important when fatigued.\n\nStatus: MODERATE FATIGUE ⚠\n\nTake a moment, review the active high-risk apps, and make sure nothing important slipped through."

        elif fl == "HIGH_FATIGUE":
            ig_apps = list({e.get("app","") for e in kc if e.get("action") == "ignored"})
            apps_str = ", ".join(ig_apps[:3]) if ig_apps else "some flagged apps"
            return f"🧠 Analyst Health\n\nWe have a fatigue problem.\n\nYou've ignored {streak} consecutive alerts. Apps you may have dismissed too quickly: {apps_str}\n\nFatigue score: {fatigue_score:.1f}/20\n\nStatus: HIGH FATIGUE 🔶\n\nI'd recommend: Stop, review the currently flagged apps before continuing. A missed critical alert at this stage could be very costly."

        else:
            return f"🧠 Analyst Health\n\nCritical fatigue detected.\n\nYou've ignored {ignored} alerts with a streak of {streak} consecutive ignores. Fatigue score: {fatigue_score:.1f}/20.\n\nStatus: CRITICAL FATIGUE 🔴\n\nStrongly recommend:\n  1. Use Emergency Lockdown to secure everything automatically\n  2. Take a proper break\n  3. Review the incident log when you return\n\nDon't push through — you will miss something critical."

    # ═══════════════════════════════════════════════════════════════════
    # 5. PERFORMANCE
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["how am i doing","performance","my score","analyst performance","rating","how good","doing well","my stats"]):
        perf = _analyst_performance(ctx)
        parts = [f"🏆 Analyst Performance\n\n"]
        parts.append(f"Alerts Reviewed: {perf['reviewed']}\n")
        parts.append(f"Response Efficiency: {perf['efficiency']}%\n")
        parts.append(f"Ignored: {perf['ignored']}\n")
        parts.append(f"Actions Taken: {perf['actions']}\n")
        parts.append(f"Fatigue Score: {perf['fatigue_score']:.1f}/20\n\n")
        parts.append(f"Rating: {perf['rating_emoji']} {perf['rating']}\n\n")
        parts.append(perf['message'])

        achievements = _check_achievements(ctx)
        if achievements:
            ach = achievements[0]
            parts.append(f"\n\n{ach['icon']} Achievement Unlocked: {ach['title']}\n{ach['desc']}")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 6. IMPACT IF IGNORED
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["ignore this","what if i ignore","what happens if","impact","consequences","risk of ignoring","skip this","dismiss"]):
        impact = _impact_if_ignored(ctx)

        if not hr and not sus:
            return "⚠ Impact Analysis\n\nHonestly? Nothing to worry about right now — no active threats.\n\nIgnoring this costs you nothing. But stay alert for new alerts."

        parts = [f"⚠ Impact Analysis\n\n"]
        parts.append(f"If you ignore the current threats:\n\n")
        parts.append(f"{impact['consequence']}\n\n")
        parts.append(f"Predicted risk increase: +{impact['risk_increase']}%\n")
        parts.append(f"Severity: {impact['severity']}\n\n")
        parts.append(f"My recommendation: {impact['recommendation']}")

        if preds:
            parts.append(f"\n\nThe attack is likely to progress to {preds[0][0]} next — {preds[0][1]}% probability.")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 7. WHY WAS [APP] FLAGGED
    # ═══════════════════════════════════════════════════════════════════
    if app_in_q and any(x in q for x in ["why","reason","flagged","suspicious","detected","what did","explain","tell me about","what is wrong"]):
        obj = app_in_q
        ts  = _get_trust_score(obj.get("app",""))
        sev = obj.get("severity",0)

        parts = [f"🔍 About {obj.get('app','?')}\n\n"]
        parts.append(f"This process is {risk_word(sev)} right now (severity {sev}%).\n\n")
        parts.append(f"Why it was flagged:\n")
        for r in obj.get("reasons",[]):
            parts.append(f"  • {translate_reason(r)}\n")

        kc_match = [e for e in kc if e.get("app","").lower() == obj.get("app","").lower()]
        if kc_match:
            tactics = list({e.get("tactic","") for e in kc_match})
            parts.append(f"\nMITRE Tactic: {', '.join(tactics)}")
            parts.append(f"\nTechnique: {kc_match[0].get('technique','?')}")

        parts.append(f"\nTrust Score: {ts}/100 — {trust_label(ts)}")

        if sev >= 80 or ts < 25:
            parts.append(f"\n\nMy assessment: Block this immediately. The evidence is strong enough to act decisively.")
        elif sev >= 50:
            parts.append(f"\n\nMy assessment: Kill the process and investigate the logs.")
        else:
            parts.append(f"\n\nMy assessment: Keep watching it. If severity exceeds 70%, take immediate action.")

        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 8. IS [APP] SAFE
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["is","safe","trusted","okay","ok","dangerous","should i trust","can i trust","is it safe"]):
        for a in blocked:
            if a.lower() in q:
                return f"🔒 Trust Check: {a}\n\nThis app is permanently BLOCKED.\n\nIt was blocked due to past malicious behavior. Do not unblock it unless you're absolutely certain it's safe."

        for a in trusted:
            if a.lower() in q:
                return f"✅ Trust Check: {a}\n\nThis app is marked TRUSTED — you've manually approved it.\n\nIt's excluded from threat scanning."

        if app_in_q:
            obj = app_in_q
            ts  = _get_trust_score(obj.get("app",""))
            sev = obj.get("severity",0)

            parts = [f"🔒 Trust Assessment: {obj.get('app','?')}\n\n"]
            parts.append(f"Trust Score: {ts}/100 — {trust_label(ts)}\n")
            parts.append(f"Severity: {sev}%\n\n")

            if ts >= 80 and sev < 30:
                parts.append("Verdict: SAFE ✅\n\nThis app appears legitimate. No active threats linked to it right now.")
            elif ts < 30 or sev >= 70:
                parts.append("Verdict: DO NOT TRUST 🚫\n\nI would not trust this application. My recommendation is to block it.\n\nReasons:\n")
                for r in obj.get("reasons",[])[:2]:
                    parts.append(f"  • {translate_reason(r)}\n")
            else:
                parts.append("Verdict: UNCERTAIN ⚠\n\nI'm not fully confident about this one. It's showing some suspicious signs but nothing conclusive yet.\n\nKeep monitoring. If severity crosses 70%, act immediately.")

            parts.append(confidence_line(confidence))
            return "".join(parts)

        if any(x in q for x in ["safe","everything","all apps","system safe","is it safe"]):
            if not hr and not sus:
                return f"✅ Trust Assessment: System\n\nYes — your system appears safe right now.\n\nNo high-risk or suspicious apps are currently detected."
            else:
                return f"⚠ Trust Assessment: System\n\nNot fully safe right now.\n\n{len(hr)} high-risk and {len(sus)} suspicious application(s) need your attention.\n\nMost urgent: {hr[0].get('app','?') if hr else sus[0].get('app','?')}"

    # ═══════════════════════════════════════════════════════════════════
    # 9. MOST DANGEROUS
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["most dangerous","highest risk","worst app","biggest threat","most risky","most critical","dangerous process","top threat","riskiest"]):
        if not hr and not sus:
            return "✅ No dangerous processes right now.\n\nAll running apps are within normal behavioral parameters."

        all_apps = sorted(hr + sus, key=lambda x: x.get("severity",0), reverse=True)
        top = all_apps[0]
        ts  = _get_trust_score(top.get("app",""))
        sev = top.get("severity",0)

        parts = [f"🔴 Most Dangerous Process\n\n"]
        parts.append(f"Application: {top.get('app','?')}\n")
        parts.append(f"Severity: {sev}% — {risk_word(sev)}\n")
        parts.append(f"Trust Score: {ts}/100 ({trust_label(ts)})\n\n")
        parts.append(f"What I'm seeing:\n")
        for r in top.get("reasons",[])[:3]:
            parts.append(f"  • {translate_reason(r)}\n")

        kc_match = [e for e in kc if e.get("app","").lower() == top.get("app","").lower()]
        if kc_match:
            parts.append(f"\nMITRE Tactic: {kc_match[0].get('tactic','?')} [{kc_match[0].get('technique','?')}]")

        parts.append(f"\n\nMy assessment: {'Block this immediately — high confidence malicious.' if ts < 30 else 'Kill the process and investigate logs.'}")

        if len(all_apps) > 1:
            others = [o.get("app","") for o in all_apps[1:3]]
            parts.append(f"\n\nAlso watch: {', '.join(others)}")

        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 10. THREAT LEVEL
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["threat level","threat score","how bad","severity","danger level","risk level","how serious","how dangerous","why critical","why is it critical","why high","why medium","why low","threat breakdown","explain threat"]):
        emoji = threat_emoji(threat_level)
        breakdown_items, computed_score = _compute_threat_breakdown()

        parts = [f"{emoji} Threat Level: {threat_level}\n\n"]

        if threat_level == "CRITICAL":
            parts.append("This is serious. Multiple attack indicators are active simultaneously.\n\nThe threat score is being driven by:\n\n")
        elif threat_level == "HIGH":
            parts.append("Significant threat activity detected. Here's what's driving the score:\n\n")
        elif threat_level == "MEDIUM":
            parts.append("Risk is elevated. Here's what I'm seeing:\n\n")
        else:
            parts.append("Your environment looks stable. Current threat contributors:\n\n")

        if breakdown_items:
            for item in breakdown_items:
                parts.append(f"  +{item['points']:>3}  {item['label']}\n")
            parts.append(f"  {'─'*25}\n")
            parts.append(f"  Total Threat Score: {min(computed_score,100)}/100\n")
        else:
            parts.append(f"  No specific threat contributors identified.\n")

        parts.append(f"\nNumbers:\n")
        parts.append(f"  • High-risk apps active: {len(hr)}\n")
        parts.append(f"  • Suspicious apps: {len(sus)}\n")
        parts.append(f"  • Kill chain events: {len(kc)}\n")
        parts.append(f"  • Alerts ignored: {ignored}\n")

        if corrs:
            parts.append(f"\n⚡ Active attack pattern: {corrs[0]['name']} ({corrs[0]['confidence']}% confidence)")

        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 11. PREDICT NEXT STEP
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["predict","next step","next attack","what comes next","will happen","next move","likely next","prediction","forecast"]):
        if not preds:
            return "🔮 Prediction\n\nNot enough data yet to make a confident prediction.\n\nI need more kill chain events to identify a pattern. Simulate an attack or interact with the alert popups, and I'll start forecasting the attacker's next move."

        parts = [f"🔮 Attack Progression Forecast\n\n"]
        parts.append(f"Based on {len(kc)} events across {len(ctx['active_tactics'])} active tactics:\n\n")

        for tactic, prob in preds:
            icon = "🔴" if prob >= 70 else "🟠" if prob >= 50 else "🟡"
            parts.append(f"{icon} {tactic} — {prob}% likely\n")

        advice_map = {
            "Credential Access":  "Protect your credentials now. Enable MFA and monitor LSASS access.",
            "Lateral Movement":   "Segment your network immediately. Disable lateral protocols.",
            "Exfiltration":       "Block outbound traffic on non-standard ports right now.",
            "Impact":             "Back up critical data NOW before it's too late.",
            "Persistence":        "Check your startup registry and scheduled tasks.",
            "Command & Control":  "Block suspicious outbound connections immediately.",
            "Collection":         "Identify what sensitive data the attacker might target.",
        }

        top_pred = preds[0][0]
        if top_pred in advice_map:
            parts.append(f"\nTo defend against {top_pred}:\n{advice_map[top_pred]}")

        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 12. MEMORY / HISTORY
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["seen this before","history","memory","historical","past","previous","before","similar incident","remember"]):
        hist = TIMELINE_DATA.get("history", [])

        if app_in_q:
            comparison = _historical_comparison(app_in_q.get("app",""), ctx)
            if comparison:
                parts = [f"🧠 Historical Record: {comparison['app']}\n\n"]
                parts.append(f"I've seen this app appear {comparison['times_seen']} time(s) in the incident log.\n\n")
                parts.append(f"Past actions:\n")
                if comparison['blocked']: parts.append(f"  • Blocked {comparison['blocked']}x\n")
                if comparison['killed']:  parts.append(f"  • Killed {comparison['killed']}x\n")
                if comparison['trusted']: parts.append(f"  • Trusted {comparison['trusted']}x\n")
                parts.append(f"\nLast seen: {comparison['last_time']} — action: {comparison['last_action'].upper()}\n\n")
                parts.append(f"Current behavior matches past incidents.\nI'd suggest the same response as last time: {comparison['last_action'].upper()}.")
                return "".join(parts)
            else:
                return f"🧠 Historical Record: {app_in_q.get('app','?')}\n\nFirst time I've seen this specific app in the incident log.\n\nNo historical data to compare against — treat this as a fresh incident and investigate carefully."

        if not hist:
            return "🧠 Session Memory\n\nNo incidents recorded yet this session.\n\nOnce you start blocking, killing, or trusting apps, I'll build a history I can reference."

        parts = [f"🧠 Session Memory\n\n"]
        parts.append(f"{len(hist)} incident(s) recorded this session.\n\n")
        parts.append(f"Recent activity:\n")
        for e in hist[-5:]:
            icon = {"blocked":"🚫","killed":"💀","trusted":"✅"}.get(e.get("action",""),"•")
            parts.append(f"  {icon} [{e.get('time','?')}] {e.get('app','?')} → {e.get('action','?').upper()}\n")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 13. SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["summarize","summary","today","incidents","report","overview","brief","recap","session"]):
        hist = TIMELINE_DATA.get("history", [])
        perf = _analyst_performance(ctx)

        parts = [f"📋 Session Summary\n\n"]
        parts.append(f"Started: {soc_memory['session_start']}\n\n")
        parts.append(f"Threat situation: {threat_emoji(threat_level)} {threat_level}\n")
        parts.append(f"Total incidents: {len(hist)}\n")
        parts.append(f"Actions — Blocked: {TIMELINE_DATA.get('blocked',0)} · Killed: {TIMELINE_DATA.get('killed',0)} · Trusted: {TIMELINE_DATA.get('trusted',0)}\n")
        parts.append(f"Alerts ignored: {ignored} · Fatigue: {fatigue_score:.1f}/20\n")
        parts.append(f"Kill chain events: {len(kc)}\n")
        parts.append(f"Your rating: {perf['rating_emoji']} {perf['rating']}\n")

        if hist:
            parts.append(f"\nRecent actions:\n")
            for e in hist[-4:]:
                icon = {"blocked":"🚫","killed":"💀","trusted":"✅"}.get(e.get("action",""),"•")
                parts.append(f"  {icon} {e.get('app','?')} at {e.get('time','?')}\n")

        if bv:
            parts.append(f"\nBehavior violations: {len(bv)}\n")
            recent_bv_apps = list({b.get("app","") for b in bv[-3:]})
            parts.append(f"Apps involved: {', '.join(recent_bv_apps)}")

        if corrs:
            parts.append(f"\n\n⚡ Attack patterns detected: {corrs[0]['name']}")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 14. BEHAVIOR VIOLATIONS
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["behavior","violation","anomal","baseline","deviation","pattern","unusual","weird","profil"]):
        if not bv:
            return "🧠 Behavior Monitor\n\nNo behavior violations detected recently.\n\nAll apps are operating within their learned behavioral baselines."

        parts = [f"🧠 Behavior Violations\n\n"]
        parts.append(f"{len(bv)} violation(s) logged recently.\n\n")

        for b in bv[-4:]:
            sev = b.get("severity", 0)
            icon = "🔴" if sev >= 70 else "🟡" if sev >= 40 else "⚪"
            viol = (b.get("violation","") or "").replace("⚠ Behavior violation: ","")
            parts.append(f"{icon} {b.get('app','?')}: {translate_reason(viol)} (Severity {sev}%)\n")

        parts.append(f"\nThese apps significantly deviated from their normal behavioral patterns.\n")
        parts.append(f"Possible causes: malware injection, resource hijacking, or a compromised process.\n\n")
        parts.append(f"My advice: Investigate the highest-severity violation first.")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 15. TRUST SCORES
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["trust score","trust decrease","trust drop","trust change","trust decay","why trust","trust report"]):
        _compute_trust_from_data()
        low_trust = [(a, s) for a, s in trust_scores.items() if s < 50]
        low_trust.sort(key=lambda x: x[1])

        parts = [f"🔒 Trust Score Report\n\n"]

        if not low_trust:
            parts.append("All monitored apps currently have acceptable trust scores.\n\nNo significant trust decay detected.")
        else:
            parts.append(f"{len(low_trust)} app(s) with low trust:\n\n")
            for app_n, score in low_trust[:5]:
                parts.append(f"  • {app_n}: {score}/100 — {trust_label(score)}\n")
                all_flagged = hr + sus
                for obj in all_flagged:
                    if obj.get("app","").lower() == app_n:
                        r = obj.get("reasons",[])[0] if obj.get("reasons") else ""
                        if r:
                            parts.append(f"    Reason: {translate_reason(r)}\n")
                        break

        parts.append(f"\nTrust decays when an app: runs at unusual hours, spikes CPU or memory, spawns too many threads, or matches known malware patterns.")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 16. PRIORITIZE ALERTS
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["prioritize","priority","first","which alert","most important","focus","urgent","which one","start with"]):
        if not hr and not sus:
            return "✅ Nothing to prioritize right now.\n\nYour alert queue is clear. Keep monitoring for new threats."

        all_alerts = sorted(hr + sus, key=lambda x: x.get("severity",0), reverse=True)
        parts = [f"⚡ Alert Triage\n\n"]

        for i, obj in enumerate(all_alerts[:4], 1):
            ts = _get_trust_score(obj.get("app",""))
            urgency = "IMMEDIATE 🔴" if obj.get("severity",0) >= 70 else "HIGH 🟠" if obj.get("severity",0) >= 50 else "REVIEW 🟡"
            parts.append(f"{i}. {obj.get('app','?')} — {urgency}\n")
            parts.append(f"   Severity {obj.get('severity',0)}% · Trust {ts}/100\n")
            parts.append(f"   {translate_reason(fmt_reasons(obj,1))}\n\n")

        parts.append(f"Start with {all_alerts[0].get('app','?')} — it's the most urgent.\n")

        nba = _next_best_action(ctx)
        if nba:
            parts.append(f"\nRecommended action: {nba['action']}")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 17. ACHIEVEMENTS
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["achievement","badge","reward","unlock","score","points","trophy","earned"]):
        earned = soc_memory.get("achievements", [])
        new_ach = _check_achievements(ctx)

        parts = [f"🏆 Security Achievements\n\n"]

        if not earned and not new_ach:
            parts.append("No achievements unlocked yet.\n\n")
            parts.append("Here's how to earn them:\n")
            for ach in ACHIEVEMENTS_POOL[:4]:
                parts.append(f"  {ach['icon']} {ach['title']}: {ach['desc']}\n")
            parts.append(f"\nKeep investigating threats and taking action to earn these.")
        else:
            if new_ach:
                for ach in new_ach:
                    parts.append(f"🎉 JUST UNLOCKED: {ach['icon']} {ach['title']}\n{ach['desc']}\n\n")
            if earned:
                parts.append(f"Achievements unlocked ({len(earned)}):\n")
                for aid in earned:
                    ach_def = next((a for a in ACHIEVEMENTS_POOL if a["id"] == aid), None)
                    if ach_def:
                        parts.append(f"  {ach_def['icon']} {ach_def['title']}: {ach_def['desc']}\n")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 18. ATTACK PATTERN
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["attack pattern","correlation","campaign","what kind of attack","type of attack","attack type","what are they doing"]):
        if not corrs:
            if kc:
                return f"🔗 Attack Correlation\n\nThe kill chain has {len(kc)} events, but I haven't identified a specific known attack pattern yet.\n\nI need at least 2 matching MITRE tactics to correlate. Keep monitoring."
            return "🔗 Attack Correlation\n\nNo attack data yet. Start the attack simulation to see correlation analysis in action."

        parts = [f"🔗 Attack Pattern Analysis\n\n"]
        for c in corrs[:2]:
            icon = "🔴" if c["priority"] == "CRITICAL" else "🟠"
            parts.append(f"{icon} {c['name']} — {c['confidence']}% confidence\n")
            parts.append(f"   {c['description']}\n")
            parts.append(f"   Matched tactics: {', '.join(c['matched_tactics'])}\n\n")
            parts.append(f"   What to do:\n")
            for act in c.get("actions",[])[:3]:
                parts.append(f"     → {act}\n")
            parts.append(f"\n")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 19. RUNNING APPS
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["running","processes","apps running","all apps","list apps","what is running","show apps","what apps"]):
        if not running:
            return "📊 Running Applications\n\nNo apps detected by the scanner right now.\n\nMake sure the app_monitor.py scanner is running."

        parts = [f"📊 Running Applications ({len(running)} total)\n\n"]
        hr_names  = {o.get("app","").lower() for o in hr}
        sus_names = {o.get("app","").lower() for o in sus}

        for a in running[:12]:
            ts = _get_trust_score(a)
            if a.lower() in hr_names:
                parts.append(f"  🔴 {a} — HIGH RISK (Trust: {ts}/100)\n")
            elif a.lower() in sus_names:
                parts.append(f"  🟡 {a} — SUSPICIOUS (Trust: {ts}/100)\n")
            else:
                parts.append(f"  🟢 {a} — Normal (Trust: {ts}/100)\n")

        if len(running) > 12:
            parts.append(f"\n  ...and {len(running)-12} more")

        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 20. BLOCKED
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["blocked","block list","permanently blocked","what is blocked"]):
        if not blocked:
            return "📋 Block List\n\nNo permanently blocked applications on this system yet."
        parts = [f"📋 Permanently Blocked Apps ({len(blocked)})\n\n"]
        for a in list(blocked)[:15]:
            parts.append(f"  🚫 {a}\n")
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # 21. EMERGENCY
    # ═══════════════════════════════════════════════════════════════════
    if any(x in q for x in ["emergency","lockdown","lock down","shut down","isolate","critical","red alert"]):
        if hr:
            parts = [f"🚨 Emergency Protocol\n\n"]
            parts.append(f"Yes — emergency action is justified right now.\n\n")
            parts.append(f"{len(hr)} high-risk app(s) active: {', '.join(o.get('app','') for o in hr[:3])}\n\n")
            parts.append(f"To execute emergency lockdown:\n")
            parts.append(f"  → Click the 🔒 EMERGENCY LOCKDOWN button in the Critical Overlay\n")
            parts.append(f"  → This will automatically kill and block ALL flagged apps\n")
            parts.append(f"  → No manual work needed — one click secures everything\n\n")
            parts.append(f"Don't wait.")
            return "".join(parts)
        else:
            return "🔒 Emergency Protocol\n\nNo emergency detected right now — your environment looks stable."

    # ═══════════════════════════════════════════════════════════════════
    # 22. APP-SPECIFIC FALLBACK
    # ═══════════════════════════════════════════════════════════════════
    if app_in_q:
        obj = app_in_q
        ts  = _get_trust_score(obj.get("app",""))
        sev = obj.get("severity",0)
        status = "HIGH RISK 🔴" if obj in hr else "SUSPICIOUS 🟡"
        parts = [f"🔍 {obj.get('app','?')}\n\n"]
        parts.append(f"Status: {status}\n")
        parts.append(f"Severity: {sev}% — {risk_word(sev)}\n")
        parts.append(f"Trust: {ts}/100 — {trust_label(ts)}\n\n")
        parts.append(f"What I'm seeing:\n")
        for r in obj.get("reasons",[]):
            parts.append(f"  • {translate_reason(r)}\n")
        parts.append(f"\nMy recommendation: {'Block it immediately' if ts < 30 else 'Kill it and investigate'}")
        parts.append(confidence_line(confidence))
        return "".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # DEFAULT FALLBACK
    # ═══════════════════════════════════════════════════════════════════
    emoji = threat_emoji(threat_level)
    parts = [f"{emoji} Guardian Assessment\n\n"]

    if hr:
        parts.append(f"I checked all running processes.\n\n")
        parts.append(f"My current concern: {hr[0].get('app','?')} is showing {risk_word(hr[0].get('severity',0))} behavior.\n\n")
        parts.append(f"The current {threat_level} score is being driven by:\n")
        for r in hr[0].get("reasons",[])[:2]:
            parts.append(f"  • {translate_reason(r)}\n")
        if preds:
            parts.append(f"\nIf the current pattern holds, {preds[0][0]} is {preds[0][1]}% likely to be the next stage.\n")
        parts.append(f"\nWould you like me to explain the attack path or recommend an action?")
    elif sus:
        parts.append(f"I checked all running processes.\n\n")
        parts.append(f"I'm watching {sus[0].get('app','?')} — it's behaving somewhat unusually.\n\n")
        parts.append(f"No confirmed compromise yet, but the activity pattern deserves attention.\n\n")
        parts.append(f"Would you like me to explain what I'm seeing or recommend next steps?")
    else:
        parts.append(f"I checked all running processes.\n\n")
        parts.append(f"No suspicious applications are active right now.\n\n")
        if kc:
            active_t = list({e.get("tactic","") for e in kc})
            parts.append(f"The current {threat_level} threat score reflects recent kill chain activity across: {', '.join(active_t[:3])}.\n\n")
            parts.append(f"These were past events — not active threats.\n\n")
        parts.append(f"Your environment appears stable. I'm continuing to monitor.\n\n")
        parts.append(f"💡 Try asking:\n  • 'What is happening right now?'\n  • 'Show attack progression'\n  • 'Am I showing fatigue?'\n  • Or upload a screenshot for analysis!")

    return "".join(parts)


# ════════════════════════════════════════════════════════════════
# ── GUARDIAN CHATBOT API ROUTE
# ════════════════════════════════════════════════════════════════

@app.route("/api/soc_assistant", methods=["POST"])
def api_soc_assistant():
    data     = request.json or {}
    question = data.get("question", "").strip()
    if not question:
        return jsonify({"answer": "Please ask a question."}), 400

    ctx    = _build_soc_context()
    answer = _copilot_respond(question, ctx)

    soc_memory["conversation"].append({
        "question": question,
        "answer":   answer,
        "time":     time.strftime("%H:%M:%S"),
    })
    if len(soc_memory["conversation"]) > 30:
        soc_memory["conversation"].pop(0)

    soc_memory["alerts_reviewed"] += 1
    _add_timeline_event("GUARDIAN_CHATBOT", f"Query: {question[:60]}", 0)

    achievements = _check_achievements(ctx)
    achievement_data = achievements[0] if achievements else None

    return jsonify({
        "answer":       answer,
        "threat_level": ctx["threat_level"],
        "fatigue_level":ctx["fatigue_level"],
        "achievement":  achievement_data,
        "confidence":   ctx.get("confidence", 70),
    })


# ════════════════════════════════════════════════════════════════
# ── STARTUP MESSAGE API
# ════════════════════════════════════════════════════════════════

@app.route("/api/guardian_startup", methods=["GET"])
def api_guardian_startup():
    ctx = _build_soc_context()
    answer = _copilot_respond("__startup__", ctx)
    soc_memory["startup_sent"] = True
    return jsonify({
        "answer":       answer,
        "threat_level": ctx["threat_level"],
        "fatigue_level":ctx["fatigue_level"],
        "confidence":   ctx.get("confidence", 70),
    })


# ════════════════════════════════════════════════════════════════
# ── PROACTIVE OBSERVATIONS
# ════════════════════════════════════════════════════════════════

@app.route("/api/soc_observation", methods=["GET"])
def api_soc_observation():
    ctx = _build_soc_context()
    observations = []
    ts = time.strftime("%H:%M:%S")

    hr  = ctx["high_risk"]
    sus = ctx["suspicious"]
    preds = ctx["predictions"]
    corrs = ctx["correlations"]
    fatigue_level = ctx["fatigue_level"]
    threat_level  = ctx["threat_level"]
    streak = ctx["ignore_streak"]
    bv = ctx["recent_bv"]
    ignored = ctx["ignored_count"]
    actions = ctx["actions_count"]
    confidence = ctx.get("confidence", 70)

    if hr:
        top = hr[0]
        observations.append({
            "type": "threat",
            "severity": "critical",
            "title": "🔔 Guardian Update",
            "message": f"New {threat_level} activity detected.\n\nThreat Score increased.\n\nRecommendation: Investigate {top.get('app','?')} immediately.",
        })

    if corrs and corrs[0]["confidence"] >= 60:
        c = corrs[0]
        observations.append({
            "type": "correlation",
            "severity": "high",
            "title": "🔔 Guardian Update",
            "message": f"Attack pattern identified: {c['name']} ({c['confidence']}% confidence).\n\n{c['description']}",
        })

    if fatigue_level in ("CRITICAL_FATIGUE","HIGH_FATIGUE") and streak >= 3:
        observations.append({
            "type": "fatigue",
            "severity": "warning",
            "title": "🔔 Guardian Update",
            "message": f"You've ignored {streak} alerts in a row.\n\nThis pattern concerns me. Review the flagged apps before continuing.",
        })

    if preds and preds[0][1] >= 75:
        next_tactic, prob = preds[0]
        observations.append({
            "type": "prediction",
            "severity": "warning",
            "title": "🔔 Guardian Update",
            "message": f"New {threat_level.lower()} activity detected.\n\nThreat Score: increased.\n\nRecommendation: {next_tactic} is {prob}% likely next. Prepare your defenses.",
        })

    if len(bv) >= 3:
        recent_apps = list({b.get("app","?") for b in bv[-3:]})
        observations.append({
            "type": "behavior",
            "severity": "warning",
            "title": "🔔 Guardian Update",
            "message": f"Behavior anomaly spike detected.\n\n{len(bv)} violations recorded.\n\nApps deviating from baseline: {', '.join(recent_apps[:3])}",
        })

    if not observations and actions >= 3 and not ignored:
        observations.append({
            "type": "positive",
            "severity": "ok",
            "title": "🔔 Guardian Update",
            "message": f"You've taken {actions} decisive actions with zero ignores this session.\n\nExcellent analyst performance.",
        })

    return jsonify({
        "observations": observations[:3],
        "threat_level": threat_level,
        "fatigue_level": fatigue_level,
        "confidence": confidence,
        "time": ts,
    })


# ════════════════════════════════════════════════════════════════
# ── FILE/IMAGE UPLOAD ANALYSIS ENDPOINT
# ════════════════════════════════════════════════════════════════

def _analyze_file_offline(filename, file_type, question, ctx):
    fname_lower = (filename or "").lower()
    q_lower     = (question or "").lower()
    hr  = ctx["high_risk"]
    sus = ctx["suspicious"]
    bv  = ctx["recent_bv"]

    parts = []

    is_image = file_type.startswith("image/")
    is_pdf   = file_type == "application/pdf"
    is_text  = "text" in file_type or fname_lower.endswith((".txt",".log",".csv",".json"))

    dangerous_keywords = ["trojan","malware","ransomware","keylogger","backdoor",
                          "exploit","mimikatz","payload","cryptominer","spyware",
                          "rootkit","netcat","meterpreter","worm","virus"]
    suspicious_keywords = ["svchost","powershell","rundll","weird","unknown","temp",
                           "tmp","update","patch","installer"]
    safe_keywords = ["chrome","msedge","explorer","notepad","python","code",
                     "system","kernel","nvidia","intel","amd"]

    detected_app = None
    for kw in dangerous_keywords:
        if kw in fname_lower:
            detected_app = ("dangerous", kw)
            break
    if not detected_app:
        for kw in suspicious_keywords:
            if kw in fname_lower:
                detected_app = ("suspicious", kw)
                break
    if not detected_app:
        for kw in safe_keywords:
            if kw in fname_lower:
                detected_app = ("safe", kw)
                break

    flagged_match = None
    for obj in (hr + sus):
        app_name = obj.get("app","").lower()
        if app_name in fname_lower or fname_lower.replace(".exe","") in app_name:
            flagged_match = obj
            break

    parts.append(f"📎 File Analysis: {filename}\n\n")

    if is_image:
        parts.append(f"I've received your screenshot/image.\n\n")
    elif is_pdf:
        parts.append(f"I've received your PDF document.\n\n")
    else:
        parts.append(f"I've received your file.\n\n")

    if any(x in q_lower for x in ["cpu","high cpu","cpu usage","cpu spike","processor","performance"]):
        parts.append("🔍 CPU Usage Analysis\n\n")

        if flagged_match:
            sev = flagged_match.get("severity", 0)
            parts.append(f"This app ({flagged_match.get('app','?')}) is currently flagged on your dashboard.\n\n")
            parts.append(f"Severity: {sev}%\n\n")
            parts.append("Why it's showing high CPU:\n")
            for r in flagged_match.get("reasons",[]):
                if "cpu" in r.lower() or "thread" in r.lower() or "ml" in r.lower():
                    parts.append(f"  • {r}\n")
            if sev >= 70:
                parts.append(f"\n🔴 High CPU + high severity = very likely malicious activity.\n")
                parts.append(f"Malware often spikes CPU for:\n")
                parts.append(f"  • Crypto mining (uses 80–100% CPU continuously)\n")
                parts.append(f"  • Encryption operations (ransomware)\n")
                parts.append(f"  • Brute-force password attacks\n")
                parts.append(f"  • Spawning many threads for lateral movement\n\n")
                parts.append(f"Recommendation: BLOCK this process immediately from the Live App Monitor.")
            else:
                parts.append(f"\n🟡 Moderate severity. Monitor and investigate before acting.\n")
                parts.append(f"Could be legitimate high-load activity or early-stage malware.")
        else:
            parts.append("Common reasons for high CPU usage in a security context:\n\n")
            parts.append("🔴 Malicious causes:\n")
            parts.append("  • Crypto mining malware (constant 80–99% CPU)\n")
            parts.append("  • Ransomware encrypting your files in background\n")
            parts.append("  • Brute-force attacks running locally\n")
            parts.append("  • Malware spawning hundreds of threads\n")
            parts.append("  • Code injection into legitimate processes\n\n")
            parts.append("🟡 Suspicious causes:\n")
            parts.append("  • CPU spike when it should be idle = red flag\n")
            parts.append("  • CPU usage 10x above the app's historical baseline\n")
            parts.append("  • Unknown process using high CPU at unusual hours\n\n")
            parts.append("🟢 Benign causes:\n")
            parts.append("  • Antivirus scanning, Windows Update, compilation\n")
            parts.append("  • Video encoding, data processing\n\n")

            if hr:
                parts.append(f"⚠ Currently on your dashboard: {hr[0].get('app','?')} is flagged HIGH RISK")
                parts.append(f" with reasons including: {hr[0].get('reasons',['?'])[0] if hr[0].get('reasons') else 'anomaly detected'}\n")
                parts.append(f"If this matches what you're seeing in your screenshot, investigate it immediately.")
            else:
                parts.append(f"Your current dashboard shows no active high-risk apps, but the behavior profiling engine may catch CPU anomalies.")

        return "".join(parts)

    if any(x in q_lower for x in ["memory","ram","mem","memory usage"]):
        parts.append("🔍 Memory Usage Analysis\n\n")
        if flagged_match:
            parts.append(f"{flagged_match.get('app','?')} is currently flagged on your dashboard.\n\n")
            parts.append(f"Security reasons for high memory:\n")
            parts.append(f"  • Memory surge: malware injecting into other processes\n")
            parts.append(f"  • Data staging before exfiltration\n")
            parts.append(f"  • Unpacking/decrypting malicious payload in memory\n")
            parts.append(f"  • Rootkits hiding in memory structures\n\n")
            for r in flagged_match.get("reasons",[]):
                if "mem" in r.lower() or "surge" in r.lower():
                    parts.append(f"  ⚠ Detected: {r}\n")
        else:
            parts.append("High memory usage security implications:\n\n")
            parts.append("  • Process consuming 10x its normal RAM = behavior violation\n")
            parts.append("  • Memory injection: malware hides inside legitimate process memory\n")
            parts.append("  • Fileless malware runs entirely in RAM — hard to detect on disk\n")
            parts.append("  • Data staging: collecting large amounts of data before sending it out\n\n")
            parts.append("Cross-reference: check the Behavior Profiling Engine panel — it shows avg RAM vs current for each app.")
        return "".join(parts)

    if any(x in q_lower for x in ["threat score","why high","score high","threat level","why is","why does","why so"]):
        parts.append("🔍 Threat Score Explanation\n\n")
        breakdown_items, computed_score = _compute_threat_breakdown()

        parts.append(f"Your current threat score: {min(computed_score, 100)}/100\n\n")
        parts.append("The score is calculated from these factors:\n\n")

        if breakdown_items:
            for item in breakdown_items:
                parts.append(f"  +{item['points']:>3} pts  {item['label']}\n")
        else:
            parts.append("  No specific contributors currently.\n")

        parts.append(f"\n📋 Breaking it down:\n")
        parts.append(f"  • Each HIGH RISK app = +15 points\n")
        parts.append(f"  • Each SUSPICIOUS app = +5 points\n")
        parts.append(f"  • Each ignored alert = +3 points (fatigue penalty)\n")
        parts.append(f"  • Each MITRE kill chain event = +10 points\n")
        parts.append(f"  • Blocking/killing apps reduces the score over time\n\n")

        if hr:
            parts.append(f"🔴 Right now: {hr[0].get('app','?')} alone is contributing {15} points.\n")
            parts.append(f"Block it to immediately reduce your threat score.")
        return "".join(parts)

    if any(x in q_lower for x in ["behavior","profiling","baseline","why flagged","reason","explain","anomaly","deviation"]):
        parts.append("🔍 Behavior Analysis\n\n")

        if flagged_match:
            app_name = flagged_match.get("app","?")
            sev = flagged_match.get("severity", 0)
            parts.append(f"App: {app_name}\n")
            parts.append(f"Severity: {sev}%\n\n")
            parts.append(f"Why it was flagged:\n")
            for r in flagged_match.get("reasons",[]):
                parts.append(f"  • {r}\n")
            parts.append(f"\n")
            parts.append(f"What this means in plain English:\n")
            for r in flagged_match.get("reasons",[]):
                r_lower = r.lower()
                if "cpu spike" in r_lower:
                    parts.append(f"  → The app suddenly started using much more CPU than it ever has before. This is a classic malware indicator.\n")
                elif "time anomaly" in r_lower or "unusual time" in r_lower:
                    parts.append(f"  → The app is running at an hour when it's not normally active. Malware often runs at night to avoid detection.\n")
                elif "thread explosion" in r_lower:
                    parts.append(f"  → It spawned far more threads than normal. This suggests aggressive scanning, attacking, or encryption operations.\n")
                elif "memory surge" in r_lower:
                    parts.append(f"  → Memory usage jumped way above its average. Could indicate data staging or memory injection.\n")
                elif "ml anomaly" in r_lower:
                    parts.append(f"  → The behavioral model says this app is acting in a way it has never seen before. Treat as high suspicion.\n")
                elif "rarely seen" in r_lower or "rare app" in r_lower:
                    parts.append(f"  → This app barely appears on your system. Unknown or rare executables are a major red flag.\n")
        else:
            parts.append("The Behavior Profiling Engine works like this:\n\n")
            parts.append("1. It watches every process for at least 10 sessions.\n")
            parts.append("2. It builds a 'normal profile' — average CPU, RAM, threads, active hours.\n")
            parts.append("3. If any metric jumps significantly above normal → it flags it as a violation.\n\n")
            parts.append("🔴 Triggers:\n")
            parts.append("  • CPU 3x above average\n")
            parts.append("  • Memory 2.5x above average\n")
            parts.append("  • Threads 3x above average\n")
            parts.append("  • Running outside its normal hours window\n\n")
            parts.append("🟡 Why this matters:\n")
            parts.append("  • Normal apps have predictable behavior\n")
            parts.append("  • Malware that hijacks a trusted process will spike one of these metrics\n")
            parts.append("  • Time anomalies reveal malware that waits for off-hours to act\n\n")

            if bv:
                parts.append(f"Current violations on your dashboard:\n")
                for b in bv[-3:]:
                    parts.append(f"  • {b.get('app','?')}: {b.get('violation','').replace('⚠ Behavior violation: ','')}\n")

        return "".join(parts)

    if any(x in q_lower for x in ["what is this","tell me","explain","analyze","analyse","what does","what should","what can you see"]):
        parts.append("📊 File Analysis\n\n")

        if detected_app:
            status, keyword = detected_app
            if status == "dangerous":
                parts.append(f"⚠ The filename contains '{keyword}' — this is a known dangerous indicator.\n\n")
                parts.append(f"Applications with this name are commonly associated with:\n")
                threat_map = {
                    "trojan": "Trojans — malware that disguises itself as legitimate software",
                    "malware": "Malware — general malicious software designed to damage or steal",
                    "ransomware": "Ransomware — encrypts your files and demands payment",
                    "keylogger": "Keyloggers — records all keystrokes including passwords",
                    "backdoor": "Backdoors — gives attackers permanent remote access",
                    "exploit": "Exploits — tools that attack software vulnerabilities",
                    "mimikatz": "Mimikatz — credential dumping tool used in attacks",
                    "cryptominer": "Crypto miners — steal CPU power to mine cryptocurrency",
                }
                parts.append(f"  • {threat_map.get(keyword, 'Known malicious activity')}\n\n")
            elif status == "suspicious":
                parts.append(f"🟡 The filename contains '{keyword}' — this warrants investigation.\n\n")
                parts.append(f"This could be:\n")
                parts.append(f"  • A legitimate system tool being abused\n")
                parts.append(f"  • Malware disguised as a system process\n")
                parts.append(f"  • Check the full path — system tools should be in C:\\Windows\\System32\n\n")
            else:
                parts.append(f"🟢 The filename suggests this may be a legitimate application.\n\n")

        if flagged_match:
            parts.append(f"🔴 This app IS currently flagged on your dashboard!\n\n")
            parts.append(f"Status: {'HIGH RISK' if flagged_match in hr else 'SUSPICIOUS'}\n")
            parts.append(f"Severity: {flagged_match.get('severity',0)}%\n\n")
            parts.append(f"Why it's flagged:\n")
            for r in flagged_match.get("reasons",[]):
                parts.append(f"  • {r}\n")
            parts.append(f"\nRecommendation: Block or Kill this process immediately from the Live App Monitor.")
        elif hr:
            parts.append(f"For context, your dashboard currently shows:\n")
            parts.append(f"  🔴 HIGH RISK: {hr[0].get('app','?')} (Severity {hr[0].get('severity',0)}%)\n")
            if len(hr) > 1:
                parts.append(f"  🔴 HIGH RISK: {hr[1].get('app','?')} (Severity {hr[1].get('severity',0)}%)\n")
        else:
            parts.append(f"Your dashboard shows no active high-risk apps matching this file.\n\n")
            parts.append(f"If you're seeing this app behave oddly:\n")
            parts.append(f"  1. Use 'Start Scan' in the Live App Monitor\n")
            parts.append(f"  2. Look for it in the Suspicious or High Risk sections\n")
            parts.append(f"  3. Ask me 'Why was [appname] flagged?' if it appears")

        return "".join(parts)

    parts.append("I've received your file. Here's what I can tell you based on the filename and your current dashboard context:\n\n")

    if flagged_match:
        parts.append(f"🔴 This app ({flagged_match.get('app','?')}) is currently active on your dashboard with {flagged_match.get('severity',0)}% severity.\n\n")
        parts.append("Detected issues:\n")
        for r in flagged_match.get("reasons",[]):
            parts.append(f"  • {r}\n")
    elif detected_app:
        status, keyword = detected_app
        if status == "dangerous":
            parts.append(f"⚠ The filename contains '{keyword}' — a known security indicator. This is concerning.\n")
        elif status == "suspicious":
            parts.append(f"🟡 The filename contains '{keyword}' — worth investigating.\n")
        else:
            parts.append(f"🟢 Filename looks normal.\n")
    else:
        parts.append("Filename looks neutral. ")
        if hr:
            parts.append(f"Your current top threat is {hr[0].get('app','?')} — if that's what you've screenshotted, ask me 'why was {hr[0].get('app','?')} flagged?'\n")
        else:
            parts.append("No matching threats found in current dashboard data.\n")

    parts.append("\nFor a deeper analysis, try asking me something specific like:\n")
    parts.append("  • 'Why is this app showing high CPU?'\n")
    parts.append("  • 'What does this behavior mean?'\n")
    parts.append("  • 'Why is the threat score high?'\n")
    parts.append("  • 'Is this app dangerous?'")

    return "".join(parts)


def _analyze_file_online(filename, file_type, question, file_data_b64, ctx):
    try:
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return None, False
        client = anthropic.Anthropic(api_key=api_key)

        hr  = ctx["high_risk"]
        sus = ctx["suspicious"]
        threat_level = ctx["threat_level"]
        threat_score = ctx["threat_score"]
        bv = ctx["recent_bv"]

        context_str = f"""You are Guardian, an expert security analyst chatbot embedded in a security dashboard.
Current dashboard state:
- Threat Level: {threat_level}
- Threat Score: {min(int(threat_score), 100)}/100
- High Risk Apps: {[o.get('app','?') + ' (severity ' + str(o.get('severity',0)) + '%)' for o in hr[:3]]}
- Suspicious Apps: {[o.get('app','?') for o in sus[:3]]}
- Recent Behavior Violations: {[b.get('app','?') + ': ' + b.get('violation','') for b in bv[-2:]]}

The analyst has uploaded a file named '{filename}' (type: {file_type}) and is asking: '{question}'

Provide a specific, actionable security analysis. Be direct and practical.
Explain security concepts in plain English. Reference the dashboard data above when relevant.
Keep response under 400 words. Use bullet points for clarity.
Start with the most important finding."""

        messages_content = []

        if file_type.startswith("image/") and file_data_b64:
            media_type = file_type if file_type in ["image/jpeg","image/png","image/gif","image/webp"] else "image/jpeg"
            messages_content = [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": file_data_b64,
                    }
                },
                {
                    "type": "text",
                    "text": context_str
                }
            ]
        elif file_type == "application/pdf" and file_data_b64:
            messages_content = [
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": file_data_b64,
                    }
                },
                {
                    "type": "text",
                    "text": context_str
                }
            ]
        else:
            messages_content = [
                {
                    "type": "text",
                    "text": context_str
                }
            ]

        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=600,
            messages=[
                {
                    "role": "user",
                    "content": messages_content
                }
            ]
        )

        answer = response.content[0].text if response.content else None
        if answer:
            return answer, True
        return None, False

    except Exception as e:
        print(f"[Guardian] Online analysis failed: {e} — falling back to offline")
        return None, False

def _analyze_image_smart(filename, file_type, question, ctx, img=None):
    if img is None:
        img = {}
    q = (question or "").lower()

    hr           = ctx.get("high_risk", [])
    sus          = ctx.get("suspicious", [])
    bv           = ctx.get("recent_bv", [])
    threat_level = ctx.get("threat_level", "LOW")
    threat_score = ctx.get("threat_score", 0)
    kc_events    = ctx.get("kc_events", [])
    fatigue      = ctx.get("fatigue_score", 0)
    ignored      = ctx.get("ignored_count", 0)
    predictions  = ctx.get("predictions", [])
    correlations = ctx.get("correlations", [])

    brightness    = img.get("brightness", 128)
    red_ratio     = img.get("red_ratio", 0)
    green_ratio   = img.get("green_ratio", 0)
    blue_ratio    = img.get("blue_ratio", 0)
    dark_ratio    = img.get("dark_ratio", 0)
    red_zones     = img.get("red_zones", 0)
    green_zones   = img.get("green_zones", 0)
    cyan_zones    = img.get("cyan_zones", 0)
    has_text      = img.get("has_text", False)
    has_bar_chart = img.get("has_bar_chart", False)
    is_dark_ui    = img.get("is_dark_ui", False)
    has_red_alerts= img.get("has_red_alerts", False)
    has_green_safe= img.get("has_green_safe", False)
    panel_hint    = img.get("panel_hint", "")
    img_w         = img.get("width", 0)
    img_h         = img.get("height", 0)

    fn_lower = (filename or "").lower()

    panel = panel_hint
    if not panel:
        combined = fn_lower + " " + q
        if any(x in combined for x in ["browser","btic","web","phish","redirect","download","permission"]):
            panel = "browser"
        elif any(x in combined for x in ["kill","chain","mitre","tactic","technique","attack"]):
            panel = "killchain"
        elif any(x in combined for x in ["behav","violation","cpu","memory","thread","anomal","profil"]):
            panel = "behavior"
        elif any(x in combined for x in ["fatigue","heat","ignored","suppres","heatmap"]):
            panel = "fatigue"
        elif any(x in combined for x in ["threat score","score","blocked","killed","trusted"]):
            panel = "threat"
        elif any(x in combined for x in ["live app","running","suspicious app","high risk app"]):
            panel = "liveapp"
        elif any(x in combined for x in ["system health","cpu%","ram","disk"]):
            panel = "system"
        elif any(x in combined for x in ["guardian","chatbot","chat"]):
            panel = "guardian"
        else:
            if red_zones >= 3 and red_ratio > 0.12:
                panel = "threat"
            elif cyan_zones >= 4 and is_dark_ui:
                panel = "browser"
            elif green_zones >= 3:
                panel = "liveapp"
            elif has_bar_chart:
                panel = "fatigue"
            else:
                panel = "overview"

    is_what_see    = any(x in q for x in ["what","see","show","tell","explain","analyze","describe","this","happening","going on","read","interpret"])
    is_threat_q    = any(x in q for x in ["threat","danger","risk","score","level","critical","high","safe"])
    is_action_q    = any(x in q for x in ["should i","what do i","what to do","next","recommend","action","help"])
    is_why_q       = any(x in q for x in ["why","reason","cause","because","how come"])
    is_compare_q   = any(x in q for x in ["compare","difference","vs","versus","better","worse","higher","lower"])
    is_number_q    = any(x in q for x in ["how many","count","number","total","how much","percentage","percent"])

    def threat_emoji(level):
        return {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(level,"⚪")

    parts = []

    if panel == "browser":
        btic    = browser_threat_data
        threats = btic.get("threats_detected", 0)
        blocked = btic.get("blocked_sites", 0)
        flagged = btic.get("downloads_flagged", 0)
        score   = btic.get("security_score", 100)
        sites   = btic.get("websites", [])
        dls     = btic.get("downloads", [])
        perms   = btic.get("permissions", [])
        reds    = btic.get("redirects", [])
        tl_evs  = btic.get("timeline", [])

        status_icon = "🔴" if threats > 0 else "🟢"
        parts.append(f"📸 I can see the Browser Threat Intelligence Center panel.\n\n")

        if red_zones >= 2:
            parts.append(f"I can see red alert indicators in your screenshot — threats have been detected.\n\n")
        elif green_zones >= 3:
            parts.append(f"The panel looks mostly green — browser activity appears clean.\n\n")

        parts.append(f"Current Browser Security Status:\n")
        parts.append(f"  {status_icon} Security Score: {score}/100\n")
        parts.append(f"  • Threats Detected: {threats}\n")
        parts.append(f"  • Blocked Sites: {blocked}\n")
        parts.append(f"  • Downloads Flagged: {flagged}\n\n")

        if is_what_see or (not is_threat_q and not is_action_q and not is_why_q):
            if threats == 0:
                parts.append("What's showing in the panel:\n")
                parts.append("  🟢 No active browser threats\n")
                parts.append("  🟢 Web monitoring active — all visited sites are being checked\n")
                parts.append("  🟢 Download scanner: ready\n")
                parts.append("  🟢 Permission monitor: watching for camera/mic/location abuse\n\n")
                parts.append("The dashboard is showing the monitoring tabs at the top (Overview, Web Activity, Downloads, Permissions, Redirects, Threat Timeline).\n\n")
                parts.append("Nothing alarming is visible. The system is in standby-monitor mode.")
            else:
                parts.append("What I can see happening:\n\n")
                risky_sites = [s for s in sites if s.get("status") in ("High Risk","Suspicious")]
                safe_sites  = [s for s in sites if s.get("status") == "Safe"]
                if risky_sites:
                    parts.append(f"Flagged websites in the panel:\n")
                    for s in risky_sites[:3]:
                        parts.append(f"  🔴 {s.get('url','?')} — {s.get('risk',0)}% risk\n")
                        parts.append(f"     {s.get('reason','')}\n")
                if safe_sites:
                    parts.append(f"\nClean sites: {', '.join(s.get('url','') for s in safe_sites[:3])}\n")
                bad_dls = [d for d in dls if d.get("status") in ("Blocked","Suspicious")]
                if bad_dls:
                    parts.append(f"\nBlocked downloads:\n")
                    for d in bad_dls[:2]:
                        parts.append(f"  🚫 {d.get('file','?')} — {d.get('reason','')}\n")
                blocked_perms = [p for p in perms if p.get("status") == "Blocked"]
                if blocked_perms:
                    parts.append(f"\nBlocked permission requests:\n")
                    for p in blocked_perms[:2]:
                        parts.append(f"  🚫 {p.get('site','?')} requested {p.get('request','?')}\n")
                if reds:
                    parts.append(f"\nRedirect chains detected: {len(reds)}\n")
                    for r in reds[:1]:
                        chain = " → ".join(r.get("chain",[]))
                        parts.append(f"  ⚠ {chain}\n")

        if is_threat_q:
            parts.append(f"\nBrowser Threat Assessment:\n")
            if score >= 80:
                parts.append(f"  Browser is relatively safe (score {score}/100).\n")
                parts.append(f"  Minor issues detected but nothing critical.\n")
            elif score >= 50:
                parts.append(f"  Moderate browser risk (score {score}/100).\n")
                parts.append(f"  {threats} threat(s) blocked. Review flagged sites.\n")
            else:
                parts.append(f"  🔴 High browser risk (score {score}/100).\n")
                parts.append(f"  Multiple threats active. Avoid clicking unknown links.\n")
                parts.append(f"  Close suspicious tabs immediately.\n")

        if is_action_q:
            parts.append(f"\nWhat you should do:\n")
            if threats == 0:
                parts.append("  ✅ Nothing urgent. Keep monitoring.\n")
                parts.append("  • Try the 'Simulate Browser Attack' button to test detection.\n")
            else:
                parts.append(f"  1. Click the 'Web Activity' tab — review all flagged sites\n")
                parts.append(f"  2. Click 'Downloads' — check for blocked malicious files\n")
                parts.append(f"  3. Click 'Redirects' — trace any suspicious redirect chains\n")
                parts.append(f"  4. Click 'Threat Timeline' — see the full sequence of events\n")
                if score < 50:
                    parts.append(f"  5. Consider closing all browser tabs and clearing cookies\n")

        if is_why_q:
            parts.append(f"\nWhy the browser panel is showing this:\n")
            risky = [s for s in sites if s.get("status") == "High Risk"]
            if risky:
                parts.append(f"  • {risky[0].get('url','?')} was flagged because: {risky[0].get('reason','suspicious pattern')}\n")
            bad_dl = next((d for d in dls if d.get("status") == "Blocked"), None)
            if bad_dl:
                parts.append(f"  • {bad_dl.get('file','?')} was blocked because: {bad_dl.get('reason','malicious pattern')}\n")
            if score < 100:
                parts.append(f"  • Score dropped from 100 because each threat detection reduces it\n")

        if is_number_q:
            parts.append(f"\nNumbers from this panel:\n")
            parts.append(f"  • Total browser threats: {threats}\n")
            parts.append(f"  • Sites blocked: {blocked}\n")
            parts.append(f"  • Downloads flagged: {flagged}\n")
            parts.append(f"  • Security score: {score}/100\n")
            parts.append(f"  • Websites tracked: {len(sites)}\n")
            parts.append(f"  • Timeline events: {len(tl_evs)}\n")

        return "".join(parts)

    elif panel == "killchain":
        active_tactics = list({e.get("tactic","") for e in kc_events})
        ignored_evs    = [e for e in kc_events if e.get("action") == "ignored"]
        actioned_evs   = [e for e in kc_events if e.get("action") in ("blocked","killed","trusted")]

        parts.append(f"📸 I can see the MITRE ATT&CK Kill Chain panel.\n\n")

        if red_zones >= 3:
            parts.append("I can see multiple red/orange indicators — active attack stages are lit up.\n\n")
        elif cyan_zones >= 3:
            parts.append("The panel is showing active events with highlighted stages.\n\n")

        if not kc_events:
            parts.append("What I see in the panel:\n")
            parts.append("  • Kill chain is empty — no attack events recorded yet\n")
            parts.append("  • All MITRE ATT&CK stage pills are gray (inactive)\n")
            parts.append("  • Waiting for attack simulation or real threat activity\n\n")
            parts.append("To populate this: click 'Simulate Demo Attack' and then interact with the alert popups.")
        else:
            parts.append(f"Kill Chain Status:\n")
            parts.append(f"  • Total events: {len(kc_events)}\n")
            parts.append(f"  • Active MITRE tactics: {len(active_tactics)}\n")
            parts.append(f"  • Ignored alerts: {len(ignored_evs)}\n")
            parts.append(f"  • Actioned: {len(actioned_evs)}\n\n")

            if active_tactics:
                parts.append(f"Active attack stages visible in panel:\n")
                for t in active_tactics[:5]:
                    evs = [e for e in kc_events if e.get("tactic") == t]
                    top = evs[-1]
                    color = top.get("color","warn")
                    icon  = "🔴" if color=="danger" else "🟠" if color=="warn" else "🟡"
                    parts.append(f"  {icon} {t} — {top.get('app','?')} [{top.get('technique','?')}]\n")

        if is_what_see:
            if kc_events:
                parts.append(f"\nWhat the panel shows:\n")
                parts.append(f"  • Top section: stage pills — colored ones are active attack stages\n")
                parts.append(f"  • Middle section: scrollable event list — each row = one popup action\n")
                parts.append(f"  • Columns: Time | MITRE Tactic | App name | Technique | Action taken\n")
                if ignored_evs:
                    parts.append(f"  • {len(ignored_evs)} red 'IGNORED' entries visible — these are risks\n")

        if is_threat_q:
            level_label = "CRITICAL" if len(active_tactics) >= 4 else "HIGH" if len(active_tactics) >= 2 else "MEDIUM" if kc_events else "LOW"
            parts.append(f"\nKill Chain Threat Assessment: {threat_emoji(level_label)} {level_label}\n")
            if len(ignored_evs) > 2:
                parts.append(f"  ⚠ {len(ignored_evs)} ignored alerts have weakened your defense\n")
            if predictions:
                parts.append(f"  Next predicted stage: {predictions[0][0]} ({predictions[0][1]}% likely)\n")

        if is_action_q:
            parts.append(f"\nWhat to do with this panel:\n")
            if not kc_events:
                parts.append("  • Simulate an attack to see kill chain analysis\n")
            else:
                parts.append("  1. Click 'Reconstruct Full Attack Story' — see a plain-English narrative\n")
                parts.append("  2. Review any IGNORED events — those are your weak spots\n")
                parts.append("  3. Block or kill apps still active in the Live App Monitor\n")
                if predictions:
                    parts.append(f"  4. Prepare for {predictions[0][0]} — {predictions[0][1]}% chance it's next\n")

        return "".join(parts)

    elif panel == "behavior":
        total_bv   = len(behavior_alerts)
        recent     = behavior_alerts[-5:]
        high_risk_bv = [b for b in behavior_alerts if (b.get("severity",0) or 0) >= 70]

        parts.append(f"📸 I can see the Behavior Profiling / Violation panel.\n\n")

        if red_zones >= 3:
            parts.append("I can see high-severity violations highlighted in red in your screenshot.\n\n")

        parts.append(f"Behavior Monitor Status:\n")
        parts.append(f"  • Total violations logged: {total_bv}\n")
        parts.append(f"  • High-risk violations: {len(high_risk_bv)}\n\n")

        if not behavior_alerts:
            parts.append("What the panel shows:\n")
            parts.append("  • No behavior violations detected yet\n")
            parts.append("  • System status: STABLE (green indicator)\n")
            parts.append("  • Scanner is running and watching all processes\n\n")
            parts.append("To trigger violations: click 'Run Demo Threat' button in the panel.")
        else:
            parts.append(f"Recent violations visible in panel:\n")
            for b in recent[:3]:
                sev  = b.get("severity", 0) or 0
                icon = "🔴" if sev >= 70 else "🟡" if sev >= 40 else "⚪"
                viol = (b.get("violation","") or "").replace("⚠ Behavior violation: ","")
                parts.append(f"  {icon} {b.get('app','?')}: {viol} (severity {sev}%)\n")

        if is_what_see and behavior_alerts:
            parts.append(f"\nPanel layout visible:\n")
            parts.append(f"  • Top: System status bar — {'RED (threat)' if len(high_risk_bv) > 0 else 'STABLE (green)'}\n")
            parts.append(f"  • Stats: {total_bv} violations | {len(high_risk_bv)} high-risk | last at {recent[-1].get('time','?') if recent else '--'}\n")
            parts.append(f"  • Each card shows: App name, violation type badge, severity bar\n")

        if is_why_q and behavior_alerts:
            parts.append(f"\nWhy these violations are being flagged:\n")
            for b in recent[:2]:
                viol = (b.get("violation","") or "").replace("⚠ Behavior violation: ","").lower()
                app  = b.get("app","?")
                if "cpu spike" in viol:
                    parts.append(f"  • {app}: suddenly using far more CPU than its normal baseline\n")
                elif "time anomaly" in viol:
                    parts.append(f"  • {app}: running at an hour it normally isn't active\n")
                elif "thread" in viol:
                    parts.append(f"  • {app}: spawned abnormally many threads — classic malware behavior\n")
                elif "memory" in viol:
                    parts.append(f"  • {app}: memory usage jumped way above its average\n")
                else:
                    parts.append(f"  • {app}: deviated significantly from learned behavior pattern\n")

        if is_action_q:
            parts.append(f"\nWhat to do:\n")
            if not behavior_alerts:
                parts.append("  • System is stable — keep monitoring\n")
                parts.append("  • Click 'Run Demo Threat' to test detection\n")
            else:
                most_severe = max(behavior_alerts, key=lambda x: x.get("severity",0) or 0)
                parts.append(f"  1. Investigate {most_severe.get('app','?')} immediately — highest severity\n")
                parts.append(f"  2. Go to Live App Monitor → find the app → Block or Kill it\n")
                parts.append(f"  3. Check the Behavior Profile card for its CPU/RAM baseline\n")

        return "".join(parts)

    elif panel == "fatigue":
        fl     = "CRITICAL" if fatigue>=15 else "HIGH" if fatigue>=8 else "MEDIUM" if fatigue>=4 else "LOW"
        streak = ctx.get("ignore_streak", 0)
        heat   = fatigue_state.get("heat", {})

        parts.append(f"📸 I can see the Fatigue Score / Heatmap panel.\n\n")

        if has_bar_chart:
            parts.append("I can see the bar chart / heatmap visualization in your screenshot.\n\n")

        parts.append(f"Fatigue Analysis:\n")
        parts.append(f"  • Fatigue Score: {fatigue:.1f}/20 — {fl}\n")
        parts.append(f"  • Ignored alerts: {ignored}\n")
        parts.append(f"  • Consecutive ignores: {streak}\n")
        parts.append(f"  • Actions taken: {ctx.get('actions_count',0)}\n\n")

        if is_what_see:
            parts.append("What the panel shows:\n")
            parts.append("  • Line chart: fatigue score over time — rising line = getting worse\n")
            parts.append("  • Alert confidence bar: how certain the system is about current alerts\n")
            parts.append(f"  • Heatmap bars: Low={heat.get('Low',0)} · Medium={heat.get('Medium',0)} · High={heat.get('High',0)} alerts triggered\n")
            if streak >= 3:
                parts.append(f"  • ⚠ Warning banner visible — {streak} consecutive ignores detected\n")
            if fatigue >= 10:
                parts.append(f"  • Suppression banner active — alerts are being suppressed due to high fatigue\n")

        if is_threat_q or is_why_q:
            parts.append(f"Why the score is at {fatigue:.1f}:\n")
            parts.append(f"  • Every ignored alert adds +3 to fatigue score\n")
            parts.append(f"  • Every acknowledged alert reduces it by -1\n")
            if fatigue >= 8:
                parts.append(f"  • You've ignored enough alerts to reach {fl} fatigue\n")
                parts.append(f"  • This means you may be missing real threats\n")

        if is_action_q:
            parts.append(f"What to do about fatigue score {fatigue:.1f}:\n")
            if fl == "LOW":
                parts.append("  ✅ You're doing great. Keep acknowledging alerts properly.\n")
            elif fl == "MEDIUM":
                parts.append("  • Slow down and review alerts more carefully\n")
                parts.append("  • Avoid clicking Ignore on anything you haven't read\n")
            else:
                parts.append("  🔴 Stop and review all current flagged apps now\n")
                parts.append("  • Use Emergency Lockdown if unsure\n")
                parts.append("  • Consider a short break — fatigue causes missed detections\n")

        if is_number_q:
            parts.append(f"Numbers from this panel:\n")
            parts.append(f"  • Fatigue score: {fatigue:.1f}/20\n")
            parts.append(f"  • Low alerts: {heat.get('Low',0)}\n")
            parts.append(f"  • Medium alerts: {heat.get('Medium',0)}\n")
            parts.append(f"  • High alerts: {heat.get('High',0)}\n")
            parts.append(f"  • Total alerts: {ctx.get('total',0)}\n")

        return "".join(parts)

    elif panel == "threat":
        ts_val   = min(int(threat_score), 100)
        ts_level = "CRITICAL" if ts_val>=70 else "HIGH" if ts_val>=40 else "ELEVATED" if ts_val>=20 else "SAFE"
        hist     = TIMELINE_DATA.get("history",[])
        blocked  = TIMELINE_DATA.get("blocked",0)
        killed   = TIMELINE_DATA.get("killed",0)
        trusted  = TIMELINE_DATA.get("trusted",0)

        parts.append(f"📸 I can see the Threat Score panel.\n\n")

        if red_ratio > 0.15:
            parts.append(f"I can see significant red coloring — threat score is elevated.\n\n")

        parts.append(f"Threat Score Status:\n")
        parts.append(f"  {threat_emoji(ts_level)} Score: {ts_val}/100 — {ts_level}\n")
        parts.append(f"  • Blocked: {blocked}\n")
        parts.append(f"  • Killed: {killed}\n")
        parts.append(f"  • Trusted: {trusted}\n\n")

        if is_what_see:
            parts.append("What's visible in this panel:\n")
            parts.append(f"  • Threat score number: {ts_val}/100 with color-coded bar\n")
            parts.append(f"  • Action counts: {blocked} blocked | {killed} killed | {trusted} trusted\n")
            if hist:
                parts.append(f"  • History button: {len(hist)} recorded actions\n")
            if ts_val >= 70:
                parts.append(f"  • Red gradient background — CRITICAL state active\n")
            elif ts_val >= 40:
                parts.append(f"  • Orange/amber coloring — HIGH threat state\n")
            else:
                parts.append(f"  • Green/cyan coloring — safe/low state\n")

        if is_threat_q or is_why_q:
            parts.append(f"Why the score is {ts_val}:\n")
            if hr:
                parts.append(f"  • {len(hr)} high-risk app(s) active = +{len(hr)*15} pts\n")
            if sus:
                parts.append(f"  • {len(sus)} suspicious app(s) = +{len(sus)*5} pts\n")
            if ignored:
                parts.append(f"  • {ignored} ignored alerts = +{ignored*3} pts\n")
            if kc_events:
                parts.append(f"  • {len(kc_events)} kill chain events = +{len(kc_events)*10} pts\n")

        if is_action_q:
            parts.append(f"To reduce the threat score:\n")
            if hr:
                parts.append(f"  1. Block {hr[0].get('app','?')} → score drops ~15 pts\n")
            if sus:
                parts.append(f"  2. Kill {sus[0].get('app','?')} → score drops ~10 pts\n")
            parts.append(f"  3. Acknowledge alerts instead of ignoring them\n")

        return "".join(parts)

    elif panel == "liveapp":
        running_apps = ctx.get("running",[])
        parts.append(f"📸 I can see the Live App Monitor panel.\n\n")

        parts.append(f"Live App Monitor Status:\n")
        parts.append(f"  • Running apps visible: {len(running_apps)}\n")
        parts.append(f"  • High-risk: {len(hr)}\n")
        parts.append(f"  • Suspicious: {len(sus)}\n\n")

        if is_what_see:
            parts.append("What's showing in the panel:\n")
            if hr:
                parts.append(f"  🔴 HIGH RISK section:\n")
                for o in hr[:3]:
                    parts.append(f"     • {o.get('app','?')} — severity {o.get('severity',0)}%\n")
                    r = o.get("reasons",[])[0] if o.get("reasons") else ""
                    if r: parts.append(f"       Reason: {r[:60]}\n")
            if sus:
                parts.append(f"  🟡 SUSPICIOUS section:\n")
                for o in sus[:3]:
                    parts.append(f"     • {o.get('app','?')} — severity {o.get('severity',0)}%\n")
            if running_apps:
                parts.append(f"  🟢 RUNNING: {', '.join(running_apps[:5])}\n")
            parts.append(f"\n  Each app has 3 buttons: Trust ✅ | Kill 💀 | Block 🚫\n")

        if is_action_q and (hr or sus):
            top = (hr+sus)[0]
            parts.append(f"\nWhat to do:\n")
            parts.append(f"  1. Find {top.get('app','?')} in the panel\n")
            parts.append(f"  2. Click Block (permanent) or Kill (session)\n")
            parts.append(f"  3. Use 'Show All' to see complete list\n")

        return "".join(parts)

    elif panel == "system":
        parts.append(f"📸 I can see the System Health panel.\n\n")

        if has_bar_chart:
            parts.append("I can see the system metrics chart in your screenshot.\n\n")

        parts.append("The System Health panel shows live CPU, RAM, and Disk usage.\n\n")
        parts.append("What to look for:\n")
        parts.append("  • CPU above 80% → possible crypto mining or heavy encryption\n")
        parts.append("  • RAM above 80% → possible memory injection or data staging\n")
        parts.append("  • Disk spiking → possible ransomware file encryption\n\n")
        parts.append("The chart updates every 3 seconds, showing last 15 data points.\n")

        if hr:
            parts.append(f"\n⚠ Cross-reference: {hr[0].get('app','?')} is flagged HIGH RISK right now.\n")
            reasons = hr[0].get("reasons",[])
            cpu_r = next((r for r in reasons if "cpu" in r.lower()), None)
            if cpu_r:
                parts.append(f"This may explain your CPU spike: {cpu_r}\n")

        return "".join(parts)

    else:
        ts_val   = min(int(threat_score), 100)
        ts_level = "CRITICAL" if ts_val>=70 else "HIGH" if ts_val>=40 else "ELEVATED" if ts_val>=20 else "SAFE"

        parts.append(f"📸 I can see your Security Dashboard screenshot.\n\n")

        if is_dark_ui:
            parts.append("The dark-themed dashboard is visible.\n\n")
        if red_zones >= 4:
            parts.append("I can see multiple red alert indicators — the system is in an elevated threat state.\n\n")
        elif green_zones >= 3:
            parts.append("The dashboard looks mostly green — system appears relatively safe.\n\n")
        if has_bar_chart:
            parts.append("I can see a chart/graph panel in the screenshot.\n\n")

        parts.append(f"Current Dashboard State:\n")
        parts.append(f"  {threat_emoji(ts_level)} Threat Level: {ts_level} ({ts_val}/100)\n")
        parts.append(f"  • High-risk apps: {len(hr)}\n")
        parts.append(f"  • Suspicious apps: {len(sus)}\n")
        parts.append(f"  • Kill chain events: {len(kc_events)}\n")
        parts.append(f"  • Fatigue score: {fatigue:.1f}/20\n")
        parts.append(f"  • Alerts ignored: {ignored}\n\n")

        if hr:
            parts.append(f"Most urgent item visible:\n")
            parts.append(f"  🔴 {hr[0].get('app','?')} — severity {hr[0].get('severity',0)}%\n")
            r = hr[0].get("reasons",[])[0] if hr[0].get("reasons") else ""
            if r: parts.append(f"  Reason: {r}\n")

        if is_action_q:
            parts.append(f"\nWhat you should focus on right now:\n")
            if hr:
                parts.append(f"  1. Go to Live App Monitor → Block {hr[0].get('app','?')}\n")
            if ignored >= 3:
                parts.append(f"  2. You've ignored {ignored} alerts — review them before they escalate\n")
            if kc_events and predictions:
                parts.append(f"  3. Kill chain is active — {predictions[0][0]} is likely next\n")

        if is_number_q:
            parts.append(f"\nAll numbers visible on dashboard:\n")
            parts.append(f"  Threat Score: {ts_val}/100\n")
            parts.append(f"  Fatigue Score: {fatigue:.1f}/20\n")
            parts.append(f"  High Risk Apps: {len(hr)}\n")
            parts.append(f"  Suspicious Apps: {len(sus)}\n")
            parts.append(f"  Kill Chain Events: {len(kc_events)}\n")
            parts.append(f"  Ignored Alerts: {ignored}\n")
            parts.append(f"  Actions Taken: {ctx.get('actions_count',0)}\n")
            parts.append(f"  Blocked: {TIMELINE_DATA.get('blocked',0)}\n")
            parts.append(f"  Killed: {TIMELINE_DATA.get('killed',0)}\n")

        if not is_what_see and not is_action_q and not is_number_q and not is_threat_q:
            parts.append(f"\nTip: Name your screenshot file with the panel name for more specific analysis.\n")
            parts.append(f"Examples: browser_screenshot.png, killchain.png, behavior.png, fatigue.png")

        return "".join(parts)


@app.route("/api/analyze_upload", methods=["POST"])
def api_analyze_upload():
    data = request.json or {}
    filename       = data.get("filename", "unknown_file")
    file_type      = data.get("file_type", "application/octet-stream")
    question       = data.get("question", "What can you tell me about this?")
    image_analysis = data.get("image_analysis", {})

    if not filename:
        return jsonify({"answer": "No file provided.", "mode": "error"}), 400

    try:
        ctx = _build_soc_context()
    except:
        ctx = {"threat_level":"LOW","confidence":70,"high_risk":[],"suspicious":[],"recent_bv":[],"threat_score":0}

    answer = _analyze_image_smart(filename, file_type, question, ctx, image_analysis)
    _add_timeline_event("FILE_ANALYSIS", f"Analyzed: {filename[:40]}", 0)

    return jsonify({
        "answer":       answer,
        "mode":         "vision",
        "filename":     filename,
        "threat_level": ctx.get("threat_level", "LOW"),
        "confidence":   ctx.get("confidence", 70),
    })

# ════════════════════════════════════════════════════════════════
# ── /critical_escalation ────────────────────────────────────────
# ════════════════════════════════════════════════════════════════
@app.route("/critical_escalation", methods=["POST"])
def critical_escalation():
    data = request.json or {}
    ignored_count = data.get("ignored_count", 0)
    ignored_apps  = data.get("ignored_apps",  [])
    fatigue_score = data.get("fatigue_score", 0.0)

    if data.get("_reset"):
        with _critical_lock:
            _critical_escalation_state["active"]        = False
            _critical_escalation_state["ignored_count"] = 0
            _critical_escalation_state["ignored_apps"]  = []
            _critical_escalation_state["fatigue_score"] = 0.0
            _critical_escalation_state["triggered_at"]  = None
        return jsonify({"status": "reset"})

    with _critical_lock:
        _critical_escalation_state["active"]        = True
        _critical_escalation_state["ignored_count"] = ignored_count
        _critical_escalation_state["ignored_apps"]  = ignored_apps
        _critical_escalation_state["fatigue_score"] = fatigue_score
        _critical_escalation_state["triggered_at"]  = time.strftime("%H:%M:%S")

    fatigue_state["score"]         = min(20.0, fatigue_score)
    fatigue_state["ignored"]       = max(fatigue_state["ignored"], ignored_count)
    fatigue_state["ignore_streak"] = max(fatigue_state["ignore_streak"], ignored_count)

    print(f"[App] 🚨 CRITICAL ESCALATION — {ignored_count} ignores, apps: {ignored_apps}")
    return jsonify({"status": "critical_escalation_set", "state": _critical_escalation_state})

# ── /emergency_lockdown ─────────────────────────────────────────────────────
@app.route("/emergency_lockdown", methods=["POST"])
def emergency_lockdown():
    with data_lock:
        all_suspicious = list(latest_data["suspicious"])
        all_high_risk  = list(latest_data["high_risk"])

    locked_apps = []
    now = time.strftime("%H:%M:%S")

    for obj in (all_suspicious + all_high_risk):
        app_name = obj.get("app", "")
        if not app_name:
            continue
        al = app_name.lower()
        if al in locked_apps:
            continue

        _kill_proc(al)
        BLOCKED_APPS.add(al)
        KILLED_APPS.add(al)
        TEMP_KILLED.add(al)
        locked_apps.append(al)
        _log_action_internal(app_name, "blocked")
        _add_kill_chain_event(app_name, "blocked",
                              reasons=obj.get("reasons",[]),
                              severity=obj.get("severity",90),
                              source="emergency_lockdown")

        fatigue_state["actions"] += 1
        fatigue_state["total"]   += 1
        fatigue_state["ignore_streak"] = 0

    save_blocked()
    save_killed()

    with data_lock:
        latest_data["suspicious"] = []
        latest_data["high_risk"]  = []

    with _critical_lock:
        _critical_escalation_state["active"]        = False
        _critical_escalation_state["ignored_count"] = 0
        _critical_escalation_state["ignored_apps"]  = []

    try:
        requests.get("http://127.0.0.1:5001/stop_popups", timeout=1)
    except Exception:
        pass

    print(f"[App] 🔒 EMERGENCY LOCKDOWN — Locked {len(locked_apps)} apps: {locked_apps}")
    return jsonify({
        "status":      "lockdown_complete",
        "locked_apps": locked_apps,
        "count":       len(locked_apps),
        "time":        now,
    })

# ── System stats ─────────────────────────────────────────────────────────────
@app.route("/system_stats")
def system_stats():
    cpu  = psutil.cpu_percent(interval=0.3)
    ram  = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    return jsonify({"cpu":round(cpu,1),"ram":round(ram,1),"disk":round(disk,1)})

# ── Action Button Endpoints ──────────────────────────────────────────────────
INCIDENT_REPORT_FILE = os.path.join(_DATA_DIR, "incident_reports.json")
LOCKDOWN_STATUS_FILE = os.path.join(_DATA_DIR, "lockdown_status.json")

def _load_incidents():
    if os.path.exists(INCIDENT_REPORT_FILE):
        try:
            with open(INCIDENT_REPORT_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return []

def _save_incidents(reports):
    with open(INCIDENT_REPORT_FILE, "w") as f:
        json.dump(reports, f, indent=2)

@app.route("/api/incident_report", methods=["POST"])
def api_incident_report():
    data    = request.json or {}
    reports = _load_incidents()
    inc_id  = "INC-" + str(1000 + len(reports)).zfill(4)
    report  = {
        "id":            inc_id,
        "time":          time.strftime("%Y-%m-%d %H:%M:%S"),
        "ignored_count": data.get("ignored_count", 0),
        "ignored_apps":  data.get("ignored_apps", []),
        "fatigue_score": data.get("fatigue_score", 0),
        "action_taken":  data.get("action_taken", "acknowledged"),
        "notes":         data.get("notes", ""),
        "locked_apps":   data.get("locked_apps", []),
    }
    reports.append(report)
    _save_incidents(reports)
    print(f"[App] 📋 Incident Report Filed: {inc_id} — {report['action_taken']}")
    return jsonify({"status": "filed", "incident_id": inc_id, "report": report})

@app.route("/api/lockdown_status", methods=["POST"])
def api_lockdown_status():
    data   = request.json or {}
    status = {
        "time":         time.strftime("%Y-%m-%d %H:%M:%S"),
        "action":       data.get("action", "network_isolate"),
        "triggered_by": data.get("triggered_by", "dashboard"),
        "apps":         data.get("apps", []),
        "note":         data.get("note", ""),
    }
    with open(LOCKDOWN_STATUS_FILE, "w") as f:
        json.dump(status, f, indent=2)
    print(f"[App] 🔌 Lockdown Action Recorded: {status['action']}")
    return jsonify({"status": "ok", "recorded": status})

@app.route("/api/flagged_apps")
def api_flagged_apps():
    with data_lock:
        sus  = list(latest_data["suspicious"])
        high = list(latest_data["high_risk"])
    return jsonify({
        "suspicious":    sus,
        "high_risk":     high,
        "blocked":       list(BLOCKED_APPS),
        "temp_killed":   list(TEMP_KILLED),
        "total_flagged": len(sus) + len(high),
    })

@app.route("/api/get_incidents")
def api_get_incidents():
    return jsonify({"incidents": _load_incidents()})

@app.route("/download_pdf_report")
def download_pdf_report():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable, KeepTogether)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import io
    import random
    import math

    # ── Register Times New Roman (Liberation Serif = identical metrics) ──
    _fonts_loaded = False
    try:
        pdfmetrics.registerFont(TTFont('TNR',      '/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf'))
        pdfmetrics.registerFont(TTFont('TNR-Bold', '/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf'))
        pdfmetrics.registerFont(TTFont('TNR-It',   '/usr/share/fonts/truetype/liberation/LiberationSerif-Italic.ttf'))
        from reportlab.pdfbase.pdfmetrics import registerFontFamily
        registerFontFamily('TNR', normal='TNR', bold='TNR-Bold', italic='TNR-It', boldItalic='TNR-Bold')
        _fonts_loaded = True
    except Exception:
        _fonts_loaded = False  # will use Helvetica fallback below

    # Font name helper — uses TNR if loaded, else built-in Helvetica variants
    def _font(bold=False, italic=False):
        if _fonts_loaded:
            if bold:   return 'TNR-Bold'
            if italic: return 'TNR-It'
            return 'TNR'
        else:
            if bold:   return 'Helvetica-Bold'
            if italic: return 'Helvetica-Oblique'
            return 'Helvetica'

    W, H   = A4
    MARGIN = 2.0 * cm

    # ── Random Colour Themes (light, easy on eyes) ───────────────────────
    # Procedurally generated palette bank: ~240 themes spread evenly around
    # the colour wheel, each with several saturation/lightness variants so
    # every downloaded report can look meaningfully different while staying
    # readable (dark banner/heading, pastel accents, near-white table rows).
    import colorsys as _colorsys

    def _hexcol(hue, lightness, saturation):
        hue = hue % 1.0
        lightness = min(0.99, max(0.05, lightness))
        saturation = min(1.0, max(0.0, saturation))
        r, g, b = _colorsys.hls_to_rgb(hue, lightness, saturation)
        return colors.HexColor('#%02X%02X%02X' % (round(r * 255), round(g * 255), round(b * 255)))

    def _make_theme(hue, sat_mult=1.0, light_mult=1.0):
        return {
            "banner":   _hexcol(hue, 0.30 * light_mult, 0.55 * sat_mult),
            "accent":   _hexcol(hue, 0.48 * light_mult, 0.50 * sat_mult),
            "heading":  _hexcol(hue, 0.38 * light_mult, 0.55 * sat_mult),
            "light_bg": _hexcol(hue, 0.95,               0.35 * sat_mult),
            "cream":    _hexcol(hue, 0.985,              0.20 * sat_mult),
            "subtext":  _hexcol(hue, 0.78,               0.55 * sat_mult),
            "hr_line":  _hexcol(hue, 0.62 * light_mult,  0.55 * sat_mult),
            "row_a":    _hexcol(hue, 0.90,               0.45 * sat_mult),
            "row_b":    _hexcol(hue, 0.98,               0.22 * sat_mult),
        }

    _HUE_STEPS = 30
    _VARIANTS  = [
        (1.00, 1.00), (0.85, 1.05), (1.15, 0.95), (0.70, 1.10),
        (1.30, 0.90), (0.90, 0.85), (1.10, 1.10), (0.60, 1.00),
    ]
    THEMES = [
        _make_theme(step / _HUE_STEPS, sat_mult, light_mult)
        for step in range(_HUE_STEPS)
        for sat_mult, light_mult in _VARIANTS
    ]

    T = random.choice(THEMES)

    C_BANNER = T["banner"]
    C_BLUE   = T["accent"]
    C_HEAD   = T["heading"]
    C_LIGHT  = T["light_bg"]
    C_CREAM  = T["cream"]
    C_SUBTEXT= T["subtext"]
    C_HR     = T["hr_line"]
    C_ROW_A  = T["row_a"]
    C_ROW_B  = T["row_b"]

    # Fixed semantic colours (unchanged across themes)
    C_RED    = colors.HexColor('#C0392B')
    C_ORANGE = colors.HexColor('#E67E22')
    C_GREEN  = colors.HexColor('#1E8449')
    C_BLACK  = colors.black
    C_GREY   = colors.HexColor('#5D6D7E')
    C_WHITE  = colors.white
    C_PURPLE = colors.HexColor('#7D3C98')

    
    def _S(name, bold=False, italic=False, size=10.5, leading=15,
           color=C_BLACK, align=0, sb=0, sa=0):
        return ParagraphStyle(name, fontName=_font(bold, italic), fontSize=size,
                              leading=leading, textColor=color, alignment=align,
                              spaceBefore=sb, spaceAfter=sa)

    s_body     = _S('body')
    s_kv_key   = _S('kvk',  bold=True,  size=9.5,  color=C_BLUE)
    s_th       = _S('th',   bold=True,  size=9,    color=C_WHITE, align=1)
    s_td       = _S('td',   size=9,     color=C_BLACK, align=1)
    s_td_left  = _S('tdl',  size=9,     color=C_BLACK)
    s_step_body= _S('stb',  size=9.5,   color=C_BLACK, sa=2)
    s_foot     = _S('foot', italic=True,size=8,    color=C_GREY,  align=1)

    def _P(text, style):
        return Paragraph(text, style)

    def _dyn(val_color):
        return ParagraphStyle('dyn', fontName=_font(), fontSize=9.5,
                              leading=13, textColor=val_color)

    # ── Section heading ───────────────────────────────────────
    def section_heading(text):
        return [
            Spacer(1, 0.3*cm),
            Paragraph(f'<u><b>{text}</b></u>',
                      _S('sec', bold=True, size=13, leading=18,
                         color=C_HEAD, sb=14, sa=4)),
            HRFlowable(width="100%", thickness=1.2, color=C_HR, spaceAfter=6),
        ]

    # ── Key-value table ───────────────────────────────────────
    def kv_table(pairs):
        rows = []
        for k, v, vc in pairs:
            rows.append([_P(k, s_kv_key),
                         _P(str(v), _dyn(vc))])
        t = Table(rows, colWidths=[5.5*cm, 12.5*cm])
        t.setStyle(TableStyle([
            ('VALIGN',         (0,0),(-1,-1),'TOP'),
            ('ROWBACKGROUNDS', (0,0),(-1,-1),[C_ROW_A, C_ROW_B]),
            ('LEFTPADDING',    (0,0),(-1,-1),8),
            ('RIGHTPADDING',   (0,0),(-1,-1),8),
            ('TOPPADDING',     (0,0),(-1,-1),5),
            ('BOTTOMPADDING',  (0,0),(-1,-1),5),
            ('GRID',           (0,0),(-1,-1),0.4,colors.HexColor('#D5D8DC')),
        ]))
        return t

    # ── Data table ────────────────────────────────────────────
    def data_table(headers, rows_data, col_widths, row_colors=None):
        header_row = [_P(h, s_th) for h in headers]
        body_rows  = [[_P(str(c), s_td_left if j == 0 else s_td)
                       for j, c in enumerate(row)]
                      for row in rows_data]
        t = Table([header_row] + body_rows, colWidths=col_widths, repeatRows=1)
        
        style = [
            ('BACKGROUND',    (0,0),(-1,0), C_BANNER),
            ('TEXTCOLOR',     (0,0),(-1,0), C_WHITE),
            ('FONTNAME',      (0,0),(-1,0), _font(bold=True)),   # fixed
            ('FONTSIZE',      (0,0),(-1,0), 9),
            ('ALIGN',         (0,0),(-1,0), 'CENTER'),
            ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
            ('GRID',          (0,0),(-1,-1),0.5, colors.HexColor('#AEB6BF')),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[C_ROW_B, C_ROW_A]),
            ('LEFTPADDING',   (0,0),(-1,-1),6),
            ('RIGHTPADDING',  (0,0),(-1,-1),6),
            ('TOPPADDING',    (0,0),(-1,-1),5),
            ('BOTTOMPADDING', (0,0),(-1,-1),5),
            ('FONTNAME',      (0,1),(-1,-1), _font()),           # fixed
            ('FONTSIZE',      (0,1),(-1,-1),9),
        ]
        if row_colors:
            for ri, col_range, col in row_colors:
                style += [('TEXTCOLOR',(col_range[0],ri+1),(col_range[1],ri+1),col),
                          ('FONTNAME', (col_range[0],ri+1),(col_range[1],ri+1), _font(bold=True))]
        t.setStyle(TableStyle(style))
        return t

    # ── Stat box row ──────────────────────────────────────────
    
    def stat_box_row(stats):
        cells = []
        for label, value, vc in stats:
            inner = Table(
                [[_P(str(value), ParagraphStyle('sv', fontName=_font(bold=True),
                                               fontSize=20, leading=24,
                                               textColor=vc, alignment=1))],
                 [_P(label,      ParagraphStyle('sl', fontName=_font(),
                                               fontSize=8,  leading=11,
                                               textColor=C_GREY, alignment=1))]],
            )
            inner.setStyle(TableStyle([
                ('ALIGN',         (0,0),(-1,-1),'CENTER'),
                ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
                ('TOPPADDING',    (0,0),(-1,-1),8),
                ('BOTTOMPADDING', (0,0),(-1,-1),8),
            ]))
            cells.append(inner)
        n     = len(cells)
        col_w = (W - 2*MARGIN) / n
        outer = Table([cells], colWidths=[col_w]*n)
        outer.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1),C_LIGHT),
            ('GRID',          (0,0),(-1,-1),0.8,colors.HexColor('#AEB6BF')),
            ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',    (0,0),(-1,-1),0),
            ('BOTTOMPADDING', (0,0),(-1,-1),0),
            ('LEFTPADDING',   (0,0),(-1,-1),0),
            ('RIGHTPADDING',  (0,0),(-1,-1),0),
        ]))
        return outer

    # ── Step block ────────────────────────────────────────────

    def step_block(num, title, items, title_bg=None):
        if title_bg is None:
            title_bg = C_BLUE
        head = Table(
            [[_P(f'STEP {num}',
                 ParagraphStyle('sn', fontName=_font(bold=True), fontSize=9,
                                leading=12, textColor=C_SUBTEXT)),
              _P(f'  {title}',
                 ParagraphStyle('st', fontName=_font(bold=True), fontSize=10.5,
                                leading=14, textColor=C_WHITE))]],    
            colWidths=[1.5*cm, (W-2*MARGIN-1.5*cm)]
        )
        head.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1),title_bg),
            ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
            ('TOPPADDING',    (0,0),(-1,-1),8),
            ('BOTTOMPADDING', (0,0),(-1,-1),8),
            ('LEFTPADDING',   (0,0),(-1,-1),8),
        ]))
        body = Table([[_P(f'* {item}', s_step_body)] for item in items],
                     colWidths=[W-2*MARGIN])
        body.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1),C_CREAM),
            ('LEFTPADDING',   (0,0),(-1,-1),20),
            ('TOPPADDING',    (0,0),(-1,-1),4),
            ('BOTTOMPADDING', (0,0),(-1,-1),4),
            ('GRID',          (0,0),(-1,-1),0.4,colors.HexColor('#D5D8DC')),
        ]))
        return KeepTogether([head, body, Spacer(1, 0.25*cm)])
# ── Risk Gauge (SVG-style using ReportLab shapes) ─────────────────────
    def risk_gauge_table(score):
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.shapes import Rect, String, Circle, Wedge, Line
        from reportlab.lib.units import cm as rcm

        gauge_rows = []
        # Build a text-based gauge bar
        filled = int((score / 100) * 30)
        empty  = 30 - filled
        bar_color = C_RED if score >= 70 else C_ORANGE if score >= 40 else C_GREEN
        bar_text  = '█' * filled + '░' * empty

        label_style = ParagraphStyle('gl', fontName=_font(bold=True), fontSize=9,
                                     leading=13, textColor=C_GREY, alignment=1)
        bar_style   = ParagraphStyle('gb', fontName='Courier' if not _fonts_loaded else _font(),
                                     fontSize=11, leading=16, textColor=bar_color, alignment=1)
        score_style = ParagraphStyle('gs', fontName=_font(bold=True), fontSize=22,
                                     leading=28, textColor=bar_color, alignment=1)
        caption_style = ParagraphStyle('gc', fontName=_font(italic=True), fontSize=9,
                                       leading=13, textColor=C_GREY, alignment=1)

        level_text = ('CRITICAL — IMMEDIATE ACTION REQUIRED'
                      if score >= 70 else
                      'HIGH RISK — REVIEW TODAY'
                      if score >= 40 else
                      'ELEVATED — MONITOR CLOSELY'
                      if score >= 20 else
                      'STABLE — CONTINUE MONITORING')

        t = Table([
            [Paragraph('SECURITY RISK METER', label_style)],
            [Paragraph(bar_text, bar_style)],
            [Paragraph(str(score) + ' / 100', score_style)],
            [Paragraph(level_text, caption_style)],
        ], colWidths=[W - 2*MARGIN])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), C_LIGHT),
            ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
            ('TOPPADDING',    (0,0),(-1,-1), 8),
            ('BOTTOMPADDING', (0,0),(-1,-1), 8),
            ('GRID',          (0,0),(-1,-1), 0.4, colors.HexColor('#D5D8DC')),
        ]))
        return t

    # ── Threat trend sparkline (text-based) ───────────────────────────────
    def threat_trend_table(kc_events, hist, hr_count, sus_count, ts_score):
        # Build a simple trend from timeline history grouped by hour
        from collections import OrderedDict
        hourly = OrderedDict()
        for e in hist:
            t_str = e.get('time','00:00:00')
            try: hour = int(t_str.split(':')[0])
            except: hour = 0
            hourly[hour] = hourly.get(hour, 0) + 1

        # If no history, synthesise from current state
        if not hourly:
            cur_h = int(time.strftime('%H'))
            for i in range(5):
                h = max(0, cur_h - (4-i))
                hourly[h] = max(0, int(ts_score * (i+1) / 10))

        hours  = list(hourly.keys())[-6:]
        counts = [hourly[h] for h in hours]
        mx = max(counts) if counts else 1
        mx = mx if mx > 0 else 1
        

        rows = []
        # Sparkline — 5 rows tall
        for row_level in range(4, -1, -1):
            cells = []
            for c in counts:
                filled = (c / mx) >= ((row_level + 1) / 5)
                cells.append(Paragraph(
                    '▓' if filled else ' ',
                    ParagraphStyle('sp', fontName=_font(), fontSize=9, leading=12,
                                   textColor=C_RED if filled else C_GREY, alignment=1)
                ))
            rows.append(cells)

        # Hour labels
        label_row = [
            Paragraph(str(h).zfill(2)+'h',
                      ParagraphStyle('hl', fontName=_font(), fontSize=8, leading=11,
                                     textColor=C_GREY, alignment=1))
            for h in hours
        ]
        rows.append(label_row)

        cw = (W - 2*MARGIN) / max(len(hours), 1)
        t = Table(rows, colWidths=[cw]*len(hours))
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), C_LIGHT),
            ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
            ('TOPPADDING',    (0,0),(-1,-1), 3),
            ('BOTTOMPADDING', (0,0),(-1,-1), 3),
            ('GRID',          (0,0),(-1,-1), 0.3, colors.HexColor('#E0E0E0')),
        ]))
        return t

    # ── Coloured risk heatmap row ─────────────────────────────────────────
    def risk_heatmap_table(b_score, kc_events, blocked_count, trusted_count,
                            fat_score, ts_score):
        rows_data = []
        def risk_level(val, thresholds):
            # thresholds = (low_max, med_max)
            if val <= thresholds[0]: return ('LOW',    C_GREEN,  '🟢')
            if val <= thresholds[1]: return ('MEDIUM', C_ORANGE, '🟡')
            return ('HIGH', C_RED, '🔴')

        browser_risk = risk_level(b_score,    (75, 50))   # score — lower is worse
        browser_risk = ('HIGH', C_RED, '🔴') if b_score < 50 else ('MEDIUM', C_ORANGE, '🟡') if b_score < 75 else ('LOW', C_GREEN, '🟢')

        kc_risk      = risk_level(len(kc_events), (0, 2))
        app_risk     = risk_level(blocked_count,   (5, 20))
        user_risk    = risk_level(fat_score,       (3, 8))
        sys_risk_val = ts_score
        sys_risk     = ('LOW', C_GREEN, '🟢') if sys_risk_val < 20 else ('MEDIUM', C_ORANGE, '🟡') if sys_risk_val < 70 else ('HIGH', C_RED, '🔴')

        categories = [
            ('Browser Security',    browser_risk),
            ('Kill Chain Activity', kc_risk),
            ('Application Risk',    app_risk),
            ('Analyst Fatigue',     user_risk),
            ('System Stability',    sys_risk),
        ]

        rows = []
        for cat, (lvl, col, emoji) in categories:
            rows.append([
                Paragraph(emoji + '  ' + cat,
                          ParagraphStyle('hm', fontName=_font(), fontSize=10, leading=14, textColor=C_BLACK)),
                Paragraph(lvl,
                          ParagraphStyle('hmv', fontName=_font(bold=True), fontSize=10, leading=14, textColor=col, alignment=1)),
            ])

        t = Table(rows, colWidths=[(W-2*MARGIN)*0.72, (W-2*MARGIN)*0.28])
        row_colors_style = []
        for i, (cat, (lvl, col, emoji)) in enumerate(categories):
            bg = colors.HexColor('#FFF0F0') if col==C_RED else colors.HexColor('#FFF8EC') if col==C_ORANGE else colors.HexColor('#F0FFF4')
            row_colors_style.append(('BACKGROUND', (0,i),(-1,i), bg))

        t.setStyle(TableStyle([
            ('VALIGN',         (0,0),(-1,-1), 'MIDDLE'),
            ('LEFTPADDING',    (0,0),(-1,-1), 10),
            ('RIGHTPADDING',   (0,0),(-1,-1), 10),
            ('TOPPADDING',     (0,0),(-1,-1), 7),
            ('BOTTOMPADDING',  (0,0),(-1,-1), 7),
            ('GRID',           (0,0),(-1,-1), 0.5, colors.HexColor('#D5D8DC')),
        ] + row_colors_style))
        return t

    # ── Attack Timeline ───────────────────────────────────────────────────
    def attack_timeline_table(kc_events):
        if not kc_events:
            return Paragraph('No kill chain events recorded in this session.',
                             ParagraphStyle('nt', fontName=_font(italic=True), fontSize=9,
                                            leading=13, textColor=C_GREY))
        # Deduplicate by tactic
        seen_tactics = {}
        ordered = []
        for ev in kc_events:
            t = ev.get('tactic','')
            if t not in seen_tactics:
                seen_tactics[t] = ev
                ordered.append(ev)

        rows = []
        for i, ev in enumerate(ordered[:8]):
            is_last = (i == len(ordered)-1)
            time_s  = ev.get('time','?')
            tactic  = ev.get('tactic','?')
            app_n   = ev.get('app','?')
            action  = ev.get('action','?').upper()
            color   = ev.get('color','warn')
            col = C_RED if color=='danger' else C_ORANGE if color=='warn' else C_GREEN

            connector = '└──' if is_last else '├──'
            icon      = '🔴' if color=='danger' else '🟠' if color=='warn' else '🟢'

            rows.append([
                Paragraph(time_s,
                          ParagraphStyle('tt', fontName=_font(bold=True), fontSize=9,
                                         leading=13, textColor=col)),
                Paragraph(connector + ' ' + icon + ' ' + tactic,
                          ParagraphStyle('tc', fontName=_font(bold=True), fontSize=10,
                                         leading=14, textColor=col)),
                Paragraph(app_n,
                          ParagraphStyle('ta', fontName=_font(), fontSize=9,
                                         leading=13, textColor=C_BLACK)),
                Paragraph(action,
                          ParagraphStyle('tac', fontName=_font(bold=True), fontSize=9,
                                         leading=13,
                                         textColor=C_RED if action=='BLOCKED' else C_ORANGE if action=='KILLED' else C_GREY)),
            ])
            if not is_last:
                rows.append([
                    Paragraph('│', ParagraphStyle('pipe', fontName=_font(), fontSize=9,
                                                   leading=10, textColor=C_GREY)),
                    Paragraph('', s_body), Paragraph('', s_body), Paragraph('', s_body)
                ])

        t = Table(rows, colWidths=[2.2*cm, 6.0*cm, 5.5*cm, 3.8*cm])
        t.setStyle(TableStyle([
            ('VALIGN',         (0,0),(-1,-1), 'TOP'),
            ('ROWBACKGROUNDS', (0,0),(-1,-1), [C_CREAM, C_ROW_A]),
            ('LEFTPADDING',    (0,0),(-1,-1), 8),
            ('RIGHTPADDING',   (0,0),(-1,-1), 8),
            ('TOPPADDING',     (0,0),(-1,-1), 5),
            ('BOTTOMPADDING',  (0,0),(-1,-1), 5),
            ('GRID',           (0,0),(-1,-1), 0.4, colors.HexColor('#D5D8DC')),
        ]))
        return t
    # ════════════════════════════════════════════════════════
    #  COLLECT LIVE DATA
    # ════════════════════════════════════════════════════════
    now_str  = time.strftime("%Y-%m-%d %H:%M:%S")
    date_str = time.strftime("%d %B %Y")
    time_str = time.strftime("%H:%M:%S")

    with data_lock:
        running_apps = list(latest_data["running"])
        suspicious   = list(latest_data["suspicious"])
        high_risk    = list(latest_data["high_risk"])

    with _kill_chain_lock:
        kc_events = list(_kill_chain_events)

    ts_score   = min(int(TIMELINE_DATA.get("score", 0)), 100)
    ts_blocked = TIMELINE_DATA.get("blocked", 0)
    ts_killed  = TIMELINE_DATA.get("killed",  0)
    ts_trusted = TIMELINE_DATA.get("trusted", 0)
    hist       = TIMELINE_DATA.get("history", [])

    fat_score  = fatigue_state.get("score",  0)
    fat_ign    = fatigue_state.get("ignored", 0)
    fat_act    = fatigue_state.get("actions", 0)
    fat_total  = fatigue_state.get("total",   0)
    fat_streak = fatigue_state.get("ignore_streak", 0)
    fat_heat   = fatigue_state.get("heat", {"Low":0,"Medium":0,"High":0})

    bv_recent      = behavior_alerts[-10:]
    btic           = browser_threat_data
    b_threats      = btic.get("threats_detected", 0)
    b_blocked_sites= btic.get("blocked_sites",    0)
    b_flagged      = btic.get("downloads_flagged",0)
    b_score        = btic.get("security_score",   100)

    threat_level = ("CRITICAL" if ts_score >= 70 else
                    "HIGH"     if ts_score >= 40 else
                    "ELEVATED" if ts_score >= 20 else "SAFE")
    fat_level    = ("CRITICAL" if fat_score >= 15 else
                    "HIGH"     if fat_score >= 8  else
                    "MODERATE" if fat_score >= 4  else "NORMAL")

    active_tactics = list({e.get("tactic","") for e in kc_events})
    ign_kc         = sum(1 for e in kc_events if e.get("action") == "ignored")
    eff            = round((fat_act/fat_total*100) if fat_total > 0 else 100)

    # ── Dynamic executive summary ─────────────────────────────────────────
    total_events_detected = b_threats + len(kc_events) + len(high_risk) + len(suspicious)
    _session_start = soc_memory.get("session_start", time_str)
    _session_end   = time_str
    def _exec_summary_text():
        lines = []
        n = 1

        lines.append((n, f"<b><u>Session Overview:</u></b> Guardian monitored "
                      f"<b>{len(running_apps)}</b> active process(es), detected "
                      f"<b>{b_threats}</b> browser threat(s) and "
                      f"<b>{len(kc_events)}</b> MITRE ATT&CK kill-chain event(s)."))
        n += 1

        if high_risk:
            lines.append((n, f"<b><u>High-Risk Applications:</u></b> "
                          f"<b>{', '.join(o.get('app','?') for o in high_risk[:3])}</b> — "
                          f"exhibiting behaviour consistent with active malware activity. "
                          f"Severity: {high_risk[0].get('severity',0)}%."))
            n += 1
        elif suspicious:
            lines.append((n, f"<b><u>Suspicious Processes:</u></b> "
                          f"<b>{', '.join(o.get('app','?') for o in suspicious[:3])}</b> "
                          f"placed under observation."))
            n += 1
        else:
            lines.append((n, f"<b><u>Process Status:</u></b> No active malicious processes "
                          f"detected at time of report generation."))
            n += 1

        if fat_total > 0:
            lines.append((n, f"<b><u>Analyst Activity:</u></b> "
                          f"<b>{fat_total}</b> total alert(s) — "
                          f"<b>{fat_ign}</b> ignored, "
                          f"<b>{fat_act}</b> actioned. "
                          f"Response efficiency: <b>{eff}%</b>. "
                          f"Fatigue score: <b>{fat_score:.1f}/20</b>."))
            n += 1

        if ts_blocked > 0 or ts_killed > 0:
            lines.append((n, f"<b><u>Response Actions:</u></b> "
                          f"<b>{ts_blocked}</b> app(s) permanently blocked, "
                          f"<b>{ts_killed}</b> process(es) terminated this session."))
            n += 1

        if b_threats > 0:
            lines.append((n, f"<b><u>Browser Security:</u></b> "
                          f"<b>{b_threats}</b> threat(s) flagged. Security score: "
                          f"<b>{b_score}/100</b> — "
                          f"{'critically below' if b_score < 50 else 'below'} "
                          f"the recommended threshold of 75."))
            n += 1

        if kc_events:
            tactics_str = ', '.join(list({e.get('tactic','') for e in kc_events})[:4])
            lines.append((n, f"<b><u>Kill Chain Activity:</u></b> Tactics identified: "
                          f"<b>{tactics_str}</b>."
                          + (f" <b>Warning: {ign_kc} event(s) ignored</b> — response gaps detected." if ign_kc > 0 else "")))
            n += 1

        if fat_score >= 8:
            lines.append((n, f"<b><u>Fatigue Alert:</u></b> Analyst fatigue at "
                          f"<b>{fat_score:.1f}/20</b> — response quality may be affected."))
            n += 1
        else:
            lines.append((n, f"<b><u>Analyst Performance:</u></b> "
                          f"Efficient session — fatigue score <b>{fat_score:.1f}/20</b>, "
                          f"efficiency <b>{eff}%</b>."))
            n += 1

        overall = ("CRITICAL - Immediate attention required."
                   if ts_score >= 70 else
                   "HIGH RISK - Review and respond today."
                   if ts_score >= 40 else
                   "ELEVATED - Continue close monitoring."
                   if ts_score >= 20 else
                   "STABLE - Maintain routine monitoring.")
        lines.append((n, f"<b><u>Overall Security Posture:</u></b> <b>{overall}</b>"))
        n += 1

        immediate = "YES" if ts_score >= 40 or high_risk or b_threats > 3 else "NO"
        lines.append((n, f"<b><u>Immediate Attention Required:</u></b> <b>{immediate}</b>"))

        return lines
                  
    _exec_lines = _exec_summary_text()

    # ── Key security events (dynamic) ────────────────────────────────────
    def _key_events_list():
        events = []
        if kc_events:
            for ev in kc_events[-4:]:
                action = ev.get('action','?').upper()
                events.append(f"{ev.get('app','?')} — {ev.get('tactic','?')} [{ev.get('technique','?')}] → {action}")
        if b_threats > 0:
            events.append(f"Browser Security Score reduced to {b_score}/100 — {b_threats} threat(s) blocked")
            risky_b = [s for s in btic.get('websites',[]) if s.get('status')=='High Risk']
            for s in risky_b[:2]:
                events.append(f"Malicious site detected: {s.get('url','?')} ({s.get('risk',0)}% risk)")
        if ts_blocked > 0:
            events.append(f"{ts_blocked} application(s) permanently added to block list")
        if high_risk:
            for obj in high_risk[:2]:
                events.append(f"HIGH RISK: {obj.get('app','?')} — severity {obj.get('severity',0)}%")
        if suspicious:
            for obj in suspicious[:2]:
                events.append(f"SUSPICIOUS: {obj.get('app','?')} — under observation")
        if not events:
            events.append("No significant security events detected in this session.")
        return events

    _key_events = _key_events_list()

    # ── Future risk outlook (dynamic) ────────────────────────────────────
    def _future_risk_outlook():
        factors = []
        predicted = "LOW"

        if b_score < 50:
            factors.append(f"Browser Security Score is critically low at {b_score}/100")
            predicted = "HIGH"
        elif b_score < 75:
            factors.append(f"Browser Security Score of {b_score}/100 is below the recommended threshold")
            if predicted != "HIGH": predicted = "MEDIUM"

        if kc_events:
            active_t = list({e.get('tactic','') for e in kc_events})
            factors.append(f"Active MITRE ATT&CK stage(s) observed: {', '.join(active_t[:3])}")
            predicted = "HIGH"

        if ign_kc > 0:
            factors.append(f"{ign_kc} kill-chain event(s) were ignored — attack may have advanced undetected")
            predicted = "HIGH"

        if high_risk:
            factors.append(f"{len(high_risk)} high-risk application(s) were active during this session")
            predicted = "HIGH"
        elif suspicious:
            factors.append(f"{len(suspicious)} suspicious application(s) flagged for observation")
            if predicted == "LOW": predicted = "MEDIUM"

        if ts_blocked > 20:
            factors.append(f"High block-list volume ({ts_blocked} apps) indicates sustained threat activity")
            if predicted == "LOW": predicted = "MEDIUM"

        if fat_score >= 8:
            factors.append(f"Analyst fatigue ({fat_score:.1f}/20) may reduce response effectiveness in future sessions")
            if predicted == "LOW": predicted = "MEDIUM"

        if not factors:
            factors.append("No significant contributing risk factors identified")
            factors.append("System is operating within normal parameters")
            predicted = "LOW"

        recommendation = (
            "Initiate Emergency Lockdown and escalate to IT Security immediately."
            if predicted == "HIGH" else
            "Continue close monitoring. Address browser threats and review suspicious applications."
            if predicted == "MEDIUM" else
            "Maintain routine scanning schedule. No immediate action required."
        )

        return predicted, factors, recommendation

    _future_risk_level, _future_factors, _future_recommendation = _future_risk_outlook()

    # ── Report ID ─────────────────────────────────────────────────────────
    _report_id = "GSR-" + time.strftime("%Y%m%d-%H%M%S")
    verdict_col = (C_RED    if ts_score >= 70 or fat_score >= 15 else
                   C_ORANGE if ts_score >= 40 or fat_score >= 8  else C_GREEN)
    verdict_txt = ("CRITICAL - IMMEDIATE ACTION REQUIRED"
                   if ts_score >= 70 or fat_score >= 15 else
                   "HIGH RISK - REVIEW AND RESPOND TODAY"
                   if ts_score >= 40 or fat_score >= 8  else
                   "STABLE - CONTINUE MONITORING")

    fat_col  = (C_RED    if fat_score >= 15 else
                C_ORANGE if fat_score >= 8  else C_GREEN)
    ts_col   = (C_RED    if ts_score  >= 70 else
                C_ORANGE if ts_score  >= 40 else
                C_PURPLE if ts_score  >= 20 else C_GREEN)
    eff_col  = C_GREEN if eff >= 70 else C_ORANGE
    bscore_c = C_RED   if b_score < 50 else C_ORANGE if b_score < 75 else C_GREEN

    # ════════════════════════════════════════════════════════
    #  BUILD STORY
    # ════════════════════════════════════════════════════════
    buf  = io.BytesIO()
    doc  = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=MARGIN, rightMargin=MARGIN,
                             topMargin=MARGIN,  bottomMargin=MARGIN,
                             title="Guardian Security Report",
                             author="Guardian Security Platform")
    story = []

    def safe(t):
        return (str(t)
                .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("!", "!")
                .replace("-&gt;","->").replace("*","*"))
# ── COVER PAGE: Executive Summary Box ────────────────────
    exec_box = Table(
        [[Paragraph('EXECUTIVE SECURITY SUMMARY',
                    ParagraphStyle('exh', fontName=_font(bold=True), fontSize=13,
                                   leading=18, textColor=C_BANNER, alignment=1))]],
        colWidths=[W - 2*MARGIN]
    )
    exec_box.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), C_LIGHT),
        ('TOPPADDING',    (0,0),(-1,-1), 0),
        ('BOTTOMPADDING', (0,0),(-1,-1), 0),
        ('LINEBELOW',     (0,0),(-1,0), 1.2, C_HR),
    ]))

    exec_body_rows = []
    for num, line in _exec_lines:
        row = Table(
            [[Paragraph(f"<b>{num}.</b>",
                        ParagraphStyle('enum', fontName=_font(bold=True), fontSize=10,
                                       leading=16, textColor=C_BANNER)),
              Paragraph(line,
                        ParagraphStyle('exb', fontName=_font(), fontSize=10, leading=16,
                                       textColor=C_BLACK, spaceBefore=2))]],
            colWidths=[0.7*cm, W - 2*MARGIN - 0.7*cm]
        )
        row.setStyle(TableStyle([
            ('VALIGN', (0,0),(-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0),(-1,-1), 8),
            ('RIGHTPADDING', (0,0),(-1,-1), 8),
            ('TOPPADDING', (0,0),(-1,-1), 3),
            ('BOTTOMPADDING', (0,0),(-1,-1), 3),
        ]))
        exec_body_rows.append([row])
           
    exec_body_t = Table(exec_body_rows, colWidths=[W - 2*MARGIN])
    exec_body_t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), C_LIGHT),
        ('LEFTPADDING',   (0,0),(-1,-1), 14),
        ('RIGHTPADDING',  (0,0),(-1,-1), 14),
        ('TOPPADDING',    (0,0),(-1,-1), 5),
        ('BOTTOMPADDING', (0,0),(-1,-1), 5),
        ('LINEBELOW',     (0,-1),(-1,-1), 1, C_HR),
    ]))
    # ── BANNER ────────────────────────────────────────────────
    logo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'guardian_logo.png')
    logo_img = None
    if os.path.exists(logo_file):
        try:
            from reportlab.platypus import Image as RLImage
            logo_img = RLImage(logo_file, width=2.0*cm, height=2.0*cm)
        except Exception:
            logo_img = None

    banner_mid = [
        _P('Guardian Security Report',
            ParagraphStyle('bh', fontName=_font(bold=True), fontSize=22,
                           leading=26, textColor=C_WHITE, alignment=0 if logo_img else 1)),
        _P('Real-Time Security Intelligence &amp; Threat Monitoring',
            ParagraphStyle('bs', fontName=_font(italic=True), fontSize=12,
                           leading=16, textColor=C_SUBTEXT, alignment=0 if logo_img else 1)),
        _P(f'Session: {date_str}   |   Generated: {time_str}',
            ParagraphStyle('bg', fontName=_font(), fontSize=9,
                           leading=13, textColor=colors.HexColor('#7FB3D3'),
                           alignment=0 if logo_img else 1))
    ]

    if logo_img:
        banner = Table(
            [[logo_img, Table([[p] for p in banner_mid], colWidths=[W - 2*MARGIN - 2.5*cm])]],
            colWidths=[2.5*cm, W - 2*MARGIN - 2.5*cm]
        )
    else:
        banner = Table([[p] for p in banner_mid], colWidths=[W - 2*MARGIN])

    banner.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1),C_BANNER),
        ('VALIGN',        (0,0),(-1,-1),'MIDDLE'),
        ('TOPPADDING',    (0,0),(-1,-1),10),
        ('BOTTOMPADDING', (0,0),(-1,-1),10),
        ('LEFTPADDING',   (0,0),(-1,-1),12),
        ('RIGHTPADDING',  (0,0),(-1,-1),12),
        ('LINEBELOW',     (0,-1),(-1,-1),2, C_HR),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.4*cm))

    # Threat level badge
    tl_badge = Table(
        [[_P(f'!  THREAT LEVEL:  {threat_level}   |   Score: {ts_score}/100',
             ParagraphStyle('vb', fontName=_font(bold=True), fontSize=14,
                            leading=20, textColor=C_WHITE, alignment=1))]],
        colWidths=[W - 2*MARGIN]
    )
    tl_badge.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1),verdict_col),
        ('TOPPADDING',    (0,0),(-1,-1),10),
        ('BOTTOMPADDING', (0,0),(-1,-1),10),
    ]))
    story.append(tl_badge)
    story.append(Spacer(1, 0.4*cm))
   

    # ── EXECUTIVE SUMMARY (after banner) ─────────────────────
    story.append(exec_box)
    story.append(exec_body_t)
    story.append(Spacer(1, 0.3*cm))

    # ── RISK GAUGE ────────────────────────────────────────────
    story += section_heading('SECURITY RISK METER')
    story.append(risk_gauge_table(ts_score))
    story.append(Spacer(1, 0.3*cm))

    # ── THREAT TREND ──────────────────────────────────────────
    story += section_heading('THREAT ACTIVITY TREND')
    story.append(_P(
        f'Activity trend based on {len(hist)} incident action(s) recorded this session.',
        s_body
    ))
    story.append(Spacer(1, 0.2*cm))
    story.append(threat_trend_table(kc_events, hist, len(high_risk), len(suspicious), ts_score))
    story.append(Spacer(1, 0.3*cm))

    # ── SESSION INFORMATION (before Section 1) ────────────────
    story += section_heading('SESSION INFORMATION')
    story.append(kv_table([
        ('Session Start Time',     _session_start,            C_BLACK),
        ('Report Generated',       _session_end,              C_BLACK),
        ('Processes Monitored',    str(len(running_apps)),    C_GREY),
        ('Threats Detected',       str(total_events_detected),
         C_RED if total_events_detected > 0 else C_GREEN),
        ('Blocked Applications',   str(len(BLOCKED_APPS)),
         C_RED if BLOCKED_APPS else C_GREY),
        ('Trusted Applications',   str(len(TRUSTED_APPS)),   C_GREY),
        ('Browser Security Score', f'{b_score}/100',
         C_RED if b_score < 50 else C_ORANGE if b_score < 75 else C_GREEN),
    ]))
    story.append(Spacer(1, 0.4*cm))


    # ── SECTION 1: SYSTEM OVERVIEW ────────────────────────────
    story += section_heading('1.  SYSTEM PERFORMANCE OVERVIEW')
    story.append(stat_box_row([
        ('Threat Score',    f'{ts_score}/100', ts_col),
        ('Apps Blocked',    str(ts_blocked),   C_RED    if ts_blocked else C_GREY),
        ('Apps Killed',     str(ts_killed),    C_ORANGE if ts_killed  else C_GREY),
        ('Apps Trusted',    str(ts_trusted),   C_GREEN  if ts_trusted else C_GREY),
        ('Total Alerts',    str(fat_total),    C_BLUE),
        ('Alerts Ignored',  str(fat_ign),      C_RED    if fat_ign>3  else C_GREY),
        ('Actions Taken',   str(fat_act),      C_GREEN),
        ('Fatigue Score',   f'{fat_score:.1f}/20', fat_col),
    ]))
    story.append(Spacer(1, 0.2*cm))
    story.append(stat_box_row([
        ('BV Alerts',       str(len(behavior_alerts)), C_ORANGE if behavior_alerts else C_GREY),
        ('KC Events',       str(len(kc_events)),       C_PURPLE if kc_events else C_GREY),
        ('High Risk Apps',  str(len(high_risk)),        C_RED    if high_risk  else C_GREY),
        ('Suspicious Apps', str(len(suspicious)),       C_ORANGE if suspicious else C_GREY),
    ]))
    story.append(Spacer(1, 0.4*cm))

    # ── SECTION 2: LIVE APP STATUS ────────────────────────────
    story += section_heading('2.  LIVE APPLICATION STATUS')
    story.append(_P(
        f'<b>Total running processes monitored: {len(running_apps)}   '
        f'|   High Risk: {len(high_risk)}   |   Suspicious: {len(suspicious)}'
        f'   |   Timestamp: {time_str}</b>',
        s_body
    ))
    story.append(Spacer(1, 0.2*cm))

    if high_risk:
        story.append(_P('<b><u>HIGH RISK PROCESSES DETECTED:</u></b>',
                        _S('hr_lbl', bold=True, size=10, color=C_RED, sa=4)))
        hr_rows = []
        hr_colors = []
        for i, obj in enumerate(high_risk[:8]):
            reason = (obj.get("reasons", ["?"])[0] or "?")[:50]
            hr_rows.append([safe(obj.get("app","?")),
                            f'{obj.get("severity",0)}%',
                            safe(reason), "ACTIVE"])
            hr_colors.append((i, (1,1), C_RED))
            hr_colors.append((i, (3,3), C_RED))
        story.append(data_table(
            ['Application','Severity %','Primary Reason','Status'],
            hr_rows, [4.5*cm, 2.2*cm, 8.5*cm, 2.3*cm], hr_colors
        ))
        story.append(Spacer(1, 0.2*cm))

    if suspicious:
        story.append(_P('<b><u>SUSPICIOUS PROCESSES:</u></b>',
                        _S('sus_lbl', bold=True, size=10, color=C_ORANGE, sa=4)))
        sus_rows = []
        sus_colors = []
        for i, obj in enumerate(suspicious[:6]):
            reason = (obj.get("reasons", ["?"])[0] or "?")[:50]
            sus_rows.append([safe(obj.get("app","?")),
                             f'{obj.get("severity",0)}%',
                             safe(reason), "WATCHING"])
            sus_colors.append((i, (1,1), C_ORANGE))
        story.append(data_table(
            ['Application','Severity %','Primary Reason','Status'],
            sus_rows, [4.5*cm, 2.2*cm, 8.5*cm, 2.3*cm], sus_colors
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── SECTION 3: ANALYST FATIGUE ────────────────────────────
    story += section_heading('3.  ANALYST FATIGUE ANALYSIS')
    story.append(kv_table([
        ('Session Start Time',      soc_memory.get("session_start", time_str), C_BLACK),
        ('Fatigue Score',           f'{fat_score:.1f} / 20  -  {fat_level}',  fat_col),
        ('Total Alerts',            str(fat_total),                             C_BLACK),
        ('Alerts Ignored',          str(fat_ign),       C_RED    if fat_ign>3 else C_GREEN),
        ('Actions Taken',           str(fat_act),                               C_GREEN),
        ('Consecutive Ignores',     str(fat_streak),    C_RED  if fat_streak>=3 else C_GREEN),
        ('Low Priority Alerts',     str(fat_heat.get("Low",0)),                 C_GREY),
        ('Medium Priority Alerts',  str(fat_heat.get("Medium",0)),              C_GREY),
        ('High Priority Alerts',    str(fat_heat.get("High",0)),
         C_RED if fat_heat.get("High",0)>0 else C_GREY),
        ('Response Efficiency',     f'{eff}%',                                  eff_col),
    ]))
    if fat_score >= 8:
        story.append(Spacer(1, 0.15*cm))
        warn_t = Table(
            [[_P(f'! {"CRITICAL" if fat_score>=15 else "HIGH"} FATIGUE DETECTED - '
                 f'Analyst response may be compromised. {fat_ign} alert(s) were ignored.',
                 ParagraphStyle('fw', fontName=_font(bold=True), fontSize=10,
                                leading=14, textColor=C_WHITE))]],
            colWidths=[W-2*MARGIN]
        )
        warn_t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), C_RED if fat_score>=15 else C_ORANGE),
            ('TOPPADDING',    (0,0),(-1,-1),8),
            ('BOTTOMPADDING', (0,0),(-1,-1),8),
            ('LEFTPADDING',   (0,0),(-1,-1),10),
        ]))
        story.append(warn_t)
    story.append(Spacer(1, 0.4*cm))

    # ── KEY SECURITY EVENTS ───────────────────────────────────
    story += section_heading('KEY SECURITY EVENTS')
    ke_rows = [[Paragraph('•  ' + e, s_step_body)] for e in _key_events]
    ke_t = Table(ke_rows, colWidths=[W - 2*MARGIN])
    ke_t.setStyle(TableStyle([
        ('VALIGN',         (0,0),(-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,0),(-1,-1), [C_ROW_A, C_ROW_B]),
        ('LEFTPADDING',    (0,0),(-1,-1), 14),
        ('TOPPADDING',     (0,0),(-1,-1), 6),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 6),
        ('GRID',           (0,0),(-1,-1), 0.4, colors.HexColor('#D5D8DC')),
    ]))
    story.append(ke_t)
    story.append(Spacer(1, 0.3*cm))

    # ── ATTACK TIMELINE ───────────────────────────────────────
    story += section_heading('ATTACK TIMELINE')
    story.append(attack_timeline_table(kc_events))
    story.append(Spacer(1, 0.4*cm))


    # ── SECTION 4: ACTION HISTORY ─────────────────────────────
    if hist:
        story += section_heading('4.  INCIDENT ACTION HISTORY')
        hist_rows   = []
        hist_colors = []
        for i, e in enumerate(hist[-20:]):
            act = e.get("action","?").upper()
            c   = C_RED if act=="BLOCKED" else C_ORANGE if act=="KILLED" else C_GREEN
            hist_rows.append([safe(e.get("time","?")),
                              safe(e.get("app","?")),
                              act,
                              f'x{e.get("count",1)}'])
            hist_colors.append((i,(2,2),c))
        story.append(data_table(
            ['Time','Application','Action','Count'],
            hist_rows, [2.8*cm, 9.5*cm, 3.5*cm, 1.7*cm], hist_colors
        ))
        story.append(Spacer(1, 0.4*cm))

    # ── SECTION 5: MITRE KILL CHAIN ───────────────────────────
    story += section_heading('5.  MITRE ATT&amp;CK KILL CHAIN')
    story.append(kv_table([
        ('Total Kill Chain Events',     str(len(kc_events)),    C_BLACK),
        ('Active Tactics Detected',     str(len(active_tactics)), C_BLACK),
        ('Events Ignored by Analyst',   str(ign_kc),
         C_RED if ign_kc>0 else C_GREEN),
        ('Active Stages',
         ' | '.join(active_tactics[:6]) if active_tactics else 'None', C_PURPLE),
    ]))
    if kc_events:
        story.append(Spacer(1, 0.2*cm))
        kc_rows   = []
        kc_colors = []
        for i, ev in enumerate(kc_events[-15:]):
            act = ev.get("action","?").upper()
            c   = C_RED if act in ("IGNORED","BLOCKED") else \
                  C_ORANGE if act=="KILLED" else C_GREEN
            kc_rows.append([safe(ev.get("time","?")),
                            safe(ev.get("app","?")),
                            safe(ev.get("tactic","?")),
                            safe(ev.get("technique","?")),
                            act])
            kc_colors.append((i,(4,4),c))
        story.append(data_table(
            ['Time','Application','MITRE Tactic','Technique','Action'],
            kc_rows, [2.2*cm, 4.3*cm, 4.3*cm, 2.4*cm, 4.3*cm], kc_colors
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── SECTION 6: BEHAVIOR VIOLATIONS ────────────────────────
    story += section_heading('6.  BEHAVIOR VIOLATION ANALYSIS')
    high_bv = [b for b in behavior_alerts if (b.get("severity",0) or 0) >= 70]
    story.append(kv_table([
        ('Total Violations Logged', str(len(behavior_alerts)),
         C_ORANGE if behavior_alerts else C_GREY),
        ('High Risk Violations',    str(len(high_bv)),
         C_RED if high_bv else C_GREEN),
        ('Last Violation',
         f'{behavior_alerts[-1].get("app","?")} at {behavior_alerts[-1].get("time","?")}'
         if behavior_alerts else '-',  C_GREY),
    ]))
    if bv_recent:
        story.append(Spacer(1, 0.2*cm))
        bv_rows   = []
        bv_colors = []
        for i, b in enumerate(bv_recent):
            viol = (b.get("violation","") or "").replace("! Behavior violation: ","")[:50]
            sev  = b.get("severity",0) or 0
            c    = C_RED if sev>=70 else C_ORANGE if sev>=40 else C_GREY
            bv_rows.append([safe(b.get("time","?")),
                            safe(b.get("app","?")),
                            safe(viol), f'{sev}%'])
            bv_colors.append((i,(3,3),c))
        story.append(data_table(
            ['Time','Application','Violation Detail','Severity %'],
            bv_rows, [2.2*cm, 4.0*cm, 9.5*cm, 1.8*cm], bv_colors
        ))
    else:
        story.append(_P('No behavior violations recorded in this session.', s_body))
    story.append(Spacer(1, 0.4*cm))

    # ── SECTION 7: BROWSER THREAT INTELLIGENCE ────────────────
    story += section_heading('7.  BROWSER THREAT INTELLIGENCE')
    story.append(kv_table([
        ('Browser Security Score', f'{b_score}/100',    bscore_c),
        ('Threats Detected',       str(b_threats),
         C_RED if b_threats>0 else C_GREEN),
        ('Sites Blocked',          str(b_blocked_sites), C_GREY),
        ('Downloads Flagged',      str(b_flagged),        C_GREY),
    ]))
    # Browser Security Assessment block
    browser_status = 'HIGH RISK' if b_score < 50 else 'MODERATE RISK' if b_score < 75 else 'ACCEPTABLE'
    browser_status_col = C_RED if b_score < 50 else C_ORANGE if b_score < 75 else C_GREEN
    browser_reasons = []
    if b_threats > 0:  browser_reasons.append(f'{b_threats} malicious website(s) detected during this session')
    if b_blocked_sites > 0: browser_reasons.append(f'{b_blocked_sites} site(s) were blocked before loading')
    if b_flagged > 0:  browser_reasons.append(f'{b_flagged} download(s) flagged as potentially malicious')
    if b_score < 50:   browser_reasons.append('Browser security score is critically below the safe threshold of 75')
    if not browser_reasons: browser_reasons.append('No browser threats detected — score within acceptable range')

    bsec_rows = [
        [_P('Status', s_kv_key), _P(browser_status,
            ParagraphStyle('bst', fontName=_font(bold=True), fontSize=10, leading=14, textColor=browser_status_col))],
    ]
    for br in browser_reasons:
        bsec_rows.append([_P('Reason', s_kv_key), _P('• ' + br, s_step_body)])
    bsec_t = Table(bsec_rows, colWidths=[5.5*cm, 12.5*cm])
    bsec_t.setStyle(TableStyle([
        ('VALIGN',         (0,0),(-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,0),(-1,-1), [C_ROW_A, C_ROW_B]),
        ('LEFTPADDING',    (0,0),(-1,-1), 8),
        ('RIGHTPADDING',   (0,0),(-1,-1), 8),
        ('TOPPADDING',     (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 5),
        ('GRID',           (0,0),(-1,-1), 0.4, colors.HexColor('#D5D8DC')),
    ]))
    story.append(Spacer(1, 0.2*cm))
    story.append(_P('<b><u>BROWSER SECURITY ASSESSMENT:</u></b>',
                    _S('bsa', bold=True, size=10, color=browser_status_col, sa=4)))
    story.append(bsec_t)
    story.append(Spacer(1, 0.2*cm))
    risky_sites = [s for s in btic.get("websites",[])
                   if s.get("status") in ("High Risk","Suspicious")]
    if risky_sites:
        story.append(Spacer(1, 0.2*cm))
        story.append(_P('<b><u>FLAGGED WEBSITES:</u></b>',
                        _S('rw', bold=True, size=10, color=C_RED, sa=4)))
        sw_rows   = []
        sw_colors = []
        for i, s in enumerate(risky_sites[:6]):
            c = C_RED if s.get("status")=="High Risk" else C_ORANGE
            sw_rows.append([safe(s.get("time","?")),
                            safe(s.get("url","?"))[:32],
                            s.get("status","?"),
                            f'{s.get("risk",0)}%',
                            safe(s.get("reason","?"))[:35]])
            sw_colors.append((i,(2,2),c))
        story.append(data_table(
            ['Time','Website','Status','Risk %','Reason'],
            sw_rows, [1.8*cm, 5.5*cm, 2.5*cm, 1.8*cm, 5.9*cm], sw_colors
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── SECTION 8: SYSTEM HEALTH ──────────────────────────────
    story += section_heading('8.  SYSTEM HEALTH SNAPSHOT')
    story.append(kv_table([
        ('Snapshot Time',           time_str,             C_BLACK),
        ('Processes Monitored',     str(len(running_apps)), C_GREY),
        ('Blocked Applications',    str(len(BLOCKED_APPS)),
         C_RED   if BLOCKED_APPS else C_GREY),
        ('Trusted Applications',    str(len(TRUSTED_APPS)),
         C_GREEN if TRUSTED_APPS else C_GREY),
    ]))
    story.append(Spacer(1, 0.3*cm))

    # ── RISK HEATMAP ──────────────────────────────────────────
    story += section_heading('RISK HEATMAP')
    story.append(risk_heatmap_table(b_score, kc_events, len(BLOCKED_APPS), len(TRUSTED_APPS), fat_score, ts_score))
    story.append(Spacer(1, 0.4*cm))

# ── SECTION 9: PRECAUTIONS ────────────────────────────────

# ── SECTION 9: PRECAUTIONS ────────────────────────────────
    story += section_heading('9.  RECOMMENDED PRECAUTIONS & ACTION')

    precautions = []

    # Build dynamic precautions based on real-time state
    if high_risk:
        top_hr = high_risk[0]
        precautions.append(f"IMMEDIATE: Block or Kill '{top_hr.get('app','?')}' — it is currently running with {top_hr.get('severity',0)}% severity. Reason: {(top_hr.get('reasons') or ['unknown'])[0][:80]}")
    if len(high_risk) > 1:
        for obj in high_risk[1:3]:
            precautions.append(f"HIGH PRIORITY: Investigate '{obj.get('app','?')}' — severity {obj.get('severity',0)}%. Do not ignore this process.")
    if suspicious:
        top_sus = suspicious[0]
        precautions.append(f"MONITOR CLOSELY: '{top_sus.get('app','?')}' is showing suspicious behaviour. If severity exceeds 70%, block immediately.")
    if fat_score >= 15:
        precautions.append(f"CRITICAL FATIGUE ALERT: Analyst fatigue is at {fat_score:.1f}/20. You have ignored {fat_ign} alert(s). Take a break and review all ignored events before proceeding.")
    elif fat_score >= 8:
        precautions.append(f"FATIGUE WARNING: Fatigue score is {fat_score:.1f}/20 with {fat_streak} consecutive ignores. Review skipped alerts — you may have missed something critical.")
    if kc_events:
        tactics_str = ', '.join(list({e.get('tactic','') for e in kc_events})[:4])
        precautions.append(f"KILL CHAIN ACTIVE: {len(kc_events)} kill chain event(s) detected across stages: {tactics_str}. Reconstruct the full attack story and take action on any unresolved events.")
    if ign_kc > 0:
        precautions.append(f"UNRESOLVED EVENTS: {ign_kc} kill chain event(s) were ignored by the analyst. Re-examine these immediately — ignored events allow the attacker to advance undetected.")
    if b_threats > 0:
        precautions.append(f"BROWSER THREAT: {b_threats} browser threat(s) detected. Security score dropped to {b_score}/100. Avoid clicking unknown links and clear browser cache. Review flagged sites in Browser Threat Intelligence panel.")
    if len(BLOCKED_APPS) > 0:
        precautions.append(f"BLOCKED APP POLICY: {len(BLOCKED_APPS)} application(s) are permanently blocked. Ensure block list is backed up and review it periodically for legitimate apps that may have been blocked by mistake.")
    if len(TRUSTED_APPS) > 30:
        precautions.append(f"TRUST REVIEW NEEDED: {len(TRUSTED_APPS)} applications are marked trusted. Periodically audit the trusted list — compromised trusted apps are a common lateral movement vector.")
    if ts_score >= 70:
        precautions.append(f"THREAT SCORE CRITICAL ({ts_score}/100): Your system is under active threat. Consider initiating Emergency Lockdown from the dashboard to automatically block all flagged apps in one click.")
    elif ts_score >= 40:
        precautions.append(f"THREAT SCORE HIGH ({ts_score}/100): Multiple risk factors are contributing to an elevated threat level. Address high-risk apps and reduce alert fatigue to bring score down.")
    if fat_ign == 0 and fat_act >= 3:
        precautions.append(f"EXCELLENT ANALYST PERFORMANCE: Zero alerts ignored with {fat_act} decisive actions taken. Continue this pattern — consistent engagement is the best defence against fatigue-induced breaches.")
    if not precautions:
        precautions.append("SYSTEM STABLE: No active threats detected at time of report generation. Continue routine monitoring and run a fresh scan every 15 minutes during active sessions.")
        precautions.append("BASELINE HYGIENE: Ensure all applications in the Live App Monitor are recognised. Any unknown or rarely-seen executable should be investigated even if not currently flagged.")
        precautions.append("PROACTIVE DEFENCE: Simulate a demo attack periodically to test your response time and keep the kill chain analysis up to date.")

    prec_rows = []
    for i, p in enumerate(precautions, 1):
        prec_rows.append([_P(str(i), _S('pn', bold=True, size=11, color=C_BANNER, align=1)),
                          _P(p, s_step_body)])
    prec_t = Table(prec_rows, colWidths=[1.0*cm, W - 2*MARGIN - 1.0*cm])
    prec_t.setStyle(TableStyle([
        ('VALIGN',         (0,0),(-1,-1),'TOP'),
        ('ROWBACKGROUNDS', (0,0),(-1,-1),[C_ROW_A, C_ROW_B]),
        ('LEFTPADDING',    (0,0),(-1,-1),8),
        ('RIGHTPADDING',   (0,0),(-1,-1),8),
        ('TOPPADDING',     (0,0),(-1,-1),7),
        ('BOTTOMPADDING',  (0,0),(-1,-1),7),
        ('GRID',           (0,0),(-1,-1),0.4,colors.HexColor('#D5D8DC')),
    ]))
    story.append(prec_t)
    story.append(Spacer(1, 0.4*cm))
    # ── SECTION 10: CURRENT SYSTEM PERFORMANCE ───────────────
    story += section_heading('10.  CURRENT SYSTEM PERFORMANCE ASSESSMENT')

    try:
        cpu_now  = psutil.cpu_percent(interval=0.5)
        ram_now  = psutil.virtual_memory().percent
        disk_now = psutil.disk_usage('/').percent
    except:
        cpu_now = ram_now = disk_now = 0

    cpu_col  = C_RED if cpu_now  >= 80 else C_ORANGE if cpu_now  >= 50 else C_GREEN
    ram_col  = C_RED if ram_now  >= 80 else C_ORANGE if ram_now  >= 50 else C_GREEN
    disk_col = C_RED if disk_now >= 90 else C_ORANGE if disk_now >= 70 else C_GREEN

    story.append(stat_box_row([
        ('CPU Usage',      f'{cpu_now}%',   cpu_col),
        ('RAM Usage',      f'{ram_now}%',   ram_col),
        ('Disk Usage',     f'{disk_now}%',  disk_col),
        ('Processes',      str(len(running_apps)), C_BLUE),
    ]))
    story.append(Spacer(1, 0.25*cm))

    # Dynamic performance narrative — changes based on actual state
    perf_lines = []
    overall_health = "HEALTHY"
    if cpu_now >= 80 or ram_now >= 80:
        overall_health = "STRESSED"
    elif cpu_now >= 50 or ram_now >= 50:
        overall_health = "MODERATE"
    if high_risk:
        overall_health = "COMPROMISED"

    if overall_health == "COMPROMISED":
        perf_lines.append(f"Overall Status: COMPROMISED — {len(high_risk)} high-risk process(es) are actively running on this system right now.")
        perf_lines.append(f"The system cannot be considered healthy while '{high_risk[0].get('app','?')}' (severity {high_risk[0].get('severity',0)}%) remains active.")
        if cpu_now >= 60:
            perf_lines.append(f"CPU is running at {cpu_now}% — elevated load during an active threat suggests the malicious process may be consuming significant resources (encryption, mining, or thread spawning).")
        if ram_now >= 60:
            perf_lines.append(f"RAM at {ram_now}% — high memory usage during a threat event can indicate data staging, memory injection, or unpacking of a malicious payload.")
    elif overall_health == "STRESSED":
        perf_lines.append(f"Overall Status: STRESSED — no confirmed active threats, but system resources are under pressure.")
        if cpu_now >= 80:
            perf_lines.append(f"CPU is at {cpu_now}%. Without a known cause (e.g. video encoding, antivirus scan), this warrants investigation. Check the Live App Monitor for any process with abnormal CPU usage.")
        if ram_now >= 80:
            perf_lines.append(f"RAM is at {ram_now}%. Identify the top memory consumer. Memory pressure at this level can indicate data-intensive operations running in the background.")
    elif overall_health == "MODERATE":
        perf_lines.append(f"Overall Status: MODERATE — system is functional with no confirmed compromise. Some resources are moderately loaded.")
        perf_lines.append(f"CPU: {cpu_now}% | RAM: {ram_now}% | Disk: {disk_now}%. These values are within acceptable range but should be watched if they continue rising.")
        if suspicious:
            perf_lines.append(f"There {'is' if len(suspicious)==1 else 'are'} {len(suspicious)} suspicious process(es) being monitored. Even under moderate load, a misbehaving process can escalate quickly.")
    else:
        perf_lines.append(f"Overall Status: HEALTHY — all system metrics are within normal operating range.")
        perf_lines.append(f"CPU: {cpu_now}% | RAM: {ram_now}% | Disk: {disk_now}%. No resource anomalies detected at time of report.")
        if not high_risk and not suspicious:
            perf_lines.append("No active threats or suspicious processes detected. The system is operating cleanly based on current scan data.")
        perf_lines.append("Continue periodic scans to maintain this baseline. Early detection depends on frequent monitoring rather than reactive response.")

    if disk_now >= 85:
        perf_lines.append(f"DISK ALERT: Disk usage is at {disk_now}%. High disk usage can slow incident response tools and logging systems. Free up space to ensure Guardian can operate at full capacity.")

    # Analyst performance summary line
    if eff >= 80 and fat_score < 5:
        perf_lines.append(f"Analyst performance this session: EXCELLENT ({eff}% efficiency, fatigue score {fat_score:.1f}/20). The combination of low fatigue and high response rate is the gold standard for security operations.")
    elif eff >= 60:
        perf_lines.append(f"Analyst performance this session: GOOD ({eff}% efficiency). {fat_act} action(s) taken, {fat_ign} ignored. Review ignored alerts to close any potential gaps.")
    else:
        perf_lines.append(f"Analyst performance this session: NEEDS REVIEW ({eff}% efficiency, {fat_ign} ignored alerts). A low efficiency rate combined with active threats is a high-risk combination. Prioritise alert review.")

    perf_rows = []
    for i, line in enumerate(perf_lines, 1):
        perf_rows.append([_P(str(i), _S('pp', bold=True, size=11, color=C_BANNER, align=1)),
                          _P(line, s_step_body)])
    perf_t = Table(perf_rows, colWidths=[1.0*cm, W - 2*MARGIN - 1.0*cm])
    perf_t.setStyle(TableStyle([
        ('VALIGN',         (0,0),(-1,-1),'TOP'),
        ('ROWBACKGROUNDS', (0,0),(-1,-1),[C_CREAM, C_ROW_A]),
        ('LEFTPADDING',    (0,0),(-1,-1),8),
        ('RIGHTPADDING',   (0,0),(-1,-1),8),
        ('TOPPADDING',     (0,0),(-1,-1),7),
        ('BOTTOMPADDING',  (0,0),(-1,-1),7),
        ('GRID',           (0,0),(-1,-1),0.4,colors.HexColor('#D5D8DC')),
    ]))
    story.append(perf_t)
    story.append(Spacer(1, 0.4*cm))
    # ── FUTURE RISK OUTLOOK ───────────────────────────────────
    story += section_heading('FUTURE RISK OUTLOOK')
    fro_rows = [
        [_P('Predicted Risk Level', s_kv_key),
         _P(_future_risk_level,
            ParagraphStyle('frl', fontName=_font(bold=True), fontSize=12, leading=16,
                           textColor=C_RED if _future_risk_level=='HIGH' else C_ORANGE if _future_risk_level=='MEDIUM' else C_GREEN))],
    ]
    for fac in _future_factors:
        fro_rows.append([_P('Contributing Factor', s_kv_key), _P('• ' + fac, s_step_body)])
    fro_rows.append([_P('Recommendation', s_kv_key),
                     _P(_future_recommendation,
                        ParagraphStyle('frec', fontName=_font(bold=True), fontSize=10, leading=15,
                                       textColor=C_HEAD))])
    fro_t = Table(fro_rows, colWidths=[5.5*cm, 12.5*cm])
    fro_t.setStyle(TableStyle([
        ('VALIGN',         (0,0),(-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,0),(-1,-1), [C_ROW_A, C_ROW_B]),
        ('LEFTPADDING',    (0,0),(-1,-1), 8),
        ('RIGHTPADDING',   (0,0),(-1,-1), 8),
        ('TOPPADDING',     (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',  (0,0),(-1,-1), 5),
        ('GRID',           (0,0),(-1,-1), 0.4, colors.HexColor('#D5D8DC')),
    ]))
    story.append(fro_t)
    story.append(Spacer(1, 0.4*cm))

    # ── REPORT INFORMATION ────────────────────────────────────
    story += section_heading('REPORT INFORMATION')
    story.append(kv_table([
        ('Report ID',        _report_id,  C_BLUE),
        ('Generated Time',   now_str,     C_BLACK),
        ('Version',          '1.0',       C_GREY),
        ('Session Start',    _session_start, C_BLACK),
        ('Processes Monitored', str(len(running_apps)), C_GREY),
        ('Total Events',     str(total_events_detected),
         C_RED if total_events_detected > 0 else C_GREEN),
    ]))
    story.append(Spacer(1, 0.2*cm))
    story.append(_P(
        'This report summarises monitored processes, security incidents, browser threats, '
        'MITRE ATT&CK kill-chain events and response actions recorded during the selected '
        'monitoring session. All data is generated dynamically from live GUARDIAN CHATBOT '
        'Security telemetry and reflects the actual state of the system at the time of generation.',
        ParagraphStyle('ri', fontName=_font(italic=True), fontSize=9, leading=14,
                       textColor=C_GREY, spaceBefore=4)
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(_P(
        '© Guardian Security Platform 2026  •  Confidential — Internal Use Only',
        ParagraphStyle('copy', fontName=_font(bold=True), fontSize=9, leading=13,
                       textColor=C_BANNER, alignment=1)
    ))
    story.append(Spacer(1, 0.2*cm))

   # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=C_HR, spaceAfter=6))
    story.append(_P(
        f'Guardian Security Report  •  {_report_id}  •  Generated {now_str}  •  Confidential — Internal Use Only',
        s_foot
    ))

    # ── BUILD & RETURN ────────────────────────────────────────
    doc.build(story)

    buf.seek(0)
    pdf_bytes = buf.read()

    # Automatically save a copy to the user's Downloads directory
    try:
        downloads_dir = _get_downloads_dir()
        pdf_path = os.path.join(downloads_dir, f"Guardian_Security_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
        with open(os.path.join(downloads_dir, "Guardian_Security_Report.pdf"), "wb") as f:
            f.write(pdf_bytes)
        print(f"[PDF Export] Successfully saved to {pdf_path}")
    except Exception as e:
        print(f"[PDF Export Notice] {e}")

    response = make_response(pdf_bytes)

    response.headers['Content-Type'] = 'application/pdf'

    response.headers['Content-Disposition'] = 'attachment; filename=Guardian_Security_Report.pdf'

    response.headers['Access-Control-Allow-Origin'] = '*'

    return response

# ── Background monitor ────────────────────────────────────────────────────────
def monitor_running_apps():
    while True:
        for proc in psutil.process_iter(['name']):
            try:
                n=proc.info['name']
                if not n: continue
                nl=n.lower()
                if nl in SAFE_APPS: continue
                if nl in BLOCKED_APPS: _kill_proc(nl); continue
                if nl in TRUSTED_APPS: continue
                if nl in HIGH_RISK_APPS: _kill_proc(nl)
            except: pass
        time.sleep(1)

# ════════════════════════════════════════════════════════════════
# ── BROWSER THREAT INTELLIGENCE CENTER (100% Real-Time Engine)
# ════════════════════════════════════════════════════════════════

NOISE_PATTERNS = [
    ".events.data.microsoft.com", ".telemetry.microsoft.com", ".data.microsoft.com",
    ".trafficmanager.net", ".azureedge.net", ".azure.com", ".azurewebsites.net",
    ".windowsupdate.com", "watson.", "settings-win.", "activity.windows.com",
    "wdcp.microsoft.com", "smartscreen.", "c.bing.com", "c.msn.com", "api.msn.com",
    "assets.msn.com", "sb.scorecardresearch.com", "datadoghq.com", "datadoghq.eu",
    "browser-intake", "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "clarity.ms", "sentry.io", "segment.io", "mixpanel.com", "telemetry.",
    "optimizationguide-pa.googleapis.com", "chrome-variations.googleapis.com",
    "clientservices.googleapis.com", "safebrowsing.", "pki.goog", "digicert.com",
    "lencr.org", "sectigo.com", "update.googleapis.com", "gvt1.com", "127.0.0.1", "localhost"
]

def _is_browser_noise(hostname):
    if not hostname:
        return True
    h = hostname.lower().strip()
    if ":" in h:
        h = h.split(":")[0]
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

def _get_running_browsers():
    active = []
    try:
        import psutil
        for p in psutil.process_iter(['name']):
            n = (p.info['name'] or '').lower()
            if not n:
                continue
            for exes, b_name in BROWSER_DEFINITIONS:
                if (n in exes or ('duckduckgo' in n and b_name == 'DuckDuckGo')) and b_name not in active:
                    active.append(b_name)
                    break
    except Exception:
        pass
    return active

browser_threat_data = {
    "websites": [],
    "downloads": [],
    "permissions": [],
    "redirects": [],
    "timeline": [],
    "active_browsers": _get_running_browsers(),
    "threats_detected": 0,
    "blocked_sites": 0,
    "downloads_flagged": 0,
    "security_score": 100,
}

_known_download_files = set()

def _scan_realtime_downloads():
    global browser_threat_data, _known_download_files
    dl_dir = os.path.expanduser('~/Downloads')
    if not os.path.exists(dl_dir):
        return []
    
    items = []
    try:
        entries = os.listdir(dl_dir)
    except Exception:
        return []

    for f in entries:
        fp = os.path.join(dl_dir, f)
        if os.path.isfile(fp):
            try:
                st = os.stat(fp)
                if time.time() - st.st_mtime < 86400 * 3:
                    ext = os.path.splitext(f)[1].lower()
                    size_mb = st.st_size / (1024 * 1024)
                    size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{st.st_size/1024:.1f} KB"
                    mtime_str = time.strftime('%H:%M:%S', time.localtime(st.st_mtime))
                    
                    parts = f.lower().split('.')
                    if len(parts) > 2 and parts[-1] in ('exe', 'bat', 'vbs', 'ps1', 'scr', 'cmd'):
                        status = 'Blocked'
                        reason = 'Double Extension Detected — potential malware vector'
                        risk = 95
                    elif ext in ('.exe', '.msi', '.scr', '.cpl', '.iso', '.vbs', '.bat', '.ps1', '.reg'):
                        status = 'Suspicious'
                        reason = 'Executable installer downloaded from web'
                        risk = 60
                    elif ext in ('.zip', '.rar', '.7z', '.tar', '.gz'):
                        status = 'Allowed'
                        reason = 'Compressed archive container'
                        risk = 15
                    else:
                        status = 'Allowed'
                        reason = 'Clean file signature'
                        risk = 5
                    
                    if f not in _known_download_files:
                        _known_download_files.add(f)
                        if len(_known_download_files) > 1:
                            icon = "🔴" if status == "Blocked" else "🟡" if status == "Suspicious" else "🟢"
                            browser_threat_data["timeline"].insert(0, {
                                "time": mtime_str,
                                "event": f"{icon} Download: {f}",
                                "detail": f"{reason} ({size_str})"
                            })
                            browser_threat_data["timeline"] = browser_threat_data["timeline"][:40]
                            if status == "Blocked":
                                browser_threat_data["threats_detected"] += 1
                                browser_threat_data["downloads_flagged"] += 1
                            elif status == "Suspicious":
                                browser_threat_data["downloads_flagged"] += 1

                    items.append({
                        "file": f,
                        "size": size_str,
                        "time": mtime_str,
                        "mtime": st.st_mtime,
                        "status": status,
                        "reason": reason,
                        "risk": risk
                    })
            except Exception:
                pass
                
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items[:50]

def _scan_realtime_permissions():
    perms = []
    caps = [('webcam', 'Webcam'), ('microphone', 'Microphone'), ('location', 'Location')]
    for cap_key, cap_label in caps:
        path = rf"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{cap_key}"
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            num_subkeys = winreg.QueryInfoKey(k)[0]
            for i in range(num_subkeys):
                subkey_name = winreg.EnumKey(k, i)
                try:
                    subk = winreg.OpenKey(k, subkey_name)
                    val = winreg.QueryValueEx(subk, 'Value')[0]
                    app_clean = subkey_name.split('#')[-1] if '#' in subkey_name else subkey_name
                    app_clean = app_clean.replace('_8wekyb3d8bbwe', '').replace('_cv1g1gvanyjgm', '')
                    if 'Microsoft.' in app_clean:
                        app_clean = app_clean.replace('Microsoft.', '')
                    perms.append({
                        "site": app_clean,
                        "request": cap_label,
                        "status": "Allowed" if val == "Allow" else "Blocked",
                        "time": "Active"
                    })
                    winreg.CloseKey(subk)
                except Exception:
                    pass
            winreg.CloseKey(k)
        except Exception:
            pass
    return perms[:40]


def save_browser_data():
    try:
        with open(BROWSER_THREAT_FILE, "w", encoding="utf-8") as f:
            json.dump(browser_threat_data, f, indent=2)
    except Exception:
        pass

def load_browser_data():
    global browser_threat_data
    if os.path.exists(BROWSER_THREAT_FILE):
        try:
            with open(BROWSER_THREAT_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                d["websites"] = [w for w in d.get("websites", []) if not _is_browser_noise(w.get("url", ""))]
                d["timeline"] = [t for t in d.get("timeline", []) if not any(np in t.get("event", "").lower() for np in NOISE_PATTERNS)]
                browser_threat_data.update(d)
        except Exception:
            pass

load_browser_data()

KNOWN_MALICIOUS_DOMAINS = [
    "phishing","malware","trojan","hack","crack","keygen","warez",
    "fakebank","verify-login","account-suspended","free-virus",
    "bit.ly","tinyurl","trackclick","adclick"
]

KNOWN_SAFE_DOMAINS = [
    "google","youtube","microsoft","github","stackoverflow",
    "amazon","wikipedia","reddit","twitter","linkedin","facebook",
    "instagram","netflix","spotify","apple","cloudflare","anthropic","claude"
]

def _classify_domain(hostname):
    h = hostname.lower()
    for bad in KNOWN_MALICIOUS_DOMAINS:
        if bad in h:
            return "High Risk", 90, "Suspicious domain pattern detected"
    for safe in KNOWN_SAFE_DOMAINS:
        if safe in h:
            return "Safe", 5, "Known trusted domain"
    if h.endswith('.xyz') or h.endswith('.tk') or h.endswith('.top') or h.endswith('.pw'):
        return "Suspicious", 65, "Uncommon TLD — often used in phishing"
    if len(h.replace('www.','').split('.')[0]) > 25:
        return "Suspicious", 55, "Unusually long domain name"
    return "Safe", 15, "No known threats detected"

def _record_browser_visit_internal(clean_host, full_url="", title="", browser="Google Chrome", profile="Default"):
    if not clean_host or _is_browser_noise(clean_host):
        return
    clean_host = clean_host.lower().strip()
    status, risk, reason = _classify_domain(clean_host)
    ts_local = time.strftime("%H:%M:%S")

    recent_urls = [w.get("url", "").lower() for w in browser_threat_data["websites"][:3]]
    if recent_urls and recent_urls[0] == clean_host:
        return

    entry = {
        "url":       clean_host,
        "full_url":  full_url if full_url else f"https://{clean_host}/",
        "title":     title,
        "status":    status,
        "risk":      risk,
        "reason":    reason,
        "time":      ts_local,
        "browser":   browser,
        "profile":   profile,
    }

    browser_threat_data["websites"].insert(0, entry)
    browser_threat_data["websites"] = browser_threat_data["websites"][:50]

    icon_map = {"High Risk": "🔴", "Suspicious": "🟡", "Safe": "🟢"}
    browser_threat_data["timeline"].insert(0, {
        "time":   ts_local,
        "event":  f"{icon_map.get(status,'⚪')} Visited: {clean_host}",
        "detail": f"{reason} ({browser})",
    })
    browser_threat_data["timeline"] = browser_threat_data["timeline"][:40]

    if status == "High Risk":
        browser_threat_data["threats_detected"] = browser_threat_data.get("threats_detected", 0) + 1
        browser_threat_data["blocked_sites"]    = browser_threat_data.get("blocked_sites", 0) + 1
        browser_threat_data["security_score"]   = max(0, browser_threat_data.get("security_score", 100) - 8)

    save_browser_data()
    try:
        print(f"[Browser Sniffer] 🌐 {ts_local} - {clean_host} ({browser}) -> {status} ({risk}%)")
    except Exception:
        pass

def _sniff_active_browser_activity():
    """
    High-frequency Win32 foreground window and active socket sniffer.
    Detects when a user navigates to any website in Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Arc, Tor, DuckDuckGo etc.
    Extracts the domain and logs it to Browser Threat Intelligence Center immediately.
    """
    import ctypes
    last_detected_key = ""
    last_detected_time = 0

    domain_regex = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|edu|gov|io|ai|app|dev|in|co|uk|de|xyz|top|info|me|tv|cc|tech|online|site|store|club|us|ca|au|fr|jp|ru|cn|br)(?::\d+)?)', re.IGNORECASE)

    site_map = {
        "google search": "google.com", "google": "google.com", "youtube": "youtube.com",
        "github": "github.com", "stackoverflow": "stackoverflow.com", "stack overflow": "stackoverflow.com",
        "reddit": "reddit.com", "wikipedia": "wikipedia.org", "amazon": "amazon.com",
        "claude": "claude.ai", "chatgpt": "chatgpt.com", "openai": "openai.com",
        "twitter": "x.com", "linkedin": "linkedin.com", "instagram": "instagram.com",
        "facebook": "facebook.com", "netflix": "netflix.com", "spotify": "spotify.com",
        "discord": "discord.com", "twitch": "twitch.tv", "bing": "bing.com",
        "duckduckgo": "duckduckgo.com", "fast.com": "fast.com", "speedtest": "speedtest.net",
        "hugging face": "huggingface.co", "canva": "canva.com", "gmail": "mail.google.com",
        "outlook": "outlook.live.com", "yahoo": "yahoo.com", "ebay": "ebay.com",
        "aliexpress": "aliexpress.com", "walmart": "walmart.com", "paypal": "paypal.com",
        "medium": "medium.com", "quora": "quora.com", "whatsapp": "web.whatsapp.com",
        "telegram": "web.telegram.org", "slack": "slack.com", "zoom": "zoom.us",
        "notion": "notion.so", "figma": "figma.com", "trello": "trello.com",
        "pinterest": "pinterest.com", "tiktok": "tiktok.com"
    }

    browser_suffixes = [
        " - Google Chrome", " - Microsoft Edge", " - Personal - Microsoft Edge",
        " - Work - Microsoft Edge", " - Profile 1 - Microsoft Edge", " - Profile 2 - Microsoft Edge",
        " - Mozilla Firefox", " - Brave", " - Opera GX", " - Opera", " - Vivaldi",
        " - Arc", " - Tor Browser", " - DuckDuckGo", " - Waterfox", " - LibreWolf",
        " - Zen Browser", " - Sidekick", " - Chromium"
    ]

    while True:
        try:
            time.sleep(0.5)
            hwnd = ctypes.windll.user32.GetForegroundWindow()
            if not hwnd:
                continue

            pid = ctypes.c_ulong()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if not pid.value:
                continue

            try:
                proc = psutil.Process(pid.value)
                pname = (proc.name() or "").lower()
            except Exception:
                continue

            matched_browser = None
            for exes, b_name in BROWSER_DEFINITIONS:
                if pname in exes or ('duckduckgo' in pname and b_name == 'DuckDuckGo'):
                    matched_browser = b_name
                    break

            if not matched_browser:
                continue

            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                continue

            buf = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            raw_title = buf.value.strip()

            if not raw_title or raw_title in ("New Tab", "Settings", "Downloads", "History", "Extensions"):
                continue

            clean_title = raw_title
            for suffix in browser_suffixes:
                if clean_title.endswith(suffix):
                    clean_title = clean_title[:-len(suffix)].strip()
                    break

            extracted_domain = None
            domain_match = domain_regex.search(clean_title)
            if domain_match:
                extracted_domain = domain_match.group(1).lower()
            else:
                title_lower = clean_title.lower()
                for key, dom in site_map.items():
                    if key in title_lower:
                        extracted_domain = dom
                        break

            if not extracted_domain:
                first_part = clean_title.split(" - ")[0].split(" | ")[0].split(" · ")[0].strip()
                if 2 < len(first_part) < 35:
                    clean_token = re.sub(r'[^a-zA-Z0-9]', '', first_part).lower()
                    if clean_token and not clean_token.isdigit() and len(clean_token) > 2:
                        extracted_domain = f"{clean_token}.com"

            if not extracted_domain or _is_browser_noise(extracted_domain):
                continue

            now = time.time()
            dedup_key = f"{extracted_domain}_{matched_browser}"
            if dedup_key == last_detected_key and (now - last_detected_time) < 12:
                continue

            last_detected_key = dedup_key
            last_detected_time = now

            _record_browser_visit_internal(
                clean_host=extracted_domain,
                full_url=f"https://{extracted_domain}/",
                title=clean_title,
                browser=matched_browser
            )

        except Exception:
            pass

threading.Thread(target=_sniff_active_browser_activity, daemon=True).start()

@app.route("/api/browser_visit", methods=["POST"])
def api_browser_visit():
    data = request.json or {}
    hostname  = data.get("url", "")
    full_url  = data.get("full_url", "")
    title     = data.get("title", "")
    browser   = data.get("browser", "")
    profile   = data.get("profile", "Default")

    if not hostname or _is_browser_noise(hostname):
        return jsonify({"status": "skip"}), 200

    clean_host = hostname.split(":")[0] if ":" in hostname else hostname
    clean_host = clean_host.lower().strip()

    if not browser or browser in ("Unknown", "Browser"):
        running_b = _get_running_browsers()
        browser = running_b[0] if running_b else "Google Chrome"

    _record_browser_visit_internal(clean_host, full_url, title, browser, profile)
    status, _, _ = _classify_domain(clean_host)
    return jsonify({"status": "logged", "hostname": clean_host, "classification": status})

@app.route("/api/browser_data", methods=["GET"])
def api_browser_data():
    global browser_threat_data
    live_dls = _scan_realtime_downloads()
    browser_threat_data["downloads"] = live_dls
    
    live_perms = _scan_realtime_permissions()
    browser_threat_data["permissions"] = live_perms
    
    browser_threat_data["active_browsers"] = _get_running_browsers()
    
    flagged_dls = sum(1 for d in live_dls if d.get("status") in ("Blocked", "Suspicious"))
    browser_threat_data["downloads_flagged"] = flagged_dls
    
    base_score = 100
    base_score -= min(30, browser_threat_data.get("threats_detected", 0) * 10)
    base_score -= min(20, browser_threat_data.get("blocked_sites", 0) * 8)
    base_score -= min(25, flagged_dls * 8)
    browser_threat_data["security_score"] = max(0, min(100, base_score))

    return jsonify(browser_threat_data)

@app.route("/api/browser_simulate", methods=["POST"])
def api_browser_simulate():
    global browser_threat_data
    data = request.json or {}
    sim_type = data.get("type", "full")
    now = time.strftime("%H:%M:%S")

    SCENARIOS = {
        "phishing": {
            "website": {"url": "sbi-verification-login.xyz", "browser": "Google Chrome", "status": "High Risk", "risk": 95, "reason": "Domain resembles banking website — possible phishing", "time": now},
            "timeline": [
                {"time": now, "event": "🔴 Threat Blocked: sbi-verification-login.xyz", "detail": "Phishing domain spoofing pattern detected"},
                {"time": now, "event": "🟡 Phishing Alert", "detail": "High-risk domain blocked before credential entry"},
            ],
            "score_delta": -18,
            "threats": 1, "blocked": 1,
        },
        "malicious_download": {
            "download": {"file": "invoice.pdf.exe", "size": "1.24 MB", "time": now, "status": "Blocked", "reason": "Double Extension Detected — likely malware", "risk": 95},
            "timeline": [
                {"time": now, "event": "🔴 Download Blocked: invoice.pdf.exe", "detail": "Double Extension .pdf.exe blocked from execution"},
            ],
            "score_delta": -12,
            "threats": 1, "flagged": 1,
        },
        "permission_abuse": {
            "permission": {"site": "random-video-site.com", "request": "Camera + Microphone", "status": "Blocked", "time": now},
            "timeline": [
                {"time": now, "event": "🔴 Permission Blocked: random-video-site.com", "detail": "Camera & Microphone access blocked for untrusted domain"},
            ],
            "score_delta": -8,
            "threats": 1,
        },
        "redirect_attack": {
            "redirect": {
                "chain": ["offer-promo.net", "verify-token.org", "credential-harvest.xyz"],
                "status": "High Risk",
                "reason": "3-hop redirect chain — phishing funnel",
                "time": now
            },
            "timeline": [
                {"time": now, "event": "🔴 Redirect Blocked", "detail": "offer-promo.net → verify-token.org → credential-harvest.xyz"},
            ],
            "score_delta": -15,
            "threats": 1, "blocked": 1,
        },
        "full": {
            "websites": [
                {"url": "fake-bank-login.xyz", "browser": "Microsoft Edge", "status": "High Risk", "risk": 94, "reason": "Phishing domain pattern — counterfeit banking portal", "time": now},
                {"url": "github.com", "browser": "Google Chrome", "status": "Safe", "risk": 2, "reason": "Verified development platform", "time": now},
                {"url": "claude.ai", "browser": "Google Chrome", "status": "Safe", "risk": 3, "reason": "Verified assistant platform", "time": now},
            ],
            "downloads": [
                {"file": "security_update_patch.pdf.exe", "size": "2.10 MB", "time": now, "status": "Blocked", "reason": "Double Extension Detected — trojan dropper", "risk": 98},
                {"file": "keygen_crack_installer.zip", "size": "4.80 MB", "time": now, "status": "Suspicious", "reason": "Piracy-related pattern", "risk": 65},
            ],
            "permissions": [
                {"site": "Google Chrome", "request": "Camera", "status": "Allowed", "time": "Active"},
                {"site": "Microsoft Edge", "request": "Microphone", "status": "Allowed", "time": "Active"},
                {"site": "suspicious-stream.xyz", "request": "Microphone", "status": "Blocked", "time": now},
            ],
            "redirects": [
                {"chain": ["offer-promo.net", "verify-token.org", "credential-harvest.xyz"], "status": "High Risk", "reason": "3-hop redirect chain", "time": now},
            ],
            "timeline": [
                {"time": now, "event": "🔴 Threat Blocked: fake-bank-login.xyz", "detail": "Phishing domain pattern detected"},
                {"time": now, "event": "🔴 Download Blocked: security_update_patch.pdf.exe", "detail": "Double extension .pdf.exe neutralized"},
                {"time": now, "event": "🟡 Permission Blocked: suspicious-stream.xyz", "detail": "Microphone access denied"},
                {"time": now, "event": "🟢 Visited: claude.ai", "detail": "Verified assistant (Google Chrome)"},
            ],
            "score_delta": -35,
            "threats": 3, "blocked": 2, "flagged": 1,
        }
    }

    sc = SCENARIOS.get(sim_type, SCENARIOS["full"])

    if "website" in sc:
        browser_threat_data["websites"].insert(0, sc["website"])
    if "websites" in sc:
        for w in reversed(sc["websites"]):
            browser_threat_data["websites"].insert(0, w)
    if "download" in sc:
        browser_threat_data["downloads"].insert(0, sc["download"])
    if "downloads" in sc:
        for d in reversed(sc["downloads"]):
            browser_threat_data["downloads"].insert(0, d)
    if "permission" in sc:
        browser_threat_data["permissions"].insert(0, sc["permission"])
    if "permissions" in sc:
        for p in reversed(sc["permissions"]):
            browser_threat_data["permissions"].insert(0, p)
    if "redirect" in sc:
        browser_threat_data["redirects"].insert(0, sc["redirect"])
    if "redirects" in sc:
        for r in reversed(sc["redirects"]):
            browser_threat_data["redirects"].insert(0, r)

    for tl in reversed(sc.get("timeline", [])):
        browser_threat_data["timeline"].insert(0, tl)
    browser_threat_data["timeline"] = browser_threat_data["timeline"][:40]

    browser_threat_data["threats_detected"] += sc.get("threats", 0)
    browser_threat_data["blocked_sites"]    += sc.get("blocked", 0)
    browser_threat_data["downloads_flagged"]+= sc.get("flagged", 0)
    browser_threat_data["security_score"]    = max(0, browser_threat_data["security_score"] + sc.get("score_delta", 0))

    save_browser_data()
    return jsonify({"status": "simulated", "type": sim_type, "data": browser_threat_data})

@app.route("/api/browser_reset", methods=["POST"])
def api_browser_reset():
    global browser_threat_data
    browser_threat_data = {
        "websites": [], "downloads": [], "permissions": [],
        "redirects": [], "timeline": [],
        "active_browsers": _get_running_browsers(),
        "threats_detected": 0, "blocked_sites": 0,
        "downloads_flagged": 0, "security_score": 100,
    }
    save_browser_data()
    return jsonify({"status": "reset"})

@app.route("/api/browser_download_ext", methods=["POST"])
def api_browser_download_ext():
    data = request.json or {}
    filename  = data.get("file", "unknown")
    status    = data.get("status", "Allowed")
    reason    = data.get("reason", "")
    now = time.strftime("%H:%M:%S")

    entry = {
        "file":   filename,
        "size":   data.get("size", "1.0 KB"),
        "status": status,
        "reason": reason if reason else "Clean file signature",
        "time":   now,
    }
    browser_threat_data["downloads"].insert(0, entry)
    browser_threat_data["downloads"] = browser_threat_data["downloads"][:50]

    if status in ("Blocked", "Suspicious"):
        browser_threat_data["downloads_flagged"] = browser_threat_data.get("downloads_flagged", 0) + 1
        if status == "Blocked":
            browser_threat_data["threats_detected"] = browser_threat_data.get("threats_detected", 0) + 1
            browser_threat_data["security_score"]   = max(0, browser_threat_data.get("security_score", 100) - 5)

    icon = "🔴" if status == "Blocked" else "🟡" if status == "Suspicious" else "🟢"
    browser_threat_data["timeline"].insert(0, {
        "time":   now,
        "event":  f"{icon} Download: {filename}",
        "detail": reason,
    })
    browser_threat_data["timeline"] = browser_threat_data["timeline"][:40]

    save_browser_data()
    return jsonify({"status": "logged"})

# ── THREAT VERIFICATION CENTER (Dynamic Version)
# ════════════════════════════════════════════════════════════════

_tvc_state = {
    "status": "awaiting",
    "confidence": 0,
    "risk_level": "LOW",
    "detection_time": None,
    "incident_id": None,
    "verification_history": [],
    "monitoring_active": False,
    "monitoring_duration": 10,
    "verification_time": None,
}


def _generate_incident_id():
    import random
    return f"INC-{time.strftime('%Y')}-{str(random.randint(1, 999)).zfill(3)}"


def _tvc_compute_signals():
    """
    Compute all security signals from live data.
    Returns a dict of signal_name -> bool.
    """
    signals = {}

    # Signal 1: Suspicious website visited
    suspicious_sites = [
        s for s in browser_threat_data.get("websites", [])
        if s.get("status") in ("High Risk", "Suspicious")
    ]
    signals["suspicious_website"] = len(suspicious_sites) > 0

    # Signal 2: Unknown executable running
    with data_lock:
        running   = list(latest_data["running"])
        suspicious = list(latest_data["suspicious"])
        high_risk  = list(latest_data["high_risk"])

    known_safe = {
        "chrome.exe", "msedge.exe", "explorer.exe", "code.exe",
        "python.exe", "notepad.exe", "taskmgr.exe", "svchost.exe",
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "dwm.exe",
        "spoolsv.exe", "searchindexer.exe", "audiodg.exe",
    }
    all_flagged_names = {o.get("app", "").lower() for o in suspicious + high_risk}
    unknown_exes = [
        a for a in running
        if a.lower() not in known_safe
        and a.lower() not in all_flagged_names
        and a.lower().endswith(".exe")
    ]
    signals["unknown_executable"] = len(unknown_exes) > 0

    # Signal 3: PowerShell detected
    ps_in_running = any(
        "powershell" in a.lower() or "pwsh" in a.lower()
        for a in running
    )
    ps_in_flagged = any(
        "powershell" in (o.get("app", "") or "").lower()
        for o in suspicious + high_risk
    )
    signals["powershell_detected"] = ps_in_running or ps_in_flagged

    # Signal 4: Registry modification (inferred from kill-chain Persistence/Defense Evasion)
    with _kill_chain_lock:
        kc_events = list(_kill_chain_events)

    registry_tactics = {"Persistence", "Defense Evasion"}
    registry_from_kc = any(e.get("tactic", "") in registry_tactics for e in kc_events)
    registry_from_bv = any(
        "registry" in (b.get("violation", "") or "").lower()
        for b in behavior_alerts[-20:]
    )
    signals["registry_modification"] = registry_from_kc or registry_from_bv

    # Signal 5: High-risk application detected
    signals["high_risk_app"] = len(high_risk) > 0

    # Signal 6: Suspicious application detected
    signals["suspicious_app"] = len(suspicious) > 0

    # Signal 7: Kill-chain event detected
    signals["killchain_event"] = len(kc_events) > 0

    return signals, kc_events, high_risk, suspicious, running


def _tvc_compute_confidence(signals):
    """
    Calculate confidence score from weighted signals.
    Weights:
      suspicious_website   +15
      unknown_executable   +20
      powershell_detected  +20
      registry_modification+20
      high_risk_app        +15
      suspicious_app       +10
      killchain_event      +10
    Clamped to 0-99.
    """
    weights = {
        "suspicious_website":    15,
        "unknown_executable":    20,
        "powershell_detected":   20,
        "registry_modification": 20,
        "high_risk_app":         15,
        "suspicious_app":        10,
        "killchain_event":       10,
    }
    score = sum(weights[k] for k, v in signals.items() if v)
    return max(0, min(99, score))


def _tvc_risk_level(confidence):
    if confidence >= 86:
        return "CRITICAL"
    elif confidence >= 61:
        return "HIGH"
    elif confidence >= 31:
        return "MEDIUM"
    else:
        return "LOW"


def _tvc_generate_assessment(signals, confidence, risk_level,
                              high_risk, suspicious, kc_events):
    """
    Generate a dynamic, context-aware assessment paragraph.
    Logic is ordered from most-specific (multiple signals) to least (single signal).
    """
    active = [k for k, v in signals.items() if v]
    count  = len(active)

    # No signals at all
    if count == 0:
        return (
            "Guardian is monitoring your session. "
            "No unusual activity has been detected at this time. "
            "All running processes appear within normal behavioural ranges."
        )

    # CRITICAL: most dangerous combination
    if (signals.get("registry_modification")
            and signals.get("unknown_executable")
            and signals.get("powershell_detected")):
        return (
            "Guardian detected behaviour consistent with a possible system compromise. "
            "An unknown executable launched a PowerShell session and registry modifications "
            "were observed — a pattern commonly associated with malware persistence or "
            "privilege escalation. Immediate verification is recommended."
        )

    # Multiple correlated attack signals
    if (signals.get("high_risk_app")
            and signals.get("killchain_event")
            and signals.get("registry_modification")):
        active_tactics = list({e.get("tactic", "") for e in kc_events if e.get("tactic")})
        tactics_str = ", ".join(active_tactics[:3]) if active_tactics else "multiple stages"
        return (
            f"Guardian observed several correlated security events that significantly increase "
            f"the likelihood of unauthorized activity. A high-risk application is active, "
            f"kill-chain events span {tactics_str}, and registry modifications were detected. "
            f"This combination requires immediate attention."
        )

    # Browser + suspicious/high-risk processes together
    if (signals.get("suspicious_website")
            and (signals.get("suspicious_app") or signals.get("high_risk_app"))):
        top_app = (high_risk + suspicious)[0].get("app", "?") if (high_risk + suspicious) else "?"
        return (
            f"Guardian detected multiple suspicious activities that differ from normal system "
            f"behaviour. A potentially malicious website was visited around the same time "
            f"{top_app} became active. This correlation increases the likelihood of an "
            f"unauthorised action. Immediate verification is recommended."
        )

    # High-risk app with kill-chain
    if signals.get("high_risk_app") and signals.get("killchain_event"):
        top_app = high_risk[0].get("app", "?") if high_risk else "?"
        reasons = high_risk[0].get("reasons", []) if high_risk else []
        reason_str = reasons[0] if reasons else "suspicious behaviour"
        return (
            f"Guardian detected {top_app} as a high-risk application with active kill-chain "
            f"events recorded. Primary reason: {reason_str}. "
            f"The combination of a flagged process and MITRE ATT&CK stage activity "
            f"suggests a potential active intrusion attempt."
        )

    # PowerShell + unknown executable (no registry)
    if signals.get("powershell_detected") and signals.get("unknown_executable"):
        return (
            "Guardian detected an unknown executable that spawned or is associated with "
            "a PowerShell process. This behaviour is frequently used in malware delivery "
            "and command-and-control operations. Please verify whether this activity "
            "was initiated by you."
        )

    # Registry modification alone or with PowerShell
    if signals.get("registry_modification"):
        return (
            "Guardian detected signs of registry modification activity. "
            "Registry changes made by unknown processes are a common indicator "
            "of persistence mechanisms or malware installation. "
            "Please confirm whether any software was recently installed or updated."
        )

    # Only browser threat
    if (active == ["suspicious_website"]
            or active == ["suspicious_website", "killchain_event"]):
        sites = browser_threat_data.get("websites", [])
        risky = [s for s in sites if s.get("status") == "High Risk"]
        if risky:
            return (
                f"Guardian observed a visit to a high-risk website "
                f"({risky[0].get('url', 'unknown domain')}). "
                f"This type of browsing activity is associated with phishing, "
                f"malware delivery, or credential theft. "
                f"Please confirm whether this visit was intentional."
            )
        return (
            "Guardian observed unusual browsing activity requiring verification. "
            "One or more visited websites matched patterns associated with malicious "
            "domains. Please confirm whether this activity was expected."
        )

    # Only suspicious app (no high-risk)
    if signals.get("suspicious_app") and not signals.get("high_risk_app"):
        top_app = suspicious[0].get("app", "?") if suspicious else "?"
        return (
            f"Guardian is monitoring {top_app}, which is showing behaviour that "
            f"deviates from its normal baseline. No confirmed compromise yet, but "
            f"the activity pattern warrants your verification."
        )

    # Only high-risk app
    if signals.get("high_risk_app"):
        top_app = high_risk[0].get("app", "?") if high_risk else "?"
        sev = high_risk[0].get("severity", 0) if high_risk else 0
        return (
            f"Guardian flagged {top_app} as high-risk with a severity of {sev}%. "
            f"This application is behaving in a way that is inconsistent with "
            f"legitimate software activity. Please verify whether you launched this process."
        )

    # Only kill-chain event
    if signals.get("killchain_event"):
        active_tactics = list({e.get("tactic", "") for e in kc_events if e.get("tactic")})
        return (
            f"Guardian recorded kill-chain events across "
            f"{len(active_tactics)} MITRE ATT&CK stage(s): "
            f"{', '.join(active_tactics[:3])}. "
            f"Please verify whether these actions were performed by you."
        )

    # Generic fallback for any other single/dual signal combo
    return (
        f"Guardian detected {count} unusual indicator(s) during this session. "
        f"Multiple factors are contributing to the current risk level. "
        f"Please review the evidence below and confirm whether this activity was expected."
    )


def _tvc_build_evidence(signals, high_risk, suspicious, kc_events):
    """
    Build a dynamic evidence list.
    Only returns items that are actually detected OR explicitly not detected.
    Never includes USB (not implemented).
    """
    evidence = []

    # Browser activity
    if signals.get("suspicious_website"):
        sites = browser_threat_data.get("websites", [])
        risky = [s for s in sites if s.get("status") in ("High Risk", "Suspicious")]
        label = f"Suspicious website visited ({risky[0].get('url', '?')})" if risky else "Suspicious website visited"
        evidence.append({"label": label, "detected": True})
    else:
        evidence.append({"label": "Suspicious website visited", "detected": False})

    # Unknown executable
    if signals.get("unknown_executable"):
        evidence.append({"label": "Unknown executable running", "detected": True})
    else:
        evidence.append({"label": "Unknown executable running", "detected": False})

    # PowerShell
    if signals.get("powershell_detected"):
        evidence.append({"label": "PowerShell process detected", "detected": True})
    else:
        evidence.append({"label": "PowerShell process detected", "detected": False})

    # Registry
    if signals.get("registry_modification"):
        evidence.append({"label": "Registry modification detected", "detected": True})
    else:
        evidence.append({"label": "Registry modification detected", "detected": False})

    # High-risk app
    if signals.get("high_risk_app"):
        top = high_risk[0].get("app", "?") if high_risk else "?"
        sev = high_risk[0].get("severity", 0) if high_risk else 0
        evidence.append({
            "label": f"High-risk application active ({top}, {sev}%)",
            "detected": True
        })
    else:
        evidence.append({"label": "High-risk application active", "detected": False})

    # Kill-chain
    if signals.get("killchain_event"):
        active_tactics = list({e.get("tactic", "") for e in kc_events if e.get("tactic")})
        label = f"Kill-chain events detected ({len(kc_events)} events, {len(active_tactics)} stages)"
        evidence.append({"label": label, "detected": True})
    else:
        evidence.append({"label": "Kill-chain events detected", "detected": False})

    # Peripheral Hardware Insertion
    if sentinel_engine and sentinel_engine.device_sentinel:
        pending_list = list(sentinel_engine.device_sentinel.pending_devices.values())
        if pending_list:
            top_p = pending_list[-1]
            evidence.append({
                "label": f"Hardware Peripheral Connected ({top_p.get('device_name', 'External Device')})",
                "detected": True
            })
        else:
            evidence.append({"label": "Unauthorized Hardware Peripheral", "detected": False})

    return evidence


@app.route("/api/tvc/state", methods=["GET"])
def api_tvc_state():
    global _tvc_state

    # Initialise detection time and incident ID on first call
    if not _tvc_state["detection_time"]:
        _tvc_state["detection_time"] = time.strftime("%H:%M:%S")
    if not _tvc_state["incident_id"]:
        _tvc_state["incident_id"] = _generate_incident_id()

    # Compute everything fresh from live data
    signals, kc_events, high_risk, suspicious, running = _tvc_compute_signals()
    confidence  = _tvc_compute_confidence(signals)
    risk_level  = _tvc_risk_level(confidence)
    assessment  = _tvc_generate_assessment(
        signals, confidence, risk_level, high_risk, suspicious, kc_events
    )
    evidence    = _tvc_build_evidence(signals, high_risk, suspicious, kc_events)

    # Persist computed values so verify endpoint can read them
    _tvc_state["confidence"]  = confidence
    _tvc_state["risk_level"]  = risk_level

    return jsonify({
        **_tvc_state,
        "confidence":        confidence,
        "risk_level":        risk_level,
        "assessment":        assessment,
        "evidence":          evidence,
        "signals":           signals,
        "high_risk_count":   len(high_risk),
        "suspicious_count":  len(suspicious),
        "kc_events":         len(kc_events),
    })


@app.route("/api/tvc/verify", methods=["POST"])
def api_tvc_verify():
    global _tvc_state
    data   = request.json or {}
    action = data.get("action", "")
    now    = time.strftime("%H:%M:%S")

    history_entry = {
        "time":   now,
        "action": action,
        "icon":   "✔" if action == "verified" else "⚠" if action == "monitoring" else "🚨",
    }
    _tvc_state["verification_history"].insert(0, history_entry)
    _tvc_state["verification_history"] = _tvc_state["verification_history"][:10]

    if action == "verified":
        _tvc_state["status"]             = "verified"
        _tvc_state["verification_time"]  = now
        _tvc_state["monitoring_active"]  = False
        try:
            requests.post(
                "http://127.0.0.1:5000/critical_escalation",
                json={"_reset": True}, timeout=1
            )
        except Exception:
            pass

    elif action == "monitoring":
        _tvc_state["status"]            = "monitoring"
        _tvc_state["monitoring_active"] = True

    elif action == "incident":
        _tvc_state["status"]            = "incident"
        _tvc_state["monitoring_active"] = False

    return jsonify({"status": "ok", "state": _tvc_state})


@app.route("/api/tvc/response", methods=["POST"])
def api_tvc_response():
    data    = request.json or {}
    actions = data.get("actions", [])
    results = []
    now     = time.strftime("%H:%M:%S")

    for action in actions:
        if action == "save_browser":
            count = len(browser_threat_data.get("websites", []))
            results.append({"action": action, "status": "saved", "count": count})

        elif action == "save_processes":
            with data_lock:
                running    = list(latest_data["running"])
                suspicious = list(latest_data["suspicious"])
                high_risk  = list(latest_data["high_risk"])
            results.append({
                "action":  action,
                "status":  "saved",
                "count":   len(running),
                "flagged": len(suspicious) + len(high_risk),
            })

        elif action == "generate_report":
            results.append({
                "action": action,
                "status": "generating",
                "url":    "/download_pdf_report",
            })

        elif action == "lock_device":
            locked = []
            with data_lock:
                all_flagged = (list(latest_data["suspicious"])
                               + list(latest_data["high_risk"]))
            for obj in all_flagged:
                app_name = obj.get("app", "")
                if app_name:
                    al = app_name.lower()
                    BLOCKED_APPS.add(al)
                    TEMP_KILLED.add(al)
                    locked.append(app_name)
            save_blocked()
            results.append({"action": action, "status": "locked", "apps": locked})

    _add_timeline_event(
        "TVC_RESPONSE",
        f"Incident response executed: {len(actions)} actions",
        80
    )
    return jsonify({"status": "ok", "results": results, "time": now})


@app.route("/api/tvc/reset", methods=["POST"])
def api_tvc_reset():
    global _tvc_state
    _tvc_state = {
        "status":               "awaiting",
        "confidence":           0,
        "risk_level":           "LOW",
        "detection_time":       time.strftime("%H:%M:%S"),
        "incident_id":          _generate_incident_id(),
        "verification_history": [],
        "monitoring_active":    False,
        "monitoring_duration":  10,
        "verification_time":    None,
    }
    return jsonify({"status": "reset"})


# ════════════════════════════════════════════════════════════════
# ── CSV & REPORT EXPORT API ROUTES (SAVED DIRECTLY TO DOWNLOADS) ──
# ════════════════════════════════════════════════════════════════

@app.route("/api/export_killchain_csv", methods=["GET", "POST"])
def api_export_killchain_csv():
    import csv
    import io
    from datetime import datetime

    events = None
    if request.method == "POST":
        req_data = request.get_json(silent=True) or {}
        events = req_data.get("events")
    if events is None:
        with _kill_chain_lock:
            events = list(_kill_chain_events)

    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
    formatted_date = now_dt.strftime("%d %b %Y, %H:%M:%S")
    filename = f"Guardian_MITRE_KillChain_{timestamp_str}.csv"

    downloads_dir = _get_downloads_dir()
    file_path = os.path.join(downloads_dir, filename)

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # Header and Summary Metadata
    writer.writerow(["GUARDIAN SECURITY PLATFORM - MITRE ATT&CK KILL CHAIN EXPORT REPORT"])
    writer.writerow(["Generated At", formatted_date])
    writer.writerow(["Total Events Recorded", len(events)])
    active_tactics = list({e.get("tactic", "Unknown") for e in events if e.get("tactic")})
    writer.writerow(["Active Tactics Detected", len(active_tactics), ", ".join(active_tactics) if active_tactics else "None"])
    writer.writerow([])  # blank row

    # Main Tabular Headers
    writer.writerow([
        "Event ID",
        "Timestamp",
        "App / Process Name",
        "Action Taken",
        "MITRE ATT&CK Tactic",
        "MITRE Technique ID",
        "Severity (%)",
        "Telemetry Source",
        "Behavioral Reasons / Triggers"
    ])

    if events:
        for idx, ev in enumerate(events, start=1):
            reasons = ev.get("reasons", [])
            if isinstance(reasons, list):
                reasons_str = "; ".join(str(r) for r in reasons)
            else:
                reasons_str = str(reasons)
            
            sev = ev.get("severity", 0)
            if isinstance(sev, (int, float)):
                sev_str = f"{int(sev)}%"
            else:
                sev_str = str(sev)

            writer.writerow([
                ev.get("id", idx),
                ev.get("time", "--"),
                ev.get("app", "unknown.exe"),
                str(ev.get("action", "ignored")).upper(),
                ev.get("tactic", "Execution"),
                ev.get("technique", "T1204"),
                sev_str,
                ev.get("source", "Telemetry Engine"),
                reasons_str or "Anomalous process pattern observed"
            ])
    else:
        writer.writerow([
            "1",
            now_dt.strftime("%H:%M:%S"),
            "System Monitor (Baseline)",
            "MONITORING",
            "Initial Reconnaissance",
            "T1057",
            "0%",
            "Guardian Core",
            "No active kill chain attacks currently active - System stable"
        ])

    csv_content = output.getvalue()

    # Save to user's Windows Downloads directory with utf-8-sig (Excel compatibility)
    try:
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            f.write(csv_content)
    except Exception as e:
        print(f"[Export Error] Failed to write file to {file_path}: {e}")

    # If requested as direct download / GET request
    if request.args.get("download") == "true" or request.method == "GET":
        mem = io.BytesIO()
        mem.write(csv_content.encode("utf-8-sig"))
        mem.seek(0)
        return send_file(
            mem,
            as_attachment=True,
            download_name=filename,
            mimetype="text/csv"
        )

    return jsonify({
        "status": "ok",
        "filename": filename,
        "path": file_path,
        "count": len(events),
        "message": f"Kill chain report saved to Downloads: {filename}",
        "csv_content": csv_content
    })


@app.route("/api/export_browser_csv", methods=["GET", "POST"])
def api_export_browser_csv():
    import csv
    import io
    from datetime import datetime

    data = None
    if request.method == "POST":
        req_data = request.get_json(silent=True) or {}
        data = req_data.get("data")
    if not data:
        data = dict(browser_threat_data)
        data["downloads"] = _scan_realtime_downloads()
        data["permissions"] = _scan_realtime_permissions()
        data["active_browsers"] = _get_running_browsers()

    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
    formatted_date = now_dt.strftime("%d %b %Y, %H:%M:%S")
    filename = f"Guardian_Browser_Threat_Intel_{timestamp_str}.csv"

    downloads_dir = _get_downloads_dir()
    file_path = os.path.join(downloads_dir, filename)

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # Header & Overview
    writer.writerow(["GUARDIAN BROWSER THREAT INTELLIGENCE REPORT"])
    writer.writerow(["Generated At", formatted_date])
    writer.writerow(["Security Score", f"{data.get('security_score', 100)} / 100"])
    writer.writerow(["Threats Detected", data.get("threats_detected", 0)])
    writer.writerow(["Blocked Sites", data.get("blocked_sites", 0)])
    writer.writerow(["Downloads Flagged", data.get("downloads_flagged", 0)])
    browsers = data.get("active_browsers", [])
    writer.writerow(["Active Browsers", ", ".join(browsers) if browsers else "None active"])
    writer.writerow([])

    # 1. Web Activity
    writer.writerow(["--- SECTION 1: WEB ACTIVITY LOGS ---"])
    writer.writerow(["Timestamp", "Website URL", "Browser", "Security Status", "Risk Level (%)", "Detection Reason"])
    websites = data.get("websites", [])
    if websites:
        for w in websites:
            writer.writerow([
                w.get("time", "--"),
                w.get("url", "--"),
                w.get("browser", "Google Chrome"),
                w.get("status", "Safe"),
                f"{w.get('risk', 0)}%",
                w.get("reason", "Standard web traffic")
            ])
    else:
        writer.writerow(["--", "No websites visited yet", "None", "Safe", "0%", "Clean session baseline"])
    writer.writerow([])

    # 2. Downloads
    writer.writerow(["--- SECTION 2: FILE DOWNLOAD MONITORING ---"])
    writer.writerow(["Timestamp", "File Name", "File Size", "Security Status", "Risk Reason", "Risk Level (%)"])
    downloads = data.get("downloads", [])
    if downloads:
        for dl in downloads:
            writer.writerow([
                dl.get("time", "--"),
                dl.get("file", "--"),
                dl.get("size", "--"),
                dl.get("status", "Allowed"),
                dl.get("reason", "Verified download signature"),
                f"{dl.get('risk', 0)}%" if dl.get('risk') is not None else "--"
            ])
    else:
        writer.writerow(["--", "No session downloads detected", "--", "Allowed", "Clean download queue", "0%"])
    writer.writerow([])

    # 3. Hardware & App Permissions
    writer.writerow(["--- SECTION 3: APP & HARDWARE PERMISSIONS ---"])
    writer.writerow(["Timestamp", "Application / Origin Site", "Requested Permission", "Access Status"])
    permissions = data.get("permissions", [])
    if permissions:
        for p in permissions:
            writer.writerow([
                p.get("time", "Active"),
                p.get("site", "--"),
                p.get("request", "--"),
                p.get("status", "Allowed")
            ])
    else:
        writer.writerow(["--", "System Sandbox", "No hardware access requests", "Allowed"])
    writer.writerow([])

    # 4. Redirect Chains
    writer.writerow(["--- SECTION 4: REDIRECT CHAINS ---"])
    writer.writerow(["Timestamp", "Redirect Chain", "Status", "Analysis Reason"])
    redirects = data.get("redirects", [])
    if redirects:
        for r in redirects:
            chain_str = " -> ".join(r.get("chain", []))
            writer.writerow([
                r.get("time", "--"),
                chain_str,
                r.get("status", "Safe"),
                r.get("reason", "--")
            ])
    else:
        writer.writerow(["--", "No cross-domain redirect chains detected", "Safe", "Direct navigation"])
    writer.writerow([])

    # 5. Threat Timeline
    writer.writerow(["--- SECTION 5: THREAT TIMELINE LOGS ---"])
    writer.writerow(["Timestamp", "Threat Event", "Telemetry Details"])
    timeline = data.get("timeline", [])
    if timeline:
        for t in timeline:
            writer.writerow([
                t.get("time", "--"),
                t.get("event", "--"),
                t.get("detail", "--")
            ])
    else:
        writer.writerow(["--", "Monitoring active", "No security threats recorded"])

    csv_content = output.getvalue()

    # Save to user's Windows Downloads directory with utf-8-sig
    try:
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            f.write(csv_content)
    except Exception as e:
        print(f"[Export Error] Failed to write file to {file_path}: {e}")

    if request.args.get("download") == "true" or request.method == "GET":
        mem = io.BytesIO()
        mem.write(csv_content.encode("utf-8-sig"))
        mem.seek(0)
        return send_file(
            mem,
            as_attachment=True,
            download_name=filename,
            mimetype="text/csv"
        )

    return jsonify({
        "status": "ok",
        "filename": filename,
        "path": file_path,
        "message": f"Browser threat intelligence saved to Downloads: {filename}",
        "csv_content": csv_content
    })


@app.route("/api/export_alerts_csv", methods=["GET", "POST"])
def api_export_alerts_csv():
    import csv
    import io
    from datetime import datetime

    queue = []
    if request.method == "POST":
        req_data = request.get_json(silent=True) or {}
        queue = req_data.get("queue", [])

    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
    formatted_date = now_dt.strftime("%d %b %Y, %H:%M:%S")
    filename = f"Guardian_Security_Alerts_{timestamp_str}.csv"

    downloads_dir = _get_downloads_dir()
    file_path = os.path.join(downloads_dir, filename)

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # Header
    writer.writerow(["GUARDIAN SECURITY PLATFORM - LIVE ALERTS LOG"])
    writer.writerow(["Generated At", formatted_date])
    writer.writerow(["Total Alerts Logged", len(queue)])
    writer.writerow([])

    writer.writerow(["Alert ID", "Timestamp", "Message / Description", "Priority Level", "Analyst Action Taken", "Status"])

    if queue:
        for idx, q in enumerate(queue, start=1):
            writer.writerow([
                idx,
                now_dt.strftime("%H:%M:%S"),
                q.get("msg", "--"),
                q.get("pri", "MEDIUM"),
                q.get("act", "PROCESSED"),
                "RESOLVED" if q.get("act") in ("TAKEN", "KILLED", "BLOCKED") else "LOGGED"
            ])
    else:
        writer.writerow(["1", now_dt.strftime("%H:%M:%S"), "Real-time alert monitoring queue baseline", "LOW", "MONITORING", "STABLE"])

    csv_content = output.getvalue()

    try:
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            f.write(csv_content)
    except Exception as e:
        print(f"[Export Error] Failed to write file to {file_path}: {e}")

    if request.args.get("download") == "true" or request.method == "GET":
        mem = io.BytesIO()
        mem.write(csv_content.encode("utf-8-sig"))
        mem.seek(0)
        return send_file(
            mem,
            as_attachment=True,
            download_name=filename,
            mimetype="text/csv"
        )

    return jsonify({
        "status": "ok",
        "filename": filename,
        "path": file_path,
        "message": f"Alerts report saved to Downloads: {filename}",
        "csv_content": csv_content
    })


@app.route("/api/export_chat_text", methods=["POST"])
def api_export_chat_text():
    from datetime import datetime
    req_data = request.get_json(silent=True) or {}
    text_content = req_data.get("text", "")
    
    now_dt = datetime.now()
    timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
    filename = f"Guardian_Chat_Transcript_{timestamp_str}.txt"

    downloads_dir = _get_downloads_dir()
    file_path = os.path.join(downloads_dir, filename)

    try:
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(text_content)
    except Exception as e:
        print(f"[Export Error] Failed to write chat text to {file_path}: {e}")

    return jsonify({
        "status": "ok",
        "filename": filename,
        "path": file_path,
        "message": f"Chat transcript saved to Downloads: {filename}"
    })


@app.route("/api/open_downloads_folder", methods=["POST"])
def api_open_downloads_folder():
    downloads_dir = _get_downloads_dir()
    try:
        if sys.platform == "win32":
            os.startfile(downloads_dir)
        else:
            import subprocess
            subprocess.Popen(["xdg-open", downloads_dir])
        return jsonify({"status": "ok", "path": downloads_dir})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/export_chat_pdf", methods=["GET", "POST"])
def api_export_chat_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable, KeepTogether, Image as RLImage)
    from reportlab.pdfgen import canvas
    import io
    import hashlib

    # Extract messages and context from request
    messages = []
    context = {}
    if request.method == "POST":
        try:
            req_data = request.get_json(silent=True) or {}
            messages = req_data.get("messages", [])
            context = req_data.get("context", {})
        except Exception:
            messages = []
            context = {}

    # Default fallback if no messages passed
    if not messages:
        t_now = time.strftime("%H:%M:%S")
        messages = [
            {
                "sender": "GUARDIAN CHATBOT",
                "time": t_now,
                "text": "Good evening. Security monitoring has started.\n\nEnvironment Summary:\n• Threat Level: CRITICAL 🔴\n• Kill Chain Stages Active: 2\n• Attention Assessment: Elevated Fatigue Detected"
            },
            {
                "sender": "Analyst",
                "time": t_now,
                "text": "What is happening right now with high-risk processes?"
            },
            {
                "sender": "GUARDIAN CHATBOT",
                "time": t_now,
                "text": "Guardian detected anomalous background spikes in thread counts and outbound socket attempts. Active Kill Chain events (Persistence & Defense Evasion) were flagged. Immediate process isolation and memory capture are recommended."
            }
        ]

    # Cross-platform font selection
    def _font(bold=False, italic=False):
        if bold and italic:
            return 'Helvetica-BoldOblique'
        elif bold:
            return 'Helvetica-Bold'
        elif italic:
            return 'Helvetica-Oblique'
        return 'Helvetica'

    # Numbered Canvas for running headers & footers
    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.setTitle("Guardian Incident Report")
                self.setAuthor("Guardian Security Platform")
                self.setSubject("Security Incident & Consultation Audit Report")
                self.draw_page_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_page_decorations(self, page_count):
            self.saveState()
            self.setFont('Helvetica', 8)
            self.setFillColor(colors.HexColor('#64748B'))
            
            # Running Footer
            self.drawString(1.6 * cm, 1.0 * cm, 'GUARDIAN — CONFIDENTIAL INCIDENT & CONSULTATION REPORT')
            page_str = f'Page {self._pageNumber} of {page_count}'
            self.drawRightString(A4[0] - 1.6 * cm, 1.0 * cm, page_str)
            
            # Footer divider line
            self.setStrokeColor(colors.HexColor('#CBD5E1'))
            self.setLineWidth(0.5)
            self.line(1.6 * cm, 1.3 * cm, A4[0] - 1.6 * cm, 1.3 * cm)
            
            # Running Top Header on pages 2+
            if self._pageNumber > 1:
                self.drawString(1.6 * cm, A4[1] - 1.0 * cm, 'GUARDIAN — INCIDENT CONSULTATION & SPECIALIST REPORT')
                self.drawRightString(A4[0] - 1.6 * cm, A4[1] - 1.0 * cm, 'TLP:AMBER // ESCALATION')
                self.setStrokeColor(colors.HexColor('#CBD5E1'))
                self.setLineWidth(0.5)
                self.line(1.6 * cm, A4[1] - 1.15 * cm, A4[0] - 1.6 * cm, A4[1] - 1.15 * cm)
                
            self.restoreState()

    W, H = A4
    MARGIN = 1.6 * cm

    # Colors
    C_BANNER = colors.HexColor('#0B0F19')
    C_ACCENT = colors.HexColor('#4F46E5')
    C_CYAN   = colors.HexColor('#0284C7')
    C_PURPLE = colors.HexColor('#7C3AED')
    C_DARK   = colors.HexColor('#0F172A')
    C_GREY   = colors.HexColor('#64748B')
    C_LIGHT  = colors.HexColor('#F1F5F9')
    C_WHITE  = colors.white
    C_RED    = colors.HexColor('#DC2626')
    C_GREEN  = colors.HexColor('#16A34A')
    C_AMBER  = colors.HexColor('#D97706')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=MARGIN, bottomMargin=1.8*cm,
                            title="Guardian Incident Report",
                            author="Guardian Security Platform",
                            subject="Security Incident & Consultation Audit Report")
    story = []

    def _P(txt, style):
        safe_txt = (str(txt)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("&lt;br&gt;", "<br/>")
                    .replace("&lt;br/&gt;", "<br/>")
                    .replace("&lt;b&gt;", "<b>")
                    .replace("&lt;/b&gt;", "</b>")
                    .replace("&lt;i&gt;", "<i>")
                    .replace("&lt;/i&gt;", "</i>")
                    .replace("&lt;u&gt;", "<u>")
                    .replace("&lt;/u&gt;", "</u>")
                    .replace("\n", "<br/>"))
        return Paragraph(safe_txt, style)

    # Styles
    s_title = ParagraphStyle('hdr_t', fontName=_font(bold=True), fontSize=13.5, leading=17, textColor=C_WHITE)
    s_subtitle = ParagraphStyle('hdr_s', fontName=_font(), fontSize=8.5, leading=12, textColor=colors.HexColor('#94A3B8'))
    s_sec = ParagraphStyle('sec', fontName=_font(bold=True), fontSize=10.5, leading=14, textColor=C_ACCENT, spaceBefore=8, spaceAfter=4)
    s_body = ParagraphStyle('body', fontName=_font(), fontSize=8.5, leading=13, textColor=C_DARK)
    s_analyst_hdr = ParagraphStyle('an_h', fontName=_font(bold=True), fontSize=8.5, leading=12, textColor=C_CYAN)
    s_bot_hdr = ParagraphStyle('bot_h', fontName=_font(bold=True), fontSize=8.5, leading=12, textColor=C_PURPLE)
    s_msg_user = ParagraphStyle('m_u', fontName=_font(), fontSize=8.5, leading=13, textColor=C_DARK)
    s_msg_bot = ParagraphStyle('m_b', fontName=_font(), fontSize=8.5, leading=13, textColor=C_DARK)

    # Header with Guardian Crystal Logo
    logo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'guardian_logo.png')
    logo_img = None
    if os.path.exists(logo_file):
        try:
            logo_img = RLImage(logo_file, width=1.8*cm, height=1.8*cm)
        except Exception:
            logo_img = None

    now_str = time.strftime("%d %b %Y, %H:%M:%S")
    report_id = "GCR-" + time.strftime("%Y%m%d-%H%M%S")

    hdr_mid = [
        _P("GUARDIAN CHATBOT — SECURITY CONSULTATION & SPECIALIST REPORT", s_title),
        _P("Detailed Incident Telemetry, Forensic Chatbot Audit & Containment Plan", s_subtitle)
    ]
    hdr_right = [
        _P(f"<b>Report ID:</b> {report_id}", ParagraphStyle('hr1', fontName=_font(bold=True), fontSize=8, leading=11, textColor=C_WHITE, alignment=2)),
        _P(f"<b>Generated:</b> {now_str}", ParagraphStyle('hr2', fontName=_font(), fontSize=7.5, leading=10, textColor=colors.HexColor('#94A3B8'), alignment=2)),
        _P("<b>Classification:</b> TLP:AMBER", ParagraphStyle('hr3', fontName=_font(bold=True), fontSize=7.5, leading=10, textColor=colors.HexColor('#F87171'), alignment=2))
    ]

    left_cells = []
    if logo_img:
        left_cells.append(logo_img)
    left_cells.append(Table([[p] for p in hdr_mid], colWidths=[9.8*cm]))

    header_table = Table([[Table([left_cells], colWidths=[2.0*cm if logo_img else 0.1*cm, 9.8*cm]),
                           Table([[p] for p in hdr_right], colWidths=[5.6*cm])]],
                         colWidths=[11.8*cm, 5.8*cm])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_BANNER),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 0.25*cm))

    # Executive Incident & Consultation Briefing
    story.append(Paragraph("<b><u>EXECUTIVE INCIDENT &amp; CONSULTATION BRIEFING</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=5))

    brief_text = (
        "This official report compiles the real-time consultation session conducted with <b>GUARDIAN CHATBOT</b> "
        "alongside live telemetry, behavioral violations, and kill chain progression. "
        "It is formatted for immediate hand-off to cybersecurity specialists, incident responders, and forensic evaluators "
        "to enable rapid comprehension of the system state, threat vectors, analyst interactions, and required containment actions."
    )
    brief_table = Table([[_P(brief_text, s_body)]], colWidths=[17.6*cm])
    brief_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 0.8, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(brief_table)
    story.append(Spacer(1, 0.25*cm))

    # Threat Posture & System Telemetry Matrix
    story.append(Paragraph("<b><u>REAL-TIME THREAT &amp; SYSTEM TELEMETRY POSTURE</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=5))

    threat_txt = context.get("threat") or "CRITICAL (100)"
    fatigue_txt = context.get("fatigue") or "STABLE"
    kc_txt = context.get("kc") or "Active (2 stages)"
    apps_txt = context.get("apps") or "MONITORED"
    tot_alerts = context.get("total_alerts") or str(len(messages))
    ign_pct = context.get("ignored_pct") or "0%"
    actions_cnt = context.get("actions_taken") or "0"

    is_crit = ("CRIT" in threat_txt.upper() or "HIGH" in threat_txt.upper())
    threat_color = C_RED if is_crit else (C_AMBER if "MED" in threat_txt.upper() else C_GREEN)

    overview_rows = [
        [
            _P("<b>Threat Severity:</b>", ParagraphStyle('ok1', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(threat_txt, ParagraphStyle('ov1', fontName=_font(bold=True), fontSize=8.5, textColor=threat_color)),
            _P("<b>Analyst Attention:</b>", ParagraphStyle('ok2', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(fatigue_txt, ParagraphStyle('ov2', fontName=_font(bold=True), fontSize=8, textColor=C_DARK))
        ],
        [
            _P("<b>Kill Chain State:</b>", ParagraphStyle('ok3', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(kc_txt, ParagraphStyle('ov3', fontName=_font(bold=True), fontSize=8, textColor=C_PURPLE)),
            _P("<b>App Defense Guard:</b>", ParagraphStyle('ok4', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(apps_txt, ParagraphStyle('ov4', fontName=_font(bold=True), fontSize=8, textColor=C_CYAN))
        ],
        [
            _P("<b>Session Alerts:</b>", ParagraphStyle('ok5', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(f"{tot_alerts} total ({ign_pct} ignored)", ParagraphStyle('ov5', fontName=_font(), fontSize=8, textColor=C_DARK)),
            _P("<b>Remediation Status:</b>", ParagraphStyle('ok6', fontName=_font(bold=True), fontSize=8, textColor=C_GREY)),
            _P(f"{actions_cnt} response action(s)", ParagraphStyle('ov6', fontName=_font(), fontSize=8, textColor=C_GREEN))
        ]
    ]
    ov_table = Table(overview_rows, colWidths=[3.5*cm, 5.3*cm, 3.5*cm, 5.3*cm])
    ov_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_LIGHT),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 7),
        ('RIGHTPADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(ov_table)
    story.append(Spacer(1, 0.25*cm))

    # Priority Focus & Key Security Findings
    priority_msg = context.get("priority") or "Environment under continuous active threat monitoring. Investigate flagged behavioral deviations."
    story.append(Paragraph("<b><u>KEY SESSION FINDINGS &amp; OBSERVATIONS</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=5))

    key_points = [
        f"<b>Active Threat Directive:</b> {priority_msg}",
        "<b>Telemetry Source:</b> Real-time process heuristics, browser telemetry, memory thread profiling, and MITRE ATT&CK correlation.",
        "<b>Analyst Interaction Context:</b> Recorded prompts and security assessments are cataloged below with precise timestamps."
    ]
    rec_rows = [[_P(f"• {pt}", s_body)] for pt in key_points]
    rec_table = Table(rec_rows, colWidths=[17.6*cm])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('BOX', (0,0), (-1,-1), 0.8, colors.HexColor('#E2E8F0')),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 0.3*cm))

    # Detailed Chronological Transcript with Timestamps
    story.append(Paragraph("<b><u>CHRONOLOGICAL CONSULTATION &amp; AUDIT TRANSCRIPT</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=6))

    for idx, msg in enumerate(messages):
        sender = msg.get("sender", "Unknown")
        text = msg.get("text", "")
        t_stamp = msg.get("time") or msg.get("timestamp") or time.strftime("%H:%M:%S")
        is_user = (sender.lower() == "analyst" or sender.lower() == "user")
        
        hdr_style = s_analyst_hdr if is_user else s_bot_hdr
        hdr_title = f"👤 SECURITY ANALYST   •   [{t_stamp}]" if is_user else f"🛡️ GUARDIAN CHATBOT   •   [{t_stamp}]"
        bg_col = colors.HexColor('#F0F9FF') if is_user else colors.HexColor('#FAF5FF')
        border_col = colors.HexColor('#BAE6FD') if is_user else colors.HexColor('#E9D5FF')
        
        msg_table = Table([
            [_P(hdr_title, hdr_style)],
            [_P(text, s_msg_user if is_user else s_msg_bot)]
        ], colWidths=[17.6*cm])
        
        msg_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_col),
            ('BOX', (0,0), (-1,-1), 0.8, border_col),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(KeepTogether([msg_table, Spacer(1, 0.15*cm)]))

    story.append(Spacer(1, 0.2*cm))

    # Specialist Action Plan & Containment Matrix
    story.append(Paragraph("<b><u>RECOMMENDED SPECIALIST ACTION PLAN</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=5))

    action_items = [
        ("1. Process Isolation", "Verify flagged PIDs, terminate suspicious parent-child chains, and block unauthorized thread execution."),
        ("2. Volatile Memory Analysis", "Generate crash dump/minidump of flagged applications to preserve injected shellcode or unpack artifacts."),
        ("3. Egress Rule Enforcement", "Block active outbound sockets and double-extension payload download attempts via local firewall."),
        ("4. Persistence Removal", "Inspect registry Run/RunOnce keys, scheduled tasks, and temp directory binaries for lingering backdoors."),
        ("5. Baseline & Fatigue Reset", "Once neutralized, execute full system verification scan and reset analyst fatigue monitoring metrics.")
    ]
    action_rows = []
    for title_act, desc_act in action_items:
        action_rows.append([
            _P(f"<b>{title_act}</b>", ParagraphStyle('a_t', fontName=_font(bold=True), fontSize=8, textColor=C_DARK)),
            _P(desc_act, ParagraphStyle('a_d', fontName=_font(), fontSize=8, textColor=C_DARK))
        ])
    
    act_table = Table(action_rows, colWidths=[4.2*cm, 13.4*cm])
    act_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(KeepTogether([act_table, Spacer(1, 0.25*cm)]))

    # Audit Verification & Specialist Sign-Off
    transcript_raw = "".join([m.get("text", "") for m in messages])
    hash_stub = hashlib.sha256(transcript_raw.encode("utf-8", errors="ignore")).hexdigest()[:24].upper()

    story.append(Paragraph("<b><u>AUDIT INTEGRITY &amp; SPECIALIST SIGN-OFF</u></b>", s_sec))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=5))

    signoff_rows = [
        [
            _P(f"<b>Audit Hash (SHA-256):</b> <code>{hash_stub}</code>", ParagraphStyle('so1', fontName=_font(), fontSize=7.5, textColor=C_GREY)),
            _P("<b>Reviewing Specialist:</b> ___________________________", ParagraphStyle('so2', fontName=_font(), fontSize=7.5, textColor=C_DARK, alignment=2))
        ],
        [
            _P("<b>Determination:</b> [ ] Threat Neutralized   [ ] Escalated   [ ] Benign", ParagraphStyle('so3', fontName=_font(), fontSize=7.5, textColor=C_DARK)),
            _P("<b>Signature / Date:</b> ___________________________", ParagraphStyle('so4', fontName=_font(), fontSize=7.5, textColor=C_DARK, alignment=2))
        ]
    ]
    signoff_table = Table(signoff_rows, colWidths=[9.8*cm, 7.8*cm])
    signoff_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(KeepTogether([signoff_table]))

    # Build PDF with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buf.getvalue()
    buf.seek(0)

    filename = "Guardian_Incident_Report.pdf"
    try:
        downloads_dir = _get_downloads_dir()
        file_path = os.path.join(downloads_dir, filename)
        with open(file_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception as e:
        print(f"[Export Error] Failed to write PDF to {filename}: {e}")

    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


# -------------------------------------------------------------
# PHONE ANTI-THEFT GUARD & SENTRY SENTINEL REST ENDPOINTS
# -------------------------------------------------------------
try:
    from sentry_sentinel import sentinel_engine
    if sentinel_engine and sentinel_engine.device_sentinel:
        _orig_device_cb = sentinel_engine.device_sentinel.on_event_callback
        def _tvc_device_event_hook(evt):
            if _orig_device_cb:
                try: _orig_device_cb(evt)
                except Exception: pass
            try:
                now_str = time.strftime("%I:%M:%S %p")
                cat = evt.get("category", "usb")
                icon_map = {"power": "⚡", "usb": "🔌", "bluetooth": "🎧", "phone": "📱", "audio": "🎧"}
                icon = icon_map.get(cat, "🔌")
                name = evt.get("device_name", "Hardware Peripheral")
                ev_type = evt.get("type", "")
                
                if "unplugged" in ev_type or "removed" in ev_type or "disconnected" in ev_type:
                    action_text = f"Hardware Disconnected: {name} removed from system"
                    log_icon = "⚪"
                else:
                    action_text = f"Hardware Plugged In / Connected: {name} — Awaiting User Verification ('This is me' / 'Not me')"
                    log_icon = icon

                entry = {
                    "time": now_str,
                    "action": action_text,
                    "icon": log_icon
                }
                _tvc_state["verification_history"].insert(0, entry)
                _tvc_state["verification_history"] = _tvc_state["verification_history"][:35]
            except Exception as e:
                print(f"[TVC] Event log hook error: {e}")

        sentinel_engine.device_sentinel.on_event_callback = _tvc_device_event_hook
except Exception as e:
    print(f"[Warning] Failed to load sentry_sentinel: {e}")
    sentinel_engine = None

@app.route("/remote")
def remote_page():
    return render_template("remote.html")

@app.route("/dossier")
def dossier_page():
    if sentinel_engine:
        dossier = sentinel_engine.generate_dossier()
    else:
        dossier = {"dossier_id": "DOSSIER-OFFLINE", "threat_level": "STANDBY", "total_events": 0, "critical_events": 0, "photos": [], "events": []}
    return render_template("dossier_report.html", dossier=dossier)

@app.route("/api/sentry/state", methods=["GET"])
def sentry_get_state():
    if not sentinel_engine:
        return jsonify({"error": "Sentry engine not loaded"}), 500
    return jsonify(sentinel_engine.get_state())

@app.route("/api/sentry/qr", methods=["GET"])
def sentry_get_qr():
    if not sentinel_engine:
        return "Not available", 500
    qr_bytes = sentinel_engine.generate_qr_code()
    return send_file(io.BytesIO(qr_bytes), mimetype="image/png")

@app.route("/api/sentry/verify_pin", methods=["POST"])
def sentry_verify_pin():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    pin = data.get("pin", "")
    return jsonify({"success": sentinel_engine.verify_pin(pin)})

@app.route("/api/sentry/arm", methods=["POST"])
def sentry_arm():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    pin = data.get("pin", "")
    if request.remote_addr in ["127.0.0.1", "::1"] or sentinel_engine.verify_pin(pin):
        sentinel_engine.arm()
        return jsonify({"success": True, "state": sentinel_engine.state})
    return jsonify({"success": False, "error": "Invalid PIN"}), 403

@app.route("/api/sentry/disarm", methods=["POST"])
def sentry_disarm():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    pin = data.get("pin", "")
    if request.remote_addr in ["127.0.0.1", "::1"] or sentinel_engine.verify_pin(pin):
        sentinel_engine.disarm()
        return jsonify({"success": True, "state": sentinel_engine.state})
    return jsonify({"success": False, "error": "Invalid PIN"}), 403

@app.route("/api/sentry/action", methods=["POST"])
def sentry_action():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    action = data.get("action", "")
    pin = data.get("pin", "")
    
    is_local = request.remote_addr in ["127.0.0.1", "::1"]
    if not is_local and not sentinel_engine.verify_pin(pin):
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    if action == "lock":
        sentinel_engine.lock_workstation()
        return jsonify({"success": True, "action": "lock"})
    elif action == "sleep":
        sentinel_engine.sleep_workstation()
        return jsonify({"success": True, "action": "sleep"})
    elif action == "toggle_alarm":
        active = sentinel_engine.toggle_siren()
        return jsonify({"success": True, "siren_active": active})
    elif action == "snap_photo":
        photo_url = sentinel_engine.capture_stealth_photo()
        return jsonify({"success": True, "photo_url": photo_url})
    elif action == "kill_app":
        ok, msg = sentinel_engine.kill_active_app()
        return jsonify({"success": ok, "message": msg})
    elif action == "voice_warning":
        idx = data.get("shout_index", 1)
        sentinel_engine.play_voice_shout(idx)
        return jsonify({"success": True, "shout_index": idx})
    elif action == "toggle_lockdown":
        enable = data.get("enable", None)
        active = sentinel_engine.toggle_lockdown(enable)
        return jsonify({"success": True, "lockdown_active": active})
    elif action == "smart_boost":
        ok, msg = sentinel_engine.smart_boost()
        return jsonify({"success": ok, "message": msg})
    elif action == "clear_logs":
        sentinel_engine.clear_events()
        return jsonify({"success": True})
    elif action == "test_intruder":
        sentinel_engine.test_demo_intruder()
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Unknown action"}), 400

@app.route("/api/sentry/change_password", methods=["POST"])
def sentry_change_password():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    pin = data.get("pin", "")
    new_pass = data.get("new_password", "")
    if request.remote_addr not in ["127.0.0.1", "::1"] and not sentinel_engine.verify_pin(pin):
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    ok, msg = sentinel_engine.change_windows_password(new_pass)
    return jsonify({"success": ok, "message": msg})

@app.route("/api/sentry/speak_custom", methods=["POST"])
def sentry_speak_custom():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    pin = data.get("pin", "")
    text = data.get("text", "")
    if request.remote_addr not in ["127.0.0.1", "::1"] and not sentinel_engine.verify_pin(pin):
        return jsonify({"success": False, "error": "Unauthorized"}), 403
    sentinel_engine.speak_text(text, force_volume=True)
    return jsonify({"success": True})

@app.route("/api/sentry/intercom_audio", methods=["POST"])
def sentry_intercom_audio():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    audio_data = request.get_data()
    if not audio_data:
        return jsonify({"success": False, "error": "No audio data"}), 400
    ok = sentinel_engine.play_intercom_audio(audio_data)
    return jsonify({"success": ok})

@app.route("/api/sentry/screen_frame", methods=["GET"])
def sentry_screen_frame():
    if not sentinel_engine:
        return "Not available", 500
    frame_bytes = sentinel_engine.capture_screen_frame(quality=55)
    if not frame_bytes:
        return "Capture failed", 500
    return send_file(io.BytesIO(frame_bytes), mimetype="image/jpeg")

@app.route("/api/sentry/screen_banner", methods=["POST"])
def sentry_screen_banner():
    if not sentinel_engine:
        return jsonify({"success": False}), 500
    data = request.get_json(silent=True) or {}
    msg = data.get("message", "INTRUDER ALERT: LAPTOP IS BEING MONITORED REMOTELY")
    sentinel_engine.show_screen_banner(msg)
    return jsonify({"success": True})

@app.route("/api/sentry/dossier", methods=["GET"])
def sentry_dossier():
    if not sentinel_engine:
        return jsonify({"error": "Sentry engine not loaded"}), 500
    return jsonify(sentinel_engine.generate_dossier())


# -------------------------------------------------------------
# REAL-TIME PERIPHERAL & HARDWARE DEFENSE API (TVC & NOTIFIER)
# -------------------------------------------------------------
@app.route("/api/peripheral/latest", methods=["GET"])
def api_peripheral_latest():
    if not sentinel_engine or not sentinel_engine.device_sentinel:
        return jsonify({"has_pending": False, "pending": None, "history": []})
    
    with sentinel_engine.device_sentinel.lock:
        pending_list = list(sentinel_engine.device_sentinel.pending_devices.values())
    
    pending = pending_list[-1] if pending_list else None
    return jsonify({
        "has_pending": len(pending_list) > 0,
        "pending": pending,
        "pending_count": len(pending_list),
        "tvc_history": _tvc_state.get("verification_history", [])[:6]
    })


@app.route("/api/peripheral/action", methods=["POST"])
def api_peripheral_action():
    if not sentinel_engine or not sentinel_engine.device_sentinel:
        return jsonify({"success": False, "error": "Sentinel not ready"}), 500
    
    data = request.get_json(silent=True) or {}
    event_id = data.get("event_id", "")
    action = data.get("action", "trust")  # "trust", "block", "timeout"
    device_category = data.get("device_category", "usb")
    device_name = data.get("device_name", "External Peripheral")
    target = data.get("target", "")
    now_str = time.strftime("%I:%M:%S %p")

    # Remove from pending queue
    with sentinel_engine.device_sentinel.lock:
        if event_id in sentinel_engine.device_sentinel.pending_devices:
            del sentinel_engine.device_sentinel.pending_devices[event_id]

    photo_url = None

    if action == "trust":
        # User confirmed "This is me"
        sentinel_engine.device_sentinel.verified_devices.add(device_name)
        log_msg = f"User Confirmed Safe ('This is me'): {device_name} allowed on workstation"
        
        # Add to TVC Live Log
        history_entry = {
            "time": now_str,
            "action": log_msg,
            "icon": "🟢"
        }
        _tvc_state["verification_history"].insert(0, history_entry)
        _tvc_state["verification_history"] = _tvc_state["verification_history"][:35]

        # Add timeline event
        _add_timeline_event("PERIPHERAL_TRUSTED", f"Verified Safe ('This is me'): {device_name}", 5)

        # Log to Sentry Hawkeye event feed
        sentinel_engine.log_event(
            event_type="peripheral_trusted",
            title=f"🟢 Hardware Verified ('This is me'): {device_name}",
            details=f"User confirmed '{device_name}' as trusted device at {now_str}.",
            severity="LOW"
        )
        return jsonify({"success": True, "action": "trusted", "message": f"Device {device_name} verified safe."})

    else:
        # "This is not me" or "timeout" (Zero-Trust)
        sentinel_engine.device_sentinel.blocked_devices.add(device_name)
        
        # 1. Execute safe hardware neutralization
        if device_category == "usb" or target:
            sentinel_engine.device_sentinel.eject_drive(target)
        if device_category in ["bluetooth", "phone"]:
            sentinel_engine.device_sentinel.disable_bluetooth_device(device_name)

        # 2. Stealth webcam snapshot of intruder
        photo_url = sentinel_engine.capture_stealth_photo()

        # 3. Add to TVC Live Log
        reason_label = "Zero-Trust Timeout" if action == "timeout" else "User Rejected ('This is not me')"
        log_msg = f"Intruder Blocked ({reason_label}): {device_name} neutralized, disconnected & ejected"
        history_entry = {
            "time": now_str,
            "action": log_msg,
            "icon": "🔴"
        }
        _tvc_state["verification_history"].insert(0, history_entry)
        _tvc_state["verification_history"] = _tvc_state["verification_history"][:35]
        _tvc_state["status"] = "incident"

        # 4. Add timeline event with high threat score
        _add_timeline_event("PERIPHERAL_BLOCKED", f"Blocked unauthorized hardware: {device_name}", 90)

        # 5. Log to Sentry Hawkeye event feed with intruder photo
        sentinel_engine.log_event(
            event_type="peripheral_blocked",
            title=f"🔴 Untrusted Hardware Neutralized: {device_name}",
            details=f"Access blocked & ejected automatically upon user rejection / zero-trust timeout at {now_str}.",
            severity="CRITICAL",
            photo_url=photo_url
        )

        return jsonify({
            "success": True,
            "action": "blocked",
            "message": f"{device_name} was neutralized and ejected. Intruder photo captured.",
            "photo_url": photo_url
        })


if __name__=="__main__":
    threading.Thread(target=monitor_running_apps,daemon=True).start()
    app.run(host="0.0.0.0",debug=False,threaded=True,port=5000)