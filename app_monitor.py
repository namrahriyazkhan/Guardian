"""
app_monitor.py — ML-based process scanner with Behavior Profiling + Context-Aware Detection
Sends data to Flask every 5 s via /update_report
"""

import psutil
import time
import requests
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import json
import os
import datetime

# ── File paths ────────────────────────────────────────────────────────────────

import tempfile
_DATA_DIR = os.path.join(tempfile.gettempdir(), "guardian_data")
os.makedirs(_DATA_DIR, exist_ok=True)

BLOCK_FILE       = os.path.join(_DATA_DIR, "blocked_apps.json")
KILLED_FILE      = os.path.join(_DATA_DIR, "killed_apps.json")
TRUST_FILE       = os.path.join(_DATA_DIR, "trusted_apps.json")
MEMORY_FILE      = os.path.join(_DATA_DIR, "app_memory.json")
PROFILE_FILE     = os.path.join(_DATA_DIR, "app_profiles.json")
FLASK_UPDATE_URL = "http://127.0.0.1:5000/update_report"

# ── Context Rules ─────────────────────────────────────────────────────────────
LOW_CONTEXT_APPS = {
    "python.exe","python3","python","code.exe","node.exe","java.exe",
    "javaw.exe","gcc.exe","g++.exe","clang.exe","make.exe","cmake.exe",
    "devenv.exe","pycharm64.exe","idea64.exe","webstorm64.exe",
    "npm.exe","webpack.js","gulp.js","cargo.exe","rustc.exe",
    "git.exe","bash.exe","wsl.exe","powershell.exe",
    "chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe",
    "duckduckgo.exe","duckduckgo.webview.exe","duckduckgobrowser.exe",
    "msedgewebview2.exe"
}

HIGH_CONTEXT_APPS = {
    "trojan.exe","malware.exe","ransomware.exe","keylogger.exe",
    "mimikatz.exe","nc.exe","ncat.exe","netcat.exe","meterpreter.exe",
    "payload.exe","cryptominer.exe","xmrig.exe","minerd.exe",
    "unknown.exe","temp.exe","tmp.exe","svchost32.exe",
    "exploit_kit.exe","rootkit.dll","spyware.exe","backdoor.exe","worm.exe",
    "weird_script.exe","psexec_copy.exe","updater_fake.exe","mimikatz_mod.exe"
}


TIME_SENSITIVE_APPS = {
    "chrome.exe":   (7, 23),
    "msedge.exe":   (7, 23),
    "firefox.exe":  (7, 23),
    "brave.exe":    (7, 23),
    "opera.exe":    (7, 23),
    "duckduckgo.exe": (7, 23),
    "duckduckgo.webview.exe": (7, 23),
    "outlook.exe":  (7, 22),
    "teams.exe":    (7, 21),
    "zoom.exe":     (7, 22),
    "slack.exe":    (7, 22),
    "explorer.exe": (6, 23),
    "winword.exe":  (7, 22),
    "excel.exe":    (7, 22),
    "powerpnt.exe": (7, 22),
}

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

# ── Safe loader helpers ───────────────────────────────────────────────────────
def load_set(file):
    if os.path.exists(file):
        try:
            with open(file) as f:
                return {a.lower() for a in json.load(f) if a.lower() not in PROTECTED_SYSTEM_APPS}
        except: pass
    return set()

def load_dict(file):
    if os.path.exists(file):
        try:
            with open(file) as f: return json.load(f)
        except: pass
    return {}

# ── Load persistent state ─────────────────────────────────────────────────────
BLOCKED_APPS = load_set(BLOCK_FILE)
KILLED_APPS  = load_set(KILLED_FILE)
TRUSTED_APPS = load_dict(TRUST_FILE)

app_memory = {}
if os.path.exists(MEMORY_FILE):
    try:
        with open(MEMORY_FILE) as f:
            content = f.read().strip()
            if content: app_memory = json.loads(content)
    except: pass

app_profiles = {}
if os.path.exists(PROFILE_FILE):
    try:
        with open(PROFILE_FILE) as f:
            content = f.read().strip()
            if content: app_profiles = json.loads(content)
    except: pass

# ── Save helpers ──────────────────────────────────────────────────────────────
def save_profiles():
    with open(PROFILE_FILE, "w") as f: json.dump(app_profiles, f, indent=2)

def save_trust():
    with open(TRUST_FILE, "w") as f: json.dump(TRUSTED_APPS, f)

MAX_SAMPLES = 100

# ── Behavior profiling ────────────────────────────────────────────────────────
def update_profile(app_name, cpu, mem, threads):
    key      = app_name.lower()
    now_hour = datetime.datetime.now().hour

    if key not in app_profiles:
        app_profiles[key] = {
            "cpu_samples":[],"mem_samples":[],"thread_samples":[],
            "active_hours":[],"seen_count":0,
        }
    p = app_profiles[key]
    p["seen_count"] += 1
    p["cpu_samples"].append(cpu)
    p["mem_samples"].append(mem)
    p["thread_samples"].append(threads)
    p["active_hours"].append(now_hour)

    for key_list in ["cpu_samples","mem_samples","thread_samples","active_hours"]:
        if len(p[key_list]) > MAX_SAMPLES:
            p[key_list] = p[key_list][-MAX_SAMPLES:]

    p["avg_cpu"]      = round(float(np.mean(p["cpu_samples"])),   2)
    p["peak_cpu"]     = round(float(np.max(p["cpu_samples"])),    2)
    p["avg_mem"]      = round(float(np.mean(p["mem_samples"])),   2)
    p["peak_mem"]     = round(float(np.max(p["mem_samples"])),    2)
    p["avg_threads"]  = round(float(np.mean(p["thread_samples"])),2)
    p["peak_threads"] = round(float(np.max(p["thread_samples"])), 2)

    if len(p["active_hours"]) >= 3:
        p["typical_hours_min"] = int(np.percentile(p["active_hours"], 10))
        p["typical_hours_max"] = int(np.percentile(p["active_hours"], 90))


def check_behavior_violation(app_name, cpu, mem, threads):
    key        = app_name.lower()
    violations = []
    if key not in app_profiles: return violations
    p = app_profiles[key]
    if p["seen_count"] < 1: return violations

    now_hour = datetime.datetime.now().hour
    avg_cpu  = p.get("avg_cpu", 0)
    avg_mem  = p.get("avg_mem", 0)
    avg_thr  = p.get("avg_threads", 0)
    t_min    = p.get("typical_hours_min", 0)
    t_max    = p.get("typical_hours_max", 23)

    if avg_cpu > 2 and cpu > avg_cpu * 3:
        violations.append(
            f"CPU spike: current {cpu:.1f}% vs avg {avg_cpu:.1f}% "
            f"(+{round((cpu/avg_cpu-1)*100)}% above normal)")

    if avg_mem > 10 and mem > avg_mem * 2.5:
        violations.append(f"Memory surge: {mem:.0f} MB vs avg {avg_mem:.0f} MB")

    if avg_thr > 2 and threads > avg_thr * 3:
        violations.append(f"Thread explosion: {threads} threads vs avg {avg_thr:.0f}")

    if t_max - t_min >= 4:
        if key in TIME_SENSITIVE_APPS:
            emin, emax = TIME_SENSITIVE_APPS[key]
            if not (emin <= now_hour <= emax):
                violations.append(
                    f"Time anomaly: active at {now_hour:02d}:xx "
                    f"(normally {emin:02d}:00–{emax:02d}:00)")
        elif not (t_min <= now_hour <= t_max):
            violations.append(
                f"Time anomaly: active at {now_hour:02d}:xx "
                f"(profile shows {t_min:02d}:00–{t_max:02d}:00)")
    return violations


def apply_context(app_name, score, reasons):
    key = app_name.lower()
    if key in LOW_CONTEXT_APPS:
        old = score; score = max(0, score - 3)
        if old != score:
            reasons = [r for r in reasons if "Anomaly" not in r]
            reasons.append(f"[Context: dev tool — severity reduced {old}→{score}]")
    if key in HIGH_CONTEXT_APPS:
        score = max(score, 8)
        reasons.append("[Context: KNOWN HIGH-RISK executable — severity forced MAX]")
    freq = app_memory.get(key, 0)
    if freq <= 3 and key not in LOW_CONTEXT_APPS and key not in HIGH_CONTEXT_APPS:
        score += 2
        reasons.append(f"[Context: rarely seen ({freq}x) — severity +2]")
    return score, reasons

# ── Feature extraction ────────────────────────────────────────────────────────
def extract_features(process):
    try:
        cpu     = process.cpu_percent(interval=0.1)
        memory  = process.memory_info().rss / (1024 * 1024)
        threads = process.num_threads()
        return [cpu, memory, threads]
    except:
        return [0, 0, 0]

# ── Train model ───────────────────────────────────────────────────────────────
def train_model():
    data = []
    for proc in psutil.process_iter():
        try: data.append(extract_features(proc))
        except: pass
    data       = np.array(data)
    scaler     = StandardScaler()
    ds         = scaler.fit_transform(data)
    model      = IsolationForest(contamination=0.1, random_state=42)
    model.fit(ds)
    mean = np.mean(data, axis=0)
    std  = np.std(data,  axis=0) + 1e-5
    return model, scaler, mean, std

print("⚙️  Training ML model...")
model, scaler, mean, std = train_model()
print("✅ Model ready!\n")

# ── Memory + Trust helpers ────────────────────────────────────────────────────
def update_memory(app):
    app_memory[app] = app_memory.get(app, 0) + 1
    with open(MEMORY_FILE, "w") as f: json.dump(app_memory, f)

def update_trust(app, severity):
    if app not in TRUSTED_APPS: TRUSTED_APPS[app] = 0
    TRUSTED_APPS[app] += (1 if severity < 30 else -1)
    TRUSTED_APPS[app]  = max(-5, min(10, TRUSTED_APPS[app]))
    save_trust()

# ── Main scan loop ────────────────────────────────────────────────────────────
_profile_save_counter = 0

while True:
    # Reload block/kill/trust from disk so Flask changes take effect
    BLOCKED_APPS = load_set(BLOCK_FILE)
    KILLED_APPS  = load_set(KILLED_FILE)
    TRUSTED_APPS = load_dict(TRUST_FILE)

    running_apps    = []
    suspicious_apps = []
    high_risk_apps  = []
    seen            = set()

    for proc in psutil.process_iter(['name']):
        try:
            app = proc.info['name']
            if not app: continue
            al  = app.lower()
            if al in PROTECTED_SYSTEM_APPS: continue
            if al in BLOCKED_APPS: continue
            if al in KILLED_APPS:  continue
            if al not in seen:
                running_apps.append((app, proc))
                seen.add(al)
        except: pass

    print(f"\n[Monitor] Running: {len(running_apps)} apps\nScanning...\n")

    for app, proc in running_apps:
        try:
            update_memory(app)
            features = extract_features(proc)
            cpu, memory, threads = features

            update_profile(app, cpu, memory, threads)

            scaled     = scaler.transform([features])
            prediction = model.predict(scaled)[0]

            reasons = []
            score   = 0

            if prediction == -1:
                reasons.append("ML anomaly detected (IsolationForest)")
                score += 2

            if cpu > mean[0] * 2:
                reasons.append(f"CPU spike ({cpu:.1f}% vs mean {mean[0]:.1f}%)")
                score += 2

            if memory > mean[1] * 2:
                reasons.append(f"High memory ({memory:.0f}MB vs mean {mean[1]:.0f}MB)")
                score += 2

            if threads > mean[2] * 2:
                reasons.append(f"Thread spike ({threads} vs mean {mean[2]:.0f})")
                score += 2

            freq = app_memory.get(app, 0)
            if freq <= 2:
                reasons.append("New / rare app (seen ≤2 times)")
                score += 1

            # Behavior profiling violations
            bv = check_behavior_violation(app, cpu, memory, threads)
            for v in bv:
                reasons.append(f"⚠ Behavior violation: {v}")
                score += 2

            # Context-aware adjustment
            score, reasons = apply_context(app, score, reasons)

            severity   = round((score / 9) * 100, 2)
            trust_val  = TRUSTED_APPS.get(app, 0)
            is_trusted = isinstance(trust_val, (int, float)) and trust_val >= 5

            update_trust(app, severity)

            if not is_trusted and score >= 2:
                suspicious_apps.append((app, reasons, severity))
            if not is_trusted and score >= 4:
                high_risk_apps.append((app, reasons, severity))

        except Exception as e:
            pass

    # Save profiles every 6 cycles (~30 s)
    _profile_save_counter += 1
    if _profile_save_counter >= 6:
        save_profiles()
        _profile_save_counter = 0

    # Build profile summary for dashboard
    profile_summary = {}
    for k, p in app_profiles.items():
        if p.get("seen_count", 0) >= 1:
            profile_summary[k] = {
                "avg_cpu":           p.get("avg_cpu",           0),
                "peak_cpu":          p.get("peak_cpu",          0),
                "avg_mem":           p.get("avg_mem",           0),
                "peak_mem":          p.get("peak_mem",          0),
                "avg_threads":       p.get("avg_threads",       0),
                "seen_count":        p.get("seen_count",        0),
                "typical_hours_min": p.get("typical_hours_min", 0),
                "typical_hours_max": p.get("typical_hours_max", 23),
            }

    # Send to Flask
    try:
        payload = {
            "running":    [a for a, _ in running_apps],
            "suspicious": [{"app":a,"reasons":r,"severity":s} for a,r,s in suspicious_apps],
            "high_risk":  [{"app":a,"reasons":r,"severity":s} for a,r,s in high_risk_apps],
            "trusted_apps":    TRUSTED_APPS,
            "profile_summary": profile_summary,
        }
        resp = requests.post(FLASK_UPDATE_URL, json=payload, timeout=3)
        print(f"[Monitor] 📡 Sent — suspicious:{len(suspicious_apps)} high:{len(high_risk_apps)}")
    except requests.exceptions.ConnectionError:
        print("[Monitor] ⚠ Flask not reachable — retrying next cycle")
    except Exception as e:
        print(f"[Monitor] Send error: {e}")

    time.sleep(5)