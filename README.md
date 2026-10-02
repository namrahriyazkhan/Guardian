# GUARDIAN Security Platform

![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask Service](https://img.shields.io/badge/Backend-Flask%20Microservice-000000?style=for-the-badge&logo=flask&logoColor=white)
![PyWebView](https://img.shields.io/badge/GUI-PyWebView%20Container-4B0082?style=for-the-badge)
![Cross-Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-555555?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

GUARDIAN is a high-performance, cross-platform endpoint security and application governance suite. Engineered in Python and Flask with a native desktop container runtime, GUARDIAN provides real-time process control, network-level HTTP/HTTPS traffic filtering, OS protected system guards, and automated threat mitigation.

---

## Executive Summary

GUARDIAN delivers low-overhead endpoint protection by decoupling UI rendering, local REST control APIs, asynchronous process inspection, and network proxy enforcement into isolated process runtimes. Designed to run seamlessly across Windows, macOS, and Linux environments, it provides deterministic security rule evaluation without reliance on external cloud dependencies or heavyweight browser engines.

---

## System Architecture

```
                                  +---------------------------------------+
                                  |    Native Desktop GUI Container       |
                                  |         (PyWebView Runtime)           |
                                  +---------------------------------------+
                                                      |
                                                      | Local HTTP / REST
                                                      v
                                  +---------------------------------------+
                                  |    Flask Core Security Microservice   |
                                  |              (127.0.0.1)              |
                                  +---------------------------------------+
                                     /                |                \
                                    /                 |                 \
                                   v                  v                  v
    +----------------------------------+ +-------------------------+ +----------------------------------+
    |   Process Inspection Subsystem   | |  Network Proxy Gateway  | |   Desktop Notification Worker    |
    |          (app_monitor.py)        | |    (browser_proxy.py)   | |           (notifier.py)          |
    +----------------------------------+ +-------------------------+ +----------------------------------+
                     |                                |                                |
                     v                                v                                v
         Active Process Scanning            System Proxy Routing            OS Desktop Alert Queue
         & Rule Policy Enforcement          & Traffic Filtering             (Win / macOS / Linux)
```

---

## Subsystem Deep Dive

### 1. Process Monitoring & Policy Enforcement Engine
* **Asynchronous Process Scanning**: Periodically scans active OS processes via `psutil` data structures to measure CPU and memory utilization while matching executable names against active security policy definitions (`blocked_apps.json`, `killed_apps.json`, `trusted_apps.json`).
* **Automated Threat Remediation**: Implements deterministic process termination for blacklisted binaries, instantly neutralizing policy violations.
* **Kernel & OS Core Protection**: Implements a hardcoded safety layer (`PROTECTED_SYSTEM_APPS`) guarding critical system executables (`explorer.exe`, `dwm.exe`, `svchost.exe`, `csrss.exe`, `kernel_task`, `launchd`) against accidental process termination or policy conflicts.

### 2. Network Proxy & Traffic Interception Gateway
* **Loopback Socket Proxy**: Embeds a lightweight network interceptor (`browser_proxy.py`) to monitor, inspect, and enforce domain blocklists on HTTP/HTTPS outbound traffic.
* **Native OS Network Control**: Programmatically configures OS-level proxy state using low-level operating system bindings:
  * **Windows**: Direct Windows Registry manipulation (`winreg`) and WinINet cache flushing via `ctypes` (`InternetSetOptionW`).
  * **macOS**: Native execution of system `networksetup` commands across Wi-Fi and Ethernet interfaces.
  * **Linux**: System-level GNOME `gsettings` proxy configuration.

### 3. Application Lifecycle & Process Concurrency
* **Single-Instance Lock Primitive**: Prevents duplicate daemon execution via platform-aware PID file locks (`guardian_running.lock`) located in platform-standard configuration paths (`APPDATA` on Windows, `Application Support` on macOS, `.config` on Linux).
* **Deterministic Subprocess Cleanup**: Leverages Python `atexit` signal handlers to cleanly terminate child processes and restore original system proxy settings upon exit.
* **Isolated Desktop Notifier**: Spawns an independent background worker (`notifier.py`) via `subprocess.Popen` to push OS desktop notifications without blocking core inspection loops.

---

## Technology Matrix

| Layer | Technology / Module | Engineering Purpose |
| :--- | :--- | :--- |
| **Desktop Runtime** | PyWebView / WebKit / EdgeHTML | Native window wrapper rendering localized HTML/CSS/JS frontend |
| **Control Server** | Python 3.12, Flask, Flask-CORS | Multi-threaded local REST API handling security telemetry & controls |
| **Process Inspection** | `psutil`, `subprocess`, `os` | Cross-platform process telemetry, signal emission, and rule evaluation |
| **Network Gateway** | Custom Python Socket Proxy | In-memory HTTP/HTTPS request inspection and domain blocking |
| **Platform Interop** | `winreg`, `ctypes`, `subprocess` | Direct operating system integration for network stack orchestration |
| **Build & Distribution** | PyInstaller, Inno Setup | Self-contained binary compilation (`GUARDIAN.exe`) and installer generation |

---

## Engineering Design Highlights

* **Fault-Tolerant Process Isolation**: Separating the GUI renderer, HTTP control server, threat inspection loop, and notification daemon guarantees that UI interactions never delay time-critical security enforcement.
* **Cross-Platform Abstraction**: Uses unified Python abstractions to execute platform-specific system calls (Windows Registry, macOS `networksetup`, Linux `gsettings`) seamlessly.
* **Non-Disruptive Fail-Safes**: Built-in system protection lists guarantee operating system stability, preventing accidental core process termination.
* **Zero-Dependency Binary Distribution**: Bundles all Python runtimes, C extensions, and application templates into a standalone single-file distribution via PyInstaller and Inno Setup.

---

## Repository Structure

```dir
Guardian UI/
├── GUARDIAN.py             # Application launcher, lock manager & process orchestrator
├── app.py                  # Flask REST API backend, policy engines & route handlers
├── app_monitor.py          # Asynchronous process scanner & threat remediation engine
├── browser_proxy.py        # Network proxy interceptor & domain filtering gateway
├── notifier.py             # Standalone desktop notification background process
├── build_release.py        # Automated build script executing PyInstaller & Inno Setup
├── GUARDIAN.spec           # PyInstaller build spec for standalone executable generation
├── GUARDIAN_installer.iss  # Inno Setup script for executable installer creation
├── static/                 # Static UI assets (CSS, JS, images, logos)
├── templates/              # Flask Jinja2 HTML layout views
└── build/                  # Artifact directory for compiled release binaries
```

---

## Build & Deployment Instructions

### Local Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/namrahriyazkhan/Guardian.git
   cd Guardian
   ```

2. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Execute application:**
   ```bash
   python GUARDIAN.py
   ```

### Production Build Pipeline

To compile the application into a standalone executable package and installer:

```bash
python build_release.py
```

* **Compiled Executable:** `dist/GUARDIAN.exe`
* **Production Installer:** `Output/GUARDIAN_Setup_v1.0.0.exe`

---

## License

This software is released under the **MIT License**. See the `LICENSE` file for details.
