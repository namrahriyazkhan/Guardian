# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['GUARDIAN.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\index.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\splash.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\remote.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\dossier_report.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\chart.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\main.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\welcome_tour.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\welcome_tour.css', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\guardian_logo.ico', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\alert_beep.wav', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\freesound_community-beep-6-96243.mp3', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\templates', 'templates'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\static', 'static')],
    hiddenimports=['engineio.async_drivers.threading', 'jinja2', 'jinja2.loaders', 'flask', 'flask_cors', 'sklearn', 'sklearn.ensemble', 'sklearn.preprocessing', 'sklearn.tree', 'sklearn.neighbors', 'numpy', 'psutil', 'PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets', 'PyQt5.sip', 'webview', 'webview.platforms.winforms', 'webview.platforms.edgechromium', 'clr', 'pythonnet', 'win32gui', 'win32con', 'win32api', 'win32process', 'win32file', 'win32com', 'win32com.client', 'pythoncom', 'reportlab', 'reportlab.lib', 'reportlab.platypus', 'reportlab.pdfgen', 'reportlab.pdfbase', 'reportlab.pdfbase.ttfonts', 'cv2', 'PIL', 'PIL.Image', 'qrcode', 'requests', 'notifier', 'app_monitor', 'browser_proxy', 'device_sentinel', 'sentry_sentinel', 'winsound', 'ctypes', 'ctypes.wintypes'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='GUARDIAN',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\guardian_logo.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='GUARDIAN',
)
