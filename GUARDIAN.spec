# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['GUARDIAN.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\index.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\splash.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\remote.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\dossier_report.html', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\chart.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\main.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\welcome_tour.js', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\welcome_tour.css', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\guardian_logo.png', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\guardian_logo.ico', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\guardian_logo.jpg', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\sentry_qr.png', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\alert_beep.wav', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\freesound_community-beep-6-96243.mp3', '.'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\templates', 'templates'), ('C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\static', 'static')],
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
    icon=['C:\\Users\\user\\OneDrive\\Documents\\projects\\Guardian\\GUARDIAN\\guardian_logo.ico'],
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
