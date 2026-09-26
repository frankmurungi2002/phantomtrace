# -*- mode: python ; coding: utf-8 -*-
# Build:  python -m PyInstaller --clean --noconfirm PhantomTraceAgent.spec
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
for pkg in ('cv2', 'comtypes', 'pycaw', 'cryptography'):
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception:
        pass

# our own sibling modules + libraries PyInstaller sometimes misses
hiddenimports += [
    'persistence', 'triggers', 'datavault', 'deterrent_lock', 'bitlocker',
    'win32api', 'win32con', 'win32timezone', 'pywintypes', 'pythoncom',
    'requests', 'PIL', 'numpy',
    'tkinter', 'tkinter.ttk',   # T4 overlay
]

a = Analysis(
    ['agent.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='PhantomTraceAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX off: avoids AV false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,             # SILENT: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
