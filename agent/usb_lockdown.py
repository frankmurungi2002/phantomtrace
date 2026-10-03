"""
PhantomTrace — USB Storage Lockdown
=====================================

When a device is marked STOLEN, we flip a Windows registry key that disables
USB mass-storage detection. While a thief is logged in they then can't:

  • Plug in a USB drive to copy your files out of the laptop
  • Run portable hacking tools, password crackers etc. from USB
  • Install the Windows Media Creation Tool / Rufus from inside Windows

This DOES NOT stop a thief powering off the laptop and booting from USB.
Only a BIOS password + locked boot order can do that — see bios_wizard.py.
Together with BitLocker, USB lockdown closes the data-exfiltration path.

Registry key:
  HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start
  Value 3 = enabled (default), 4 = disabled

Reversible via unlock_usb_storage() for when the device is marked Found.
"""

import os
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

USBSTOR_KEY_PATH = r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR"
_VALUE_NAME = "Start"
_LOCKED_VAL = "4"   # disabled
_OPEN_VAL   = "3"   # enabled (Windows default)


def _reg_set(value):
    """Write the Start DWORD. Requires admin — the agent should be launched
    with SYSTEM privileges by the scheduled task persistence, which gives
    this access."""
    try:
        r = subprocess.run([
            "reg", "add", USBSTOR_KEY_PATH, "/v", _VALUE_NAME,
            "/t", "REG_DWORD", "/d", value, "/f"
        ], capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        if r.returncode == 0:
            return True
        print(f"[usb-lockdown] reg write failed: rc={r.returncode} "
              f"stdout={r.stdout!r} stderr={r.stderr!r}")
    except Exception as e:
        print(f"[usb-lockdown] reg write exception: {e}")
    return False


def _reg_get():
    """Read the Start value. Returns int or None."""
    try:
        r = subprocess.run([
            "reg", "query", USBSTOR_KEY_PATH, "/v", _VALUE_NAME
        ], capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        if r.returncode != 0:
            return None
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if _VALUE_NAME in line and "0x" in line:
                hex_val = line.rsplit(" ", 1)[-1]
                try: return int(hex_val, 16)
                except Exception: return None
    except Exception as e:
        print(f"[usb-lockdown] reg read exception: {e}")
    return None


def lock_usb_storage():
    """Disable USB mass storage on this machine. Returns True on success.
    Already-plugged USB drives stay accessible until unplugged (we don't
    yank them mid-write to avoid corrupting legitimate backups you may be
    taking at the exact moment of theft — the lockdown applies to NEW
    insertions). Thief disconnects their USB and re-plugs → nothing shows."""
    if not IS_WINDOWS:
        print("[usb-lockdown] non-Windows, no-op")
        return False
    before = _reg_get()
    ok = _reg_set(_LOCKED_VAL)
    after = _reg_get()
    print(f"[usb-lockdown] lock: before={before} after={after} ok={ok}")
    return ok


def unlock_usb_storage():
    """Re-enable USB mass storage. Called when device is marked Found."""
    if not IS_WINDOWS:
        return False
    before = _reg_get()
    ok = _reg_set(_OPEN_VAL)
    after = _reg_get()
    print(f"[usb-lockdown] unlock: before={before} after={after} ok={ok}")
    return ok


def is_locked():
    """True iff USB mass storage is currently disabled via our key."""
    return _reg_get() == 4
