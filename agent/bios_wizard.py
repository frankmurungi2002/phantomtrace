"""
PhantomTrace — BIOS Protection Setup Wizard
=============================================

The one thing software cannot stop: a thief powering off the laptop and
booting from a USB installer. The ONLY defense is a BIOS/UEFI password +
locked boot order, which must be set in firmware (not from Windows).

This module:
  1. Detects the laptop manufacturer + model via WMI
  2. Looks up the OEM-specific key sequence to enter BIOS setup
  3. Builds a plain-English step-by-step guide for the owner
  4. Reports the make/model to the backend so the dashboard can show the
     correct instructions on any device
"""

import os
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


# OEM → BIOS entry key + helpful notes. Based on documented defaults from
# the top laptop manufacturers in East Africa. "key" is the single key to
# tap at power-on; "fallback" is an alternate on some models.
_OEM_GUIDE = {
    'hp': {
        'display': 'HP',
        'key': 'F10',
        'fallback': 'ESC then F10',
        'security_path': 'Security → Setup BIOS Administrator Password',
        'boot_path': 'Advanced → Boot Options → Legacy/USB Boot = Disabled',
    },
    'dell': {
        'display': 'Dell',
        'key': 'F2',
        'fallback': 'F12 → BIOS Setup',
        'security_path': 'Security → Admin Password → Set/Change',
        'boot_path': 'Boot Sequence → Removable Devices → Disable',
    },
    'lenovo': {
        'display': 'Lenovo',
        'key': 'F1',
        'fallback': 'F2 or Enter during logo, then F1',
        'security_path': 'Security → Password → Supervisor Password',
        'boot_path': 'Startup → Boot → USB Boot = Disabled',
    },
    'thinkpad': {   # Lenovo ThinkPad variant
        'display': 'Lenovo ThinkPad',
        'key': 'F1',
        'fallback': 'Enter then F1 during logo',
        'security_path': 'Security → Password → Supervisor Password',
        'boot_path': 'Startup → Boot → USB Boot = Disabled',
    },
    'acer': {
        'display': 'Acer',
        'key': 'F2',
        'fallback': 'DEL',
        'security_path': 'Security → Set Supervisor Password',
        'boot_path': 'Boot → USB Boot Mode = Disabled',
    },
    'asus': {
        'display': 'ASUS',
        'key': 'F2',
        'fallback': 'DEL during logo',
        'security_path': 'Security → Administrator Password',
        'boot_path': 'Boot → Boot Option Priorities → remove USB',
    },
    'msi': {
        'display': 'MSI',
        'key': 'DEL',
        'fallback': 'F2',
        'security_path': 'Security → Administrator Password',
        'boot_path': 'Boot → Boot mode select → UEFI with CSM = Disabled',
    },
    'toshiba': {
        'display': 'Toshiba',
        'key': 'F2',
        'fallback': 'ESC then F1',
        'security_path': 'Security → Supervisor Password',
        'boot_path': 'Advanced → Boot Mode → USB Boot = Disabled',
    },
    'samsung': {
        'display': 'Samsung',
        'key': 'F2',
        'fallback': 'F10 during logo',
        'security_path': 'Security → Set Supervisor Password',
        'boot_path': 'Boot → Boot Device Priority → remove USB',
    },
    'microsoft': {   # Surface
        'display': 'Microsoft Surface',
        'key': 'Hold Volume Up + Power',
        'fallback': 'Then release Power only',
        'security_path': 'Security → Password → Add Password',
        'boot_path': 'Boot Configuration → USB Storage = Disabled',
    },
}

_UNKNOWN_GUIDE = {
    'display': 'your laptop',
    'key': 'F2, F10, DEL, or ESC (check your model)',
    'fallback': 'the laptop manual lists the exact key',
    'security_path': 'Security → Set Administrator/Supervisor Password',
    'boot_path': 'Boot Order → USB Boot = Disabled',
}


def detect_model():
    """Return (manufacturer, model_name) via WMI (CSV). Falls back to
    ('Unknown', 'Unknown') if anything goes wrong."""
    if not IS_WINDOWS:
        return 'Unknown', 'Unknown'
    try:
        # CSV output is easier to parse than the default pretty-print.
        r = subprocess.run([
            "wmic", "computersystem", "get", "Manufacturer,Model", "/format:csv"
        ], capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        for line in (r.stdout or "").splitlines():
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 3 and parts[1] and parts[1].lower() not in ('manufacturer', 'node'):
                return parts[1], parts[2]
    except Exception as e:
        print(f"[bios-wizard] WMI model detect failed: {e}")

    # Fallback via PowerShell (works even if wmic is deprecated on Win 11).
    try:
        ps = ("Get-CimInstance Win32_ComputerSystem | "
              "Select-Object -Property Manufacturer, Model | "
              "ConvertTo-Json -Compress")
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW)
        import json as _json
        d = _json.loads((r.stdout or "{}").strip())
        return d.get("Manufacturer", "Unknown"), d.get("Model", "Unknown")
    except Exception as e:
        print(f"[bios-wizard] PowerShell model detect failed: {e}")

    return 'Unknown', 'Unknown'


def guide_for(manufacturer, model):
    """Pick the right OEM guide for a given manufacturer + model string.
    Checks both for broader matching (e.g. 'Lenovo ThinkPad T14' matches
    the thinkpad entry over the generic lenovo one)."""
    probe = f"{manufacturer} {model}".lower()
    # Specific matches first (thinkpad beats lenovo).
    priority = ['thinkpad', 'microsoft']
    for key in priority:
        if key in probe:
            return _OEM_GUIDE[key]
    for key, data in _OEM_GUIDE.items():
        if key in priority:
            continue
        if key in probe:
            return data
    return _UNKNOWN_GUIDE


def steps_for(manufacturer, model):
    """Returns a list of plain-English steps the owner can follow."""
    g = guide_for(manufacturer, model)
    display = f"{manufacturer} {model}".strip() or g['display']
    return {
        'manufacturer': manufacturer,
        'model': model,
        'oem_display': g['display'],
        'display_name': display,
        'enter_key': g['key'],
        'fallback_key': g['fallback'],
        'steps': [
            f"Save your work and restart the laptop.",
            f"The moment the {g['display']} logo appears on screen, press "
            f"{g['key']} repeatedly (if that doesn't work, try "
            f"{g['fallback']}).",
            f"Once in the BIOS/UEFI setup, navigate to: "
            f"{g['security_path']}.",
            f"Set a strong password you'll remember — write it down and "
            f"keep it somewhere safe. If you lose it, only the manufacturer "
            f"can reset it.",
            f"Still in BIOS, go to: {g['boot_path']}.",
            f"Save your changes (usually F10 → Yes) and exit. Your laptop "
            f"will restart — Windows will boot normally.",
            f"Come back to PhantomTrace and tap \"I've done it\" to confirm.",
        ],
    }
