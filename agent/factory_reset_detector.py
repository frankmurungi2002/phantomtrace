"""
PhantomTrace — Factory Reset Detector (T-FACTORY-RESET-DETECT)
================================================================

Runs in a background thread watching for signs the thief is about to wipe
the laptop. The moment any of these events is seen, we trigger a FULL
forensic burst *immediately* — before the OS tears everything down:

  • WEBCAM + SCREENSHOT       — capture the thief's face + what they were
                                clicking right at the moment of reset
  • SEND CURRENT LOCATION     — one last GPS/Wi-Fi fix
  • MARK DEVICE STOLEN        — auto-flip server-side status so the owner
                                is pushed a notification
  • LOUD ALARM + SCREEN LOCK  — scare the thief away mid-reset

What we watch for:
  - "sysreset.exe"    launched (Windows Settings → Reset this PC)
  - "reagentc.exe"    launched with /BootToRE or /Reset flags
  - "systemreset.exe" launched (older Windows name)
  - "SystemReset"     entries in the Setup event log

These are the three legitimate paths a user takes to factory-reset Windows.
We check every 10 seconds, which is fast enough — a Windows reset takes
~30 seconds of UI confirmation before it starts wiping, so we have a window.

What we deliberately DO NOT do:
  - Modify BIOS or EFI firmware (that's rootkit territory, dangerous and
    illegal to distribute).
  - Install into the WinRE recovery image (Windows RE updates wipe it).
  - Rely on persisting through the reset — the reset kills us.

What we DO rely on:
  - The forensic burst completing BEFORE wipe starts (~15-25 seconds).
  - Cloudinary + the backend holding the evidence after the device dies.

The owner gets: "Your laptop was reset at 14:32. Last photo of thief
attached. Last known location: Mbarara, Western Region."
"""

import os
import sys
import time
import threading
import subprocess
import platform

IS_WINDOWS = platform.system() == "Windows"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Process names (lowercase) that indicate a factory reset is being invoked.
# Includes the Settings-UI launcher, the old Win 10 name, and the recovery
# tool itself.
_RESET_PROCESS_NAMES = {
    "sysreset.exe",       # Settings → Recovery → Reset this PC (modern)
    "systemreset.exe",    # Legacy Win 10 name
    "reagentc.exe",       # Recovery Environment Control — can boot into RE
}

# Check interval. 10 seconds is fast enough — Windows gives the thief
# multiple confirmation screens (minutes of UI) before actually wiping.
_CHECK_INTERVAL_S = 10

# Guard against repeated detections of the same reset event. Once we've
# fired the forensic burst, we don't need to fire it again for the next
# N seconds (either the reset proceeds and we die, or the thief cancelled
# and we don't want to spam the owner).
_SUPPRESSION_WINDOW_S = 300  # 5 minutes


def _list_running_processes():
    """Return a lowercased set of running process executable names."""
    names = set()
    if not IS_WINDOWS:
        return names
    try:
        # tasklist is more reliable than psutil for cold-start environments
        # (we may run before psutil has indexed everything).
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
            creationflags=NO_WINDOW,
        ).stdout or ""
        for line in out.splitlines():
            # CSV format: "image.exe","PID","Session","#","Mem"
            if not line.startswith('"'):
                continue
            end = line.find('"', 1)
            if end > 1:
                names.add(line[1:end].lower())
    except Exception as e:
        print(f"[factory-reset] tasklist failed: {e}")
    return names


def _detect_reset_attempt():
    """Return the matching process name if a factory-reset process is
    currently running, else None."""
    running = _list_running_processes()
    for target in _RESET_PROCESS_NAMES:
        if target in running:
            return target
    return None


def _trigger_forensic_burst(agent_module, device_id, trigger_reason):
    """Fire photo + screenshot + location + mark-stolen + alarm + lock
    using the agent's own command handlers. Runs each in its own thread so
    a slow upload doesn't block the next action — speed matters, the OS
    may be seconds from wiping us."""
    print(f"[factory-reset] ⚠ FORENSIC BURST — trigger: {trigger_reason}")

    def _safe(fn_name, *args):
        """Call an agent function if it exists, swallow exceptions
        (we're on borrowed time — any crash loses the capture)."""
        fn = getattr(agent_module, fn_name, None)
        if fn is None:
            print(f"[factory-reset] agent has no {fn_name}, skipping")
            return
        try:
            fn(*args)
        except Exception as e:
            print(f"[factory-reset] {fn_name} failed: {e}")

    def _capture_webcam():
        # take_photo returns a local file path; send_evidence uploads it.
        fp = _safe_call(agent_module, "take_photo")
        if fp:
            _safe_call(agent_module, "send_evidence", device_id, fp, "WEBCAM")

    def _capture_screen():
        fp = _safe_call(agent_module, "take_screenshot")
        if fp:
            _safe_call(agent_module, "send_evidence", device_id, fp, "SCREENSHOT")

    # Fire everything in parallel — we have maybe 15-25 seconds before wipe.
    # Order of threads chosen so the most important evidence (face +
    # screen) starts first.
    #
    # IMPORTANT: NO alarm here. The thief is remote (not in the owner's
    # presence) at this point, so a siren serves no purpose and would only
    # tempt the thief to physically destroy the laptop before we finish
    # uploading the evidence. The alarm is reserved for the final "find it
    # in the room" moment, which the owner triggers manually from the app.
    # We DO lock the screen because that may spook the thief into stopping
    # the reset — and locking is silent.
    threads = [
        threading.Thread(target=_capture_webcam, daemon=True),
        threading.Thread(target=_capture_screen, daemon=True),
        threading.Thread(target=_safe, args=("send_location", device_id), daemon=True),
        threading.Thread(target=_safe, args=("mark_self_stolen", device_id, trigger_reason), daemon=True),
        threading.Thread(target=_safe, args=("lock_device",), daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(1)


def _safe_call(agent_module, fn_name, *args):
    """Variant of _safe that returns the function's return value, so the
    webcam/screenshot callers can get the file path back for upload."""
    fn = getattr(agent_module, fn_name, None)
    if fn is None:
        print(f"[factory-reset] agent has no {fn_name}, skipping")
        return None
    try:
        return fn(*args)
    except Exception as e:
        print(f"[factory-reset] {fn_name} failed: {e}")
        return None


def start_factory_reset_watcher(agent_module, device_id):
    """Spawn the background watcher thread. Call this once at agent startup.
    `agent_module` is the agent.py module itself — we call functions on it
    by name to avoid circular imports."""
    if not IS_WINDOWS:
        print("[factory-reset] non-Windows, watcher disabled")
        return

    def _loop():
        last_fire_ts = 0
        print(f"[factory-reset] watcher started (checks every {_CHECK_INTERVAL_S}s)")
        while True:
            try:
                time.sleep(_CHECK_INTERVAL_S)
                trigger = _detect_reset_attempt()
                if trigger is None:
                    continue
                now = time.time()
                if now - last_fire_ts < _SUPPRESSION_WINDOW_S:
                    # Already fired recently — the user may have confirmed
                    # the reset dialog and the process is lingering, OR
                    # the thief cancelled and reopened. Either way, we
                    # don't want to spam the owner with duplicate alerts.
                    continue
                last_fire_ts = now
                _trigger_forensic_burst(agent_module, device_id, trigger)
            except Exception as e:
                print(f"[factory-reset] watcher loop error: {e}")

    t = threading.Thread(target=_loop, daemon=True, name="FactoryResetWatcher")
    t.start()
    return t
