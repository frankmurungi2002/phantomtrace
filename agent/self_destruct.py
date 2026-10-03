"""
PhantomTrace Agent Self-Destruct
==================================
Called from the agent when it receives the AGENT_UNINSTALL command — which
happens when the owner deletes the device from the mobile app.

Steps (in order):
  1. Remove the scheduled task (schtasks /delete)
  2. Remove the HKCU Run registry entry
  3. Delete the registry backup of device.json (HKCU\\Software\\PhantomTrace)
  4. Delete device.json
  5. Re-enable USB storage (reverse USB lockdown) — courtesy to the next
     legitimate owner of this laptop
  6. Spawn a self-destruct batch script that waits a few seconds, then
     deletes the agent files (including the running .exe itself) and
     removes itself afterwards. The agent's own Python process exits
     cleanly BEFORE the batch tries the deletion, so Windows can release
     the exe lock.
  7. Call os._exit(0) to leave immediately.

This whole operation is best-effort. If the agent dies partway, next launch
re-detects device.json missing and goes through pairing again — the owner
can simply not pair it, and reality converges.
"""

import os
import sys
import time
import subprocess
import platform

IS_WINDOWS = platform.system() == "Windows"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

TASK_NAME = "PhantomTrace"
RUN_KEY_NAME = "PhantomTrace"


def _run(cmd, timeout=10):
    """Run a command silently. Always returns (rc, stdout, stderr),
    swallowing exceptions as rc=-1."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode, r.stdout or "", r.stderr or ""
    except Exception as e:
        return -1, "", str(e)


def _remove_scheduled_task():
    rc, _, err = _run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"])
    print(f"[self-destruct] schtasks rc={rc} {('ok' if rc == 0 else err.strip())}")


def _remove_run_key():
    if not IS_WINDOWS:
        return
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, RUN_KEY_NAME)
            print("[self-destruct] Run key removed")
        except FileNotFoundError:
            print("[self-destruct] Run key already absent")
        winreg.CloseKey(key)
    except Exception as e:
        print(f"[self-destruct] Run key error: {e}")


def _remove_registry_backup():
    """We also stored a backup of device.json under HKCU\\Software\\PhantomTrace.
    Clean that up so a reinstall doesn't re-register the deleted device."""
    rc, _, err = _run(["reg", "delete", r"HKCU\Software\PhantomTrace", "/f"])
    print(f"[self-destruct] HKCU\\Software\\PhantomTrace rc={rc}")


def _delete_config(base_dir):
    cfg = os.path.join(base_dir, "device.json")
    try:
        if os.path.exists(cfg):
            os.remove(cfg)
            print(f"[self-destruct] deleted {cfg}")
    except Exception as e:
        print(f"[self-destruct] cfg delete error: {e}")


def _unlock_usb():
    """Reverse the USB storage lockdown so the owner (or next legitimate
    owner of the laptop) can use USB drives again. Best effort."""
    try:
        import usb_lockdown
        usb_lockdown.unlock_usb_storage()
    except Exception as e:
        print(f"[self-destruct] usb unlock error: {e}")


def _schedule_file_deletion(base_dir, exe_path):
    """Write a .bat that waits a few seconds (so our process has exited and
    released the exe), then deletes the files, then deletes itself. The
    batch spawns detached so our calling process can return immediately."""
    if not IS_WINDOWS:
        return
    bat_path = os.path.join(os.path.expandvars("%TEMP%"), "pt_cleanup.bat")
    # NOTE: single-% is a batch literal; double %% escapes % inside the script.
    bat = (
        "@echo off\r\n"
        "timeout /t 4 /nobreak > nul\r\n"
        # Kill the exe in case it is still running (shouldn't be — we exited).
        f'taskkill /f /im "{os.path.basename(exe_path)}" >nul 2>&1\r\n'
        f'del /f /q "{exe_path}" >nul 2>&1\r\n'
        f'del /f /q "{os.path.join(base_dir, "device.json")}" >nul 2>&1\r\n'
        f'del /f /q "{os.path.join(base_dir, "STOP_PHANTOMTRACE")}" >nul 2>&1\r\n'
        f'del /f /q "{os.path.join(base_dir, "agent_alive.txt")}" >nul 2>&1\r\n'
        f'del /f /q "{os.path.join(base_dir, "watchdog_alive.txt")}" >nul 2>&1\r\n'
        f'del /f /q "{os.path.join(base_dir, "trigger_state.json")}" >nul 2>&1\r\n'
        # Finally, delete this batch file itself.
        '(goto) 2>nul & del "%~f0"\r\n'
    )
    try:
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(bat)
        # Detached, no console window.
        subprocess.Popen(
            ["cmd", "/c", bat_path],
            creationflags=NO_WINDOW | 0x00000008,  # DETACHED_PROCESS
            close_fds=True, stdin=None, stdout=None, stderr=None,
        )
        print(f"[self-destruct] scheduled cleanup bat at {bat_path}")
    except Exception as e:
        print(f"[self-destruct] bat write error: {e}")


def perform_self_destruct():
    """Full uninstall sequence. Exits the process at the end — DOES NOT RETURN."""
    print("[self-destruct] AGENT_UNINSTALL received — tearing down.")
    try:
        base_dir = (os.path.dirname(sys.executable)
                    if getattr(sys, 'frozen', False)
                    else os.path.dirname(os.path.abspath(sys.argv[0])))
        exe_path = (sys.executable if getattr(sys, 'frozen', False)
                    else os.path.abspath(sys.argv[0]))
        _remove_scheduled_task()
        _remove_run_key()
        _remove_registry_backup()
        _unlock_usb()
        _delete_config(base_dir)
        _schedule_file_deletion(base_dir, exe_path)
    except Exception as e:
        print(f"[self-destruct] fatal: {e}")
    finally:
        # Give the batch script a moment to start.
        time.sleep(1)
        print("[self-destruct] goodbye.")
        os._exit(0)
