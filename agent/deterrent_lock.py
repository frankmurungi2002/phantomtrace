"""
PhantomTrace Deterrent Lock Screen (T4)
========================================
When the owner presses LOCK in the mobile app, this shows a FULL-SCREEN
overlay on the stolen laptop with:
  * a large "THIS DEVICE HAS BEEN REPORTED STOLEN" banner
  * the owner's custom message (contact info, reward, etc.)
  * the device ID
  * an unlock code field (only the owner's code will dismiss it)

While the overlay is up:
  * Alt-Tab / Alt-F4 / Win / Ctrl+Esc are intercepted (best effort)
  * Windows is also locked underneath (LockWorkStation)
  * local non-admin user accounts are disabled (admin still gets in)
  * the Windows lock-screen LegalNoticeText is set to the same message
  * the Power button on the login screen is hidden
  * a shutdown block is armed (see on_shutdown_signal in agent.py)

This is a DETERRENT, not a bulletproof cage — a determined attacker can
still boot to safe mode. The goal is to make an opportunistic thief give
up and return the laptop.

Copied ideas: Microsoft Find My Device (custom lock-screen message,
disable local users) + Prey Project (full-screen overlay).
"""
import os, sys, json, threading, subprocess, hashlib

IS_WINDOWS = os.name == 'nt'

# Path where the last-issued unlock code lives (so the overlay can check
# it locally even when the laptop is offline). Sits next to the agent.
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOCK_STATE_FILE = os.path.join(BASE_DIR, "lock_state.json")

NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# One overlay at a time. Held so we can dismiss it from another thread.
_overlay_thread = None
_overlay_root   = None
_overlay_lock   = threading.Lock()


# ── State: is the device currently under deterrent lock? ─────────────────────
def _write_state(active, message="", unlock_code_hash=""):
    try:
        with open(LOCK_STATE_FILE, "w") as f:
            json.dump({
                "active":            bool(active),
                "message":           message,
                "unlock_code_hash":  unlock_code_hash,
            }, f)
    except Exception as e:
        print(f"lock state write failed: {e}")


def _read_state():
    try:
        with open(LOCK_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"active": False, "message": "", "unlock_code_hash": ""}


def is_locked():
    """True if the device is currently under deterrent lock."""
    return _read_state().get("active", False)


def _hash_code(code):
    return hashlib.sha256(str(code).encode()).hexdigest()


# ── Windows lock-screen message (the LegalNoticeText registry key) ───────────
def set_lockscreen_message(message, caption="PhantomTrace Anti-Theft"):
    """
    Write the message to the Windows registry so it appears on the login
    screen BEFORE anyone signs in. Needs admin; silently no-ops otherwise.
    """
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        k = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(k, "legalnoticecaption", 0, winreg.REG_SZ, caption)
        winreg.SetValueEx(k, "legalnoticetext",    0, winreg.REG_SZ, message)
        winreg.CloseKey(k)
        print("Lock-screen message set")
        return True
    except Exception as e:
        print(f"legalnoticetext write failed: {e}")
        return False


def clear_lockscreen_message():
    if not IS_WINDOWS:
        return
    try:
        import winreg
        k = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        for name in ("legalnoticecaption", "legalnoticetext"):
            try: winreg.DeleteValue(k, name)
            except Exception: pass
        winreg.CloseKey(k)
    except Exception as e:
        print(f"legalnoticetext clear failed: {e}")


# ── Hide the Power button on the login screen ────────────────────────────────
def block_shutdown_button():
    """Remove Power from the lock screen. Needs admin; silent otherwise."""
    if not IS_WINDOWS:
        return
    try:
        import winreg
        k = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(k, "ShutdownWithoutLogon", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(k)
        print("Shutdown button hidden on lock screen")
    except Exception as e:
        print(f"ShutdownWithoutLogon write failed: {e}")


def restore_shutdown_button():
    if not IS_WINDOWS:
        return
    try:
        import winreg
        k = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(k, "ShutdownWithoutLogon", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)
    except Exception as e:
        print(f"ShutdownWithoutLogon restore failed: {e}")


# ── Disable local (non-admin) users ──────────────────────────────────────────
# Mirrors Microsoft Find My Device: after Lock, local users are blocked but
# admin accounts can still sign in — so the owner can always get back in.
_DISABLED_USERS_FILE = os.path.join(BASE_DIR, "disabled_users.json")


def _list_local_users():
    """Return (username, is_admin) tuples via `net user` + admin group check."""
    users = []
    if not IS_WINDOWS:
        return users
    try:
        out = subprocess.run(["net", "user"], capture_output=True, text=True,
                             timeout=15, creationflags=NO_WINDOW).stdout or ""
        # parse the table between the ---- lines
        in_table = False
        names = []
        for line in out.splitlines():
            if line.startswith("---"):
                in_table = not in_table
                continue
            if in_table:
                # each row is space-separated; take non-empty tokens
                for tok in line.split():
                    if tok and not tok.startswith("The"):
                        names.append(tok)
        # figure out who is an admin
        admins = set()
        try:
            out2 = subprocess.run(["net", "localgroup", "Administrators"],
                                  capture_output=True, text=True, timeout=15,
                                  creationflags=NO_WINDOW).stdout or ""
            in_table2 = False
            for line in out2.splitlines():
                if line.startswith("---"):
                    in_table2 = not in_table2; continue
                if in_table2 and line.strip() and not line.startswith("The"):
                    admins.add(line.strip())
        except Exception:
            pass
        for n in names:
            users.append((n, n in admins))
    except Exception as e:
        print(f"user enumeration failed: {e}")
    return users


def disable_local_users():
    """
    Disable every local user EXCEPT admins. Records who was disabled so
    we can re-enable exactly them on unlock. Needs admin; silent otherwise.
    """
    if not IS_WINDOWS:
        return
    disabled = []
    try:
        for name, is_admin in _list_local_users():
            if is_admin:
                continue
            try:
                r = subprocess.run(["net", "user", name, "/active:no"],
                                   capture_output=True, text=True, timeout=15,
                                   creationflags=NO_WINDOW)
                if r.returncode == 0:
                    disabled.append(name)
                    print(f"Disabled local user: {name}")
            except Exception as e:
                print(f"disable user {name} failed: {e}")
        try:
            with open(_DISABLED_USERS_FILE, "w") as f:
                json.dump({"users": disabled}, f)
        except Exception:
            pass
    except Exception as e:
        print(f"disable_local_users error: {e}")


def enable_local_users():
    """Re-enable exactly the users we disabled at lock time."""
    if not IS_WINDOWS:
        return
    try:
        with open(_DISABLED_USERS_FILE) as f:
            names = json.load(f).get("users", [])
    except Exception:
        names = []
    for name in names:
        try:
            subprocess.run(["net", "user", name, "/active:yes"],
                           capture_output=True, text=True, timeout=15,
                           creationflags=NO_WINDOW)
            print(f"Re-enabled local user: {name}")
        except Exception as e:
            print(f"enable user {name} failed: {e}")
    try: os.remove(_DISABLED_USERS_FILE)
    except Exception: pass


# ── Enable Windows Location (per Microsoft Find My Device lock behavior) ─────
def enable_location_services():
    """Turn Location on so the owner can keep locating the device."""
    if not IS_WINDOWS:
        return
    try:
        import winreg
        for path in (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged",
        ):
            try:
                k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
                winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ, "Allow")
                winreg.CloseKey(k)
            except Exception as e:
                print(f"loc enable ({path}) failed: {e}")
        try:
            k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration")
            winreg.SetValueEx(k, "Status", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k)
            print("Location services enabled by deterrent lock")
        except Exception as e:
            print(f"loc platform status failed: {e}")
    except Exception as e:
        print(f"enable_location_services failed: {e}")


# ── The full-screen overlay itself (Tkinter) ────────────────────────────────
def _build_overlay(message, device_id, unlock_callback):
    """
    Build the overlay window. Called on the overlay thread. Blocks until
    the correct unlock code is entered or the overlay is dismissed from
    another thread.
    """
    global _overlay_root
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception as e:
        print(f"tkinter unavailable: {e}")
        return

    root = tk.Tk()
    _overlay_root = root
    root.title("PhantomTrace")
    root.configure(bg="#0a0a0a")

    # Full-screen, borderless, topmost
    try:
        root.attributes("-fullscreen", True)
        root.attributes("-topmost",   True)
        root.overrideredirect(True)
    except Exception:
        # Fall back to a large window if the WM refuses fullscreen
        w, h = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{w}x{h}+0+0")

    # Kill close/minimize hotkeys we CAN block from Tk itself
    for seq in ("<Alt-F4>", "<Escape>", "<Alt-Tab>", "<Control-Escape>"):
        root.bind(seq, lambda e: "break")
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    # ── Layout ────────────────────────────────────────────────────────────
    outer = tk.Frame(root, bg="#0a0a0a")
    outer.pack(expand=True, fill="both", padx=40, pady=40)

    tk.Label(outer,
             text="🔒  THIS DEVICE HAS BEEN REPORTED STOLEN",
             font=("Segoe UI", 36, "bold"),
             fg="#ff3b3b", bg="#0a0a0a", wraplength=1200).pack(pady=(60, 20))

    tk.Label(outer,
             text="Protected by PhantomTrace",
             font=("Segoe UI", 20),
             fg="#888", bg="#0a0a0a").pack(pady=(0, 40))

    # Owner's custom message
    msg_frame = tk.Frame(outer, bg="#1a1a1a",
                         highlightbackground="#ff3b3b",
                         highlightthickness=2)
    msg_frame.pack(fill="x", padx=100, pady=20)
    tk.Label(msg_frame,
             text=message or "This device is protected. Please return it to its owner.",
             font=("Segoe UI", 22),
             fg="#ffffff", bg="#1a1a1a",
             wraplength=1000, justify="center").pack(padx=40, pady=30)

    tk.Label(outer,
             text=f"Device ID: {device_id}",
             font=("Consolas", 14),
             fg="#666", bg="#0a0a0a").pack(pady=(30, 10))

    # Unlock area
    unlock_frame = tk.Frame(outer, bg="#0a0a0a")
    unlock_frame.pack(pady=(40, 20))

    tk.Label(unlock_frame,
             text="Owner unlock code:",
             font=("Segoe UI", 14),
             fg="#aaa", bg="#0a0a0a").pack(side="left", padx=(0, 10))

    code_var = tk.StringVar()
    entry = tk.Entry(unlock_frame,
                     textvariable=code_var,
                     show="•",
                     font=("Segoe UI", 16),
                     width=20,
                     bg="#222", fg="#fff",
                     insertbackground="#fff",
                     relief="flat")
    entry.pack(side="left", padx=(0, 10), ipady=6)
    entry.focus_set()

    status_var = tk.StringVar(value="")
    status_lbl = tk.Label(outer,
                          textvariable=status_var,
                          font=("Segoe UI", 12),
                          fg="#ffaa00", bg="#0a0a0a")
    status_lbl.pack(pady=(10, 0))

    wrong_attempts = {"n": 0}

    def try_unlock(event=None):
        code = code_var.get().strip()
        if not code:
            return
        if unlock_callback(code):
            status_var.set("✓ Unlocked. Restoring...")
            root.update()
            try:
                root.destroy()
            except Exception:
                pass
        else:
            wrong_attempts["n"] += 1
            status_var.set(f"✗ Wrong code (attempt {wrong_attempts['n']}). "
                           "The owner has been notified.")
            code_var.set("")
            # Notify the owner + take a photo (fire-and-forget)
            threading.Thread(target=_report_wrong_attempt,
                             args=(device_id, wrong_attempts["n"]),
                             daemon=True).start()

    tk.Button(unlock_frame,
              text="Unlock",
              font=("Segoe UI", 14, "bold"),
              bg="#ff3b3b", fg="#fff",
              activebackground="#cc2222",
              relief="flat", padx=20, pady=6,
              command=try_unlock).pack(side="left")

    root.bind("<Return>", try_unlock)

    # Footer
    tk.Label(outer,
             text="A photo is taken and the owner is alerted on every wrong attempt.",
             font=("Segoe UI", 10),
             fg="#555", bg="#0a0a0a").pack(side="bottom", pady=20)

    try:
        root.mainloop()
    except Exception as e:
        print(f"overlay mainloop error: {e}")
    finally:
        _overlay_root = None


def _report_wrong_attempt(device_id, attempt_num):
    """Take a webcam photo and alert the owner. Best effort; never raises."""
    try:
        # Import here to avoid circular imports at load time
        import requests
        try:
            import cv2, tempfile
            tmp = os.path.join(tempfile.gettempdir(), "pt_unlock_attempt.jpg")
            for idx in range(3):
                cam = cv2.VideoCapture(idx)
                ret, frame = cam.read()
                cam.release()
                if ret:
                    cv2.imwrite(tmp, frame)
                    with open(tmp, "rb") as f:
                        requests.post(
                            "https://phantomtrace-backend-c0if.onrender.com/api/evidence/photo",
                            files={"photo": f},
                            data={"device_id": device_id,
                                  "photo_type": "UNLOCK_ATTEMPT"},
                            timeout=30)
                    try: os.remove(tmp)
                    except Exception: pass
                    break
        except Exception as pe:
            print(f"wrong-attempt photo failed: {pe}")

        requests.post(
            "https://phantomtrace-backend-c0if.onrender.com/api/device/alert",
            json={"device_id": device_id,
                  "title": "Wrong unlock code entered",
                  "body":  f"Attempt #{attempt_num} on the deterrent lock. "
                           "A webcam photo was captured."},
            timeout=8)
    except Exception as e:
        print(f"wrong-attempt report failed: {e}")


# ── Public API ────────────────────────────────────────────────────────────
def activate(message, device_id, unlock_code):
    """
    Turn on the deterrent lock:
      * write the lock-screen message
      * disable local non-admin users
      * hide the Power button on the login screen
      * enable Location services
      * lock Windows
      * show the full-screen overlay
    Idempotent — calling it while already active just refreshes the message.
    """
    global _overlay_thread

    _write_state(True, message, _hash_code(unlock_code))

    # System-level changes (best effort; each is silent if not elevated)
    set_lockscreen_message(message)
    disable_local_users()
    block_shutdown_button()
    enable_location_services()

    # Underlying Windows lock (behind the overlay)
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
        except Exception as e:
            print(f"LockWorkStation failed: {e}")

    # The overlay itself
    def _check(code):
        return _hash_code(code) == _read_state().get("unlock_code_hash", "")

    with _overlay_lock:
        if _overlay_thread and _overlay_thread.is_alive():
            print("Overlay already showing; message refreshed")
            return
        _overlay_thread = threading.Thread(
            target=_build_overlay,
            args=(message, device_id, _check),
            daemon=True)
        _overlay_thread.start()

    print(f"Deterrent lock activated for device {device_id}")


def deactivate():
    """
    Turn the deterrent lock off:
      * dismiss the overlay
      * re-enable local users
      * restore the Power button
      * clear the lock-screen message
    Called on UNLOCK_DETERRENT command or when the local unlock succeeds.
    """
    _write_state(False, "", "")

    global _overlay_root
    if _overlay_root is not None:
        try:
            _overlay_root.after(0, _overlay_root.destroy)
        except Exception:
            pass

    enable_local_users()
    restore_shutdown_button()
    clear_lockscreen_message()
    print("Deterrent lock deactivated")


def restore_on_boot():
    """
    Called from agent.py at startup. If the device rebooted while under
    deterrent lock, put the overlay back up immediately.
    """
    st = _read_state()
    if st.get("active"):
        # Reconstruct the unlock hash from what's on disk
        msg  = st.get("message", "")
        # We can't recover the raw unlock code, only the hash — use it directly
        def _check(code):
            return _hash_code(code) == st.get("unlock_code_hash", "")
        global _overlay_thread
        with _overlay_lock:
            if _overlay_thread and _overlay_thread.is_alive():
                return
            _overlay_thread = threading.Thread(
                target=_build_overlay,
                args=(msg, "(restored)", _check),
                daemon=True)
            _overlay_thread.start()
        print("Deterrent lock restored after boot")
