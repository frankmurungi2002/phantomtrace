"""
PhantomTrace Agent
==================
Runs silently on a protected laptop. On first launch it self-registers with
the backend, then polls for commands every 3 seconds and sends heartbeats.

Supports: LOCK, ALARM, STOP_ALARM, PHOTO, SCREENSHOT, AUDIO, WIPE,
          PING, SYSTEM_INFO, GET_NETWORK, GET_DISKS, GET_PROCESSES, GET_LOCATION,
          SECURE_DATA, RESTORE_DATA, DETERRENT_LOCK, UNLOCK_DETERRENT,
          BITLOCKER_STATUS, ENABLE_BITLOCKER, INSTANT_WIPE
"""

import subprocess, sys, platform as _platform_check, os

# ── Auto-install missing packages ─────────────────────────────────────────────
def _ensure_dependencies():
    required = ["requests", "opencv-python"]
    if _platform_check.system() == "Windows":
        required += ["pywin32", "pycaw", "comtypes", "pillow"]
    import importlib
    names = {"requests":"requests","opencv-python":"cv2","pywin32":"win32api",
             "pycaw":"pycaw","comtypes":"comtypes","pillow":"PIL"}
    missing = [p for p in required if not _can_import(names.get(p, p))]
    if missing:
        print(f"Installing: {missing}")
        subprocess.run([sys.executable,"-m","pip","install","--quiet"]+missing, check=False)

def _can_import(mod):
    import importlib
    try: importlib.import_module(mod); return True
    except ImportError: return False

if not getattr(sys, 'frozen', False):
    _ensure_dependencies()   # bundled deps in the .exe; only install when running as .py

import requests, time, platform, socket, getpass, uuid, shutil, json, math, signal, threading

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

# Run all helper processes (powershell, netsh, tasklist, taskkill, ffmpeg...)
# WITHOUT flashing a console window on Windows.
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# ── Persistence layer (T1) ──────────────────────────────────────────────────
# Ensure the agent's own folder is importable, then load persistence helpers.
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)
try:
    import persistence
    _HAS_PERSISTENCE = True
except Exception as _pe:
    _HAS_PERSISTENCE = False
    print(f"Persistence layer unavailable: {_pe}")

# ── Automatic triggers (T2) ─────────────────────────────────────────────────
try:
    import triggers
    _HAS_TRIGGERS = True
except Exception as _te0:
    _HAS_TRIGGERS = False
    print(f"Triggers layer unavailable: {_te0}")

# ── Data vault (T5) ──────────────────────────────────────────────────────────
try:
    import datavault
    _HAS_VAULT = True
except Exception as _ve0:
    _HAS_VAULT = False
    print(f"Data vault unavailable: {_ve0}")

# ── Deterrent lock overlay (T4) ─────────────────────────────────────────────
try:
    import deterrent_lock
    _HAS_DETERRENT = True
except Exception as _de0:
    _HAS_DETERRENT = False
    print(f"Deterrent lock unavailable: {_de0}")

# ── BitLocker orchestrator (T8) ─────────────────────────────────────────────
try:
    import bitlocker
    _HAS_BITLOCKER = True
except Exception as _be0:
    _HAS_BITLOCKER = False
    print(f"BitLocker module unavailable: {_be0}")

# ── USB storage lockdown + BIOS wizard model detection ────────────────────
try:
    import usb_lockdown
    _HAS_USB_LOCKDOWN = True
except Exception as _ue0:
    _HAS_USB_LOCKDOWN = False
    print(f"USB lockdown module unavailable: {_ue0}")

try:
    import bios_wizard
    _HAS_BIOS_WIZARD = True
except Exception as _bwe:
    _HAS_BIOS_WIZARD = False
    print(f"BIOS wizard module unavailable: {_bwe}")

# Self-destruct: owner deleted the device → agent uninstalls itself.
try:
    import self_destruct
    _HAS_SELF_DESTRUCT = True
except Exception as _sde:
    _HAS_SELF_DESTRUCT = False
    print(f"Self-destruct module unavailable: {_sde}")

if getattr(sys, 'frozen', False):
    CONFIG_FILE = os.path.join(os.path.dirname(sys.executable), 'device.json')
else:
    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device.json')

BASE_URL = "https://phantomtrace-backend-c0if.onrender.com"

# ── Shutdown protection globals ────────────────────────────────────────────────
_shutdown_blocked = False
_alarm_active     = False

# ── Device registration ────────────────────────────────────────────────────────
def _pair_via_dialog(device_name):
    """
    First-launch pairing. Show a Tk dialog asking the user for the
    pairing code they generated in the PhantomTrace mobile app.
    Retries on wrong / expired codes until the user cancels.

    Returns (device_id, beacon_id) on success, or None on cancel.
    """
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except Exception as e:
        print(f"Tk unavailable for pairing dialog: {e}")
        return None

    result = {"device_id": None, "beacon_id": None}

    def submit():
        code = code_var.get().strip().upper()
        if not code:
            status_var.set("Please enter your pairing code."); return
        submit_btn.configure(state="disabled")
        status_var.set("Contacting server…")
        root.update()
        try:
            r = requests.post(f"{BASE_URL}/api/device/pair",
                              json={"code": code, "device_name": device_name},
                              timeout=15)
            if r.status_code == 201:
                d = r.json()
                result["device_id"] = d["device_id"]
                result["beacon_id"] = d.get("beacon_id", "")
                root.destroy()
                return
            err = "Pairing failed."
            try: err = r.json().get("error", err)
            except Exception: pass
            status_var.set(f"✗ {err}")
        except Exception as e:
            status_var.set(f"✗ Network error: {e}")
        finally:
            submit_btn.configure(state="normal")

    def cancel():
        root.destroy()

    # ── Premium dark-themed pairing dialog, visually matching the mobile app ──
    # Design language:
    #   • Deep #0A0A0A background with a #141A2E surface card
    #   • Crimson #DC2626 primary (same as mobile AppColors.primary)
    #   • Segoe UI (fallback to Arial) weighted for hierarchy
    #   • Large monospace code entry with 8px letter-spacing feel
    #   • Status row for inline errors/progress, not modal popups
    PT_BG      = "#0A0A0A"
    PT_SURFACE = "#141A2E"
    PT_MUTED   = "#9CA3AF"
    PT_SUBTLE  = "#6B7280"
    PT_PRIMARY = "#DC2626"
    PT_PRIMARY_HOVER = "#B91C1C"
    PT_TEXT    = "#F3F4F6"
    PT_SUCCESS = "#10B981"
    PT_WARN    = "#F59E0B"

    root = tk.Tk()
    root.title("PhantomTrace")
    root.configure(bg=PT_BG)
    # Center the window on screen. Height bumped so the Pair/Cancel buttons
    # are never clipped off the bottom of the card on tall-DPI laptop screens.
    _w, _h = 600, 700
    _sw = root.winfo_screenwidth()
    _sh = root.winfo_screenheight()
    root.geometry(f"{_w}x{_h}+{(_sw - _w) // 2}+{(_sh - _h) // 2}")
    root.resizable(False, False)
    try: root.attributes("-topmost", True)
    except Exception: pass

    # Outer padding frame — matches the 24px margin style of the mobile app.
    outer = tk.Frame(root, bg=PT_BG)
    outer.pack(expand=True, fill="both", padx=28, pady=28)

    # ── Logo + brand row ──────────────────────────────────────────────────
    brand = tk.Frame(outer, bg=PT_BG)
    brand.pack(fill="x", pady=(0, 20))
    tk.Label(brand, text="◆",
             font=("Segoe UI", 22, "bold"),
             fg=PT_PRIMARY, bg=PT_BG).pack(side="left")
    tk.Label(brand, text="  PHANTOMTRACE",
             font=("Segoe UI", 15, "bold"),
             fg=PT_TEXT, bg=PT_BG).pack(side="left")

    # ── Surface card ──────────────────────────────────────────────────────
    card = tk.Frame(outer, bg=PT_SURFACE)
    card.pack(fill="both", expand=True, ipadx=4, ipady=4)
    inner = tk.Frame(card, bg=PT_SURFACE)
    inner.pack(fill="both", expand=True, padx=28, pady=28)

    tk.Label(inner, text="PAIR THIS LAPTOP",
             font=("Segoe UI", 10, "bold"),
             fg=PT_MUTED, bg=PT_SURFACE).pack(anchor="w")
    tk.Label(inner, text="Link this device to your account",
             font=("Segoe UI", 18, "bold"),
             fg=PT_TEXT, bg=PT_SURFACE,
             wraplength=460, justify="left").pack(anchor="w", pady=(4, 14))

    tk.Label(inner,
             text=("Open PhantomTrace on your phone and tap \"Add device\".\n"
                   "You'll see a one-time pairing code. Type it below."),
             font=("Segoe UI", 10),
             fg=PT_MUTED, bg=PT_SURFACE,
             wraplength=460, justify="left").pack(anchor="w", pady=(0, 22))

    # ── Pairing-code field ────────────────────────────────────────────────
    tk.Label(inner, text="PAIRING CODE",
             font=("Segoe UI", 9, "bold"),
             fg=PT_MUTED, bg=PT_SURFACE).pack(anchor="w")

    # Simulate a bordered input: a thin frame around a flat entry.
    code_wrap = tk.Frame(inner, bg="#1F2937", highlightthickness=1,
                         highlightbackground="#374151",
                         highlightcolor=PT_PRIMARY)
    code_wrap.pack(fill="x", pady=(8, 4))
    code_var = tk.StringVar()
    entry = tk.Entry(code_wrap, textvariable=code_var,
                     font=("Consolas", 26, "bold"),
                     justify="center",
                     bg="#1F2937", fg=PT_TEXT,
                     insertbackground=PT_PRIMARY, relief="flat",
                     bd=0)
    entry.pack(fill="x", padx=14, pady=14)
    entry.focus_set()

    tk.Label(inner, text=f"Device name:  {device_name}",
             font=("Segoe UI", 9),
             fg=PT_SUBTLE, bg=PT_SURFACE).pack(anchor="w", pady=(12, 6))

    # ── Inline status row ─────────────────────────────────────────────────
    status_var = tk.StringVar(value="")
    status_lbl = tk.Label(inner, textvariable=status_var,
             font=("Segoe UI", 10, "bold"),
             fg=PT_WARN, bg=PT_SURFACE,
             wraplength=460, justify="left")
    status_lbl.pack(anchor="w", pady=(6, 0))

    # Give submit() access to the status label so it can color-switch
    def set_status(msg, color=PT_WARN):
        status_var.set(msg); status_lbl.configure(fg=color)

    # Rewire submit() to use the modern status helper and color codes
    def submit_modern():
        code = code_var.get().strip().upper()
        if not code:
            set_status("Enter the pairing code shown on your phone.", PT_WARN)
            return
        submit_btn.configure(state="disabled", text="Pairing…")
        set_status("Contacting server…", PT_MUTED)
        root.update()
        try:
            r = requests.post(f"{BASE_URL}/api/device/pair",
                              json={"code": code, "device_name": device_name},
                              timeout=15)
            if r.status_code == 201:
                d = r.json()
                result["device_id"] = d["device_id"]
                result["beacon_id"] = d.get("beacon_id", "")
                set_status("✓ Paired — welcome to PhantomTrace.", PT_SUCCESS)
                root.update()
                root.after(900, root.destroy)
                return
            err = "Pairing failed."
            try: err = r.json().get("error", err)
            except Exception: pass
            set_status(f"✗ {err}", PT_PRIMARY)
        except Exception as e:
            set_status(f"✗ Network error: {e}", PT_PRIMARY)
        finally:
            submit_btn.configure(state="normal", text="Pair device")

    # ── Buttons ───────────────────────────────────────────────────────────
    # Full-width button row at the bottom, each 50% wide so they read as
    # real buttons and never look like clipped text.
    btns = tk.Frame(inner, bg=PT_SURFACE); btns.pack(fill="x", pady=(32, 4))
    btns.columnconfigure(0, weight=1)
    btns.columnconfigure(1, weight=1)

    def _hover(btn, enter_bg, leave_bg):
        btn.bind("<Enter>", lambda _e: btn.configure(bg=enter_bg))
        btn.bind("<Leave>", lambda _e: btn.configure(bg=leave_bg))

    # Cancel on the left — bordered-looking neutral button.
    cancel_wrap = tk.Frame(btns, bg="#374151")
    cancel_wrap.grid(row=0, column=0, sticky="ew", padx=(0, 8))
    cancel_btn = tk.Button(cancel_wrap, text="Cancel",
                           font=("Segoe UI", 12, "bold"),
                           bg="#1F2937", fg=PT_TEXT,
                           activebackground="#111827",
                           activeforeground=PT_TEXT,
                           relief="flat", bd=0, cursor="hand2",
                           pady=14, command=cancel)
    cancel_btn.pack(fill="x", padx=1, pady=1)
    _hover(cancel_btn, "#111827", "#1F2937")

    # Pair device on the right — brand primary, bold.
    submit_btn = tk.Button(btns, text="Pair device",
                           font=("Segoe UI", 12, "bold"),
                           bg=PT_PRIMARY, fg="#FFFFFF",
                           activebackground=PT_PRIMARY_HOVER,
                           activeforeground="#FFFFFF",
                           relief="flat", bd=0, cursor="hand2",
                           pady=14, command=submit_modern)
    submit_btn.grid(row=0, column=1, sticky="ew", padx=(8, 0))
    _hover(submit_btn, PT_PRIMARY_HOVER, PT_PRIMARY)

    root.bind("<Return>", lambda _e: submit_modern())
    root.bind("<Escape>", lambda _e: cancel())

    # Replace the plain submit() with submit_modern — don't keep the old one bound.
    root.mainloop()
    return (result["device_id"], result["beacon_id"]) if result["device_id"] else None


def get_or_register_device():
    """
    Returns (device_id, beacon_id).

    Priority order:
      1. Existing device.json — normal case, every launch after the first.
      2. First launch with no device.json:
         a) if a pairing code was supplied via env var PHANTOMTRACE_PAIR_CODE
            (useful for scripted installs), pair silently
         b) if PHANTOMTRACE_EMAIL is set AND the legacy self-register still
            works, fall back to it (dev-mode single-user installs)
         c) otherwise, prompt the user with a Tk dialog for the pairing
            code they generated in the mobile app
    """
    if os.path.exists(CONFIG_FILE):
        # Sanity check: a stale/empty/corrupt device.json would silently skip
        # the pairing dialog and leave the agent registered to nobody.
        # Treat a missing or empty device_id as "not paired" and fall through
        # to the pairing dialog instead.
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            dev_id = (config or {}).get('device_id', '').strip()
            if dev_id:
                # NEW: validate with the backend. The owner may have deleted
                # this device from the mobile app (or wiped the DB), in which
                # case our stored device_id is a ghost and heartbeats will
                # fall into a black hole. Ask the backend before trusting it.
                try:
                    r = requests.get(
                        f"{BASE_URL}/api/device/{dev_id}/exists",
                        timeout=10)
                    if r.status_code == 200 and r.json().get('exists') is True:
                        print(f"Device ID: {dev_id} (verified with backend)")
                        return dev_id, config.get('beacon_id', '')
                    # Backend answered but doesn't know this device — clear
                    # local state and re-prompt. ALSO clean up the registry
                    # backup so persistence.restore_device_config can't bring
                    # the stale ID back on the next launch.
                    print(f"Backend does not recognise device {dev_id} — "
                          "clearing local state and re-prompting for pairing.")
                    try: os.remove(CONFIG_FILE)
                    except Exception: pass
                    try:
                        subprocess.run(
                            ["reg", "delete",
                             r"HKCU\Software\PhantomTrace", "/f"],
                            capture_output=True,
                            creationflags=NO_WINDOW if IS_WINDOWS else 0,
                        )
                    except Exception: pass
                except Exception as _ve:
                    # Backend unreachable — give the stored ID the benefit of
                    # the doubt (offline-first). We retry at every launch, so
                    # the next online launch will resolve it.
                    print(f"Could not verify device_id with backend "
                          f"({_ve}) — assuming valid for now.")
                    print(f"Device ID: {dev_id}")
                    return dev_id, config.get('beacon_id', '')
            else:
                print("device.json exists but has no device_id — reprompting for pairing.")
                try: os.remove(CONFIG_FILE)
                except Exception: pass
        except Exception as e:
            print(f"device.json unreadable ({e}) — reprompting for pairing.")
            try: os.remove(CONFIG_FILE)
            except Exception: pass

    device_name = socket.gethostname()

    # (2a) Silent pairing via env var (for scripted enterprise installs)
    env_code = (os.getenv('PHANTOMTRACE_PAIR_CODE') or '').strip()
    if env_code:
        try:
            r = requests.post(f"{BASE_URL}/api/device/pair",
                              json={"code": env_code, "device_name": device_name},
                              timeout=15)
            if r.status_code == 201:
                d = r.json()
                with open(CONFIG_FILE, 'w') as f:
                    json.dump({"device_id": d["device_id"],
                               "beacon_id": d.get("beacon_id", ""),
                               "user_id":   d.get("user_id", "")}, f)
                print(f"Paired via env code: {d['device_id']}")
                return d["device_id"], d.get("beacon_id", "")
            print(f"Env-code pair failed: {r.status_code} {r.text[:120]}")
        except Exception as e:
            print(f"Env-code pair error: {e}")

    # (2b) Legacy owner-email fallback for single-user dev installs
    owner_email = os.getenv('PHANTOMTRACE_EMAIL', '')
    if owner_email:
        try:
            response = requests.post(f"{BASE_URL}/api/device/self-register",
                json={"device_name": device_name, "owner_email": owner_email},
                timeout=15)
            if response.status_code == 201:
                data = response.json()
                device_id = data['device_id']
                beacon_id = data.get('beacon_id', '')
                with open(CONFIG_FILE, 'w') as f:
                    json.dump({"device_id": device_id, "beacon_id": beacon_id}, f)
                print(f"Registered (legacy self-register): {device_id}")
                return device_id, beacon_id
            print(f"Legacy self-register refused: {response.status_code} {response.text[:120]}")
        except Exception as e:
            print(f"Legacy self-register error: {e}")

    # (2c) Show the pairing dialog
    print("First launch — showing pairing dialog")
    paired = _pair_via_dialog(device_name)
    if not paired:
        # Cancelled — exit cleanly. Raising an exception would surface as
        # an ugly "Unhandled exception in script" popup on the frozen .exe.
        print("Pairing cancelled by user. Restart the agent to try again.")
        sys.exit(0)
    device_id, beacon_id = paired
    with open(CONFIG_FILE, 'w') as f:
        json.dump({"device_id": device_id, "beacon_id": beacon_id}, f)
    print(f"Paired: {device_id}")
    return device_id, beacon_id

# ── System information reporters ───────────────────────────────────────────────
def send_system_info(device_id):
    info = {"device_id": device_id, "hostname": socket.gethostname(),
            "user": getpass.getuser(), "os": platform.system(),
            "version": platform.release()}
    r = requests.post(f"{BASE_URL}/api/device/systeminfo", json=info, timeout=10)
    print(f"SYSTEM_INFO: {r.status_code}")

def send_network_info(device_id):
    hostname = socket.gethostname()
    try:   ip = socket.gethostbyname(hostname)
    except: ip = "unknown"
    mac = ':'.join([format((uuid.getnode() >> ele) & 0xff, '02x')
                    for ele in range(0, 8*6, 8)][::-1])
    r = requests.post(f"{BASE_URL}/api/device/networkinfo",
        json={"device_id": device_id, "hostname": hostname,
              "ip_address": ip, "mac_address": mac}, timeout=10)
    print(f"NETWORK_INFO: {r.status_code}")

def send_disk_info(device_id):
    path = "C:\\" if IS_WINDOWS else "/"
    disk = shutil.disk_usage(path)
    r = requests.post(f"{BASE_URL}/api/device/diskinfo",
        json={"device_id": device_id,
              "total_gb": round(disk.total/(1024**3), 2),
              "used_gb":  round(disk.used /(1024**3), 2),
              "free_gb":  round(disk.free /(1024**3), 2)}, timeout=10)
    print(f"DISK_INFO: {r.status_code}")

def send_process_info(device_id):
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["tasklist","/FO","CSV","/NH"], text=True, errors="ignore", creationflags=NO_WINDOW)
            procs = list({line.split('","')[0].strip('"') for line in out.splitlines() if line.strip()})[:100]
        else:
            out = subprocess.check_output(["ps","-eo","comm"], text=True)
            procs = [p.strip() for p in out.splitlines()[1:] if p.strip()][:100]
        r = requests.post(f"{BASE_URL}/api/device/processes",
            json={"device_id": device_id, "processes": procs}, timeout=10)
        print(f"PROCESSES: {r.status_code}")
    except Exception as e:
        print(f"process_info error: {e}")

# ── Location consent + keep-on ────────────────────────────────────────────────
# With the owner's consent, PhantomTrace keeps Windows Location ON so a forgotten
# toggle can't defeat recovery. It asks ONCE; enabling the platform needs admin.
_REG_PT = r"Software\PhantomTrace"

def _loc_consent_get():
    if not IS_WINDOWS:
        return None
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PT)
        val, _ = winreg.QueryValueEx(k, "location_consent")
        winreg.CloseKey(k)
        return val
    except Exception:
        return None

def _loc_consent_set(v):
    try:
        import winreg
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, _REG_PT)
        winreg.SetValueEx(k, "location_consent", 0, winreg.REG_SZ, v)
        winreg.CloseKey(k)
    except Exception as e:
        print(f"consent store failed: {e}")

def _loc_prompt_consent():
    """Ask the owner (once) to allow always-on location. Returns True if allowed."""
    try:
        import ctypes
        MB_YESNO, MB_ICONQUESTION, IDYES = 0x4, 0x20, 6
        msg = ("PhantomTrace can keep Location turned ON so this laptop can be located "
               "if it is ever lost or stolen — even if you forget to switch it on.\n\n"
               "Allow PhantomTrace to keep Location enabled on this device?")
        r = ctypes.windll.user32.MessageBoxW(0, msg, "PhantomTrace - Location Permission",
                                             MB_YESNO | MB_ICONQUESTION)
        return r == IDYES
    except Exception as e:
        print(f"consent prompt failed: {e}")
        return False

def _loc_is_enabled():
    if not IS_WINDOWS:
        return True
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")
        val, _ = winreg.QueryValueEx(k, "Value")
        winreg.CloseKey(k)
        return val == "Allow"
    except Exception:
        return False

def _loc_enable_registry():
    """Turn on the location platform + app/desktop access. Needs admin; silent."""
    ok = False
    try:
        import winreg
        for path in (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged",
        ):
            try:
                k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
                winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ, "Allow")
                winreg.CloseKey(k); ok = True
            except Exception as e:
                print(f"loc consent reg failed ({path}): {e}")
        try:
            k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration")
            winreg.SetValueEx(k, "Status", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(k); ok = True
        except Exception as e:
            print(f"loc platform status failed: {e}")
    except Exception as e:
        print(f"enable location failed: {e}")
    return ok

_loc_settings_opened = False

def ensure_location(startup=False):
    """Consent once, then keep Windows Location enabled for the owner."""
    global _loc_settings_opened
    if not IS_WINDOWS:
        return
    consent = _loc_consent_get()
    if consent is None and startup:
        granted = _loc_prompt_consent()
        consent = "yes" if granted else "no"
        _loc_consent_set(consent)
        print(f"Location consent: {consent}")
    if consent != "yes":
        return
    if _loc_is_enabled():
        return
    if _loc_enable_registry():
        print("Location: enabled by PhantomTrace")
    elif startup and not _loc_settings_opened:
        # Not elevated — open the settings page once so the owner flips it.
        # Use os.startfile (ShellExecute under the hood) instead of os.system,
        # which would flash a cmd.exe window. Silent = no visible CMD popup.
        _loc_settings_opened = True
        try:
            os.startfile("ms-settings:privacy-location")
            print("Location: opened Windows settings for the owner to enable")
        except Exception:
            pass


# Cache so we don't spawn PowerShell on every call
_loc_cache = {"lat": None, "lon": None, "acc": None, "src": None, "ts": 0}

# Set this to your Google API key (Geolocation API enabled) for accurate Wi-Fi
# positioning. Read from env var so it isn't hard-coded in the repo.
GOOGLE_GEOLOCATION_KEY = os.getenv("GOOGLE_GEOLOCATION_KEY", "")


def _wifi_scan():
    """Nearby Wi-Fi access points as [{macAddress, signalStrength(dBm)}] (Windows)."""
    aps = []
    if not IS_WINDOWS:
        return aps
    try:
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                             capture_output=True, text=True, timeout=15,
                             creationflags=NO_WINDOW).stdout or ""
        cur = None
        for line in out.splitlines():
            s = line.strip()
            low = s.lower()
            if low.startswith("bssid") and ":" in s:
                mac = s.split(":", 1)[1].strip()
                cur = {"macAddress": mac}
            elif low.startswith("signal") and cur is not None and "%" in s:
                try:
                    pct = int(s.split(":", 1)[1].strip().replace("%", ""))
                    cur["signalStrength"] = int(pct / 2) - 100  # % -> approx dBm
                    aps.append(cur)
                except Exception:
                    pass
                cur = None
    except Exception as e:
        print(f"wifi scan failed: {e}")
    return aps


def get_wifi_location_google():
    """Accurate device location from nearby Wi-Fi via Google Geolocation API."""
    if not GOOGLE_GEOLOCATION_KEY:
        return None, None, None
    aps = _wifi_scan()
    try:
        payload = {"considerIp": True}
        if len(aps) >= 2:
            payload["wifiAccessPoints"] = aps
        r = requests.post(
            f"https://www.googleapis.com/geolocation/v1/geolocate?key={GOOGLE_GEOLOCATION_KEY}",
            json=payload, timeout=12)
        if r.status_code == 200:
            d = r.json()
            loc = d.get("location", {})
            return loc.get("lat"), loc.get("lng"), d.get("accuracy")
        print(f"google geolocate {r.status_code}: {r.text[:120]}")
    except Exception as e:
        print(f"google geolocate failed: {e}")
    return None, None, None


def get_windows_location():
    """Device location via Windows Location Service (falls back to IP internally)."""
    if not IS_WINDOWS:
        return None, None, None
    try:
        ps = (
            "Add-Type -AssemblyName System.Device;"
            "$w=New-Object System.Device.Location.GeoCoordinateWatcher;"
            "$w.Start();"
            "$n=0; while(($w.Status -ne [System.Device.Location.GeoPositionStatus]::Ready) "
            "-and ($n -lt 30)){Start-Sleep -Milliseconds 400; $n++};"
            "$c=$w.Position.Location;"
            "if($c.IsUnknown){'UNKNOWN'} else "
            "{'{0},{1},{2}' -f $c.Latitude,$c.Longitude,$c.HorizontalAccuracy};"
            "$w.Stop()"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW)
        val = (out.stdout or "").strip().splitlines()[-1].strip() if out.stdout else ""
        if val and val != "UNKNOWN" and "," in val:
            parts = val.split(",")
            acc = float(parts[2]) if len(parts) > 2 and parts[2] else None
            return float(parts[0]), float(parts[1]), acc
    except Exception as e:
        print(f"windows location failed: {e}")
    return None, None, None


def get_precise_location(max_age=60):
    """
    Best available device location, in priority order:
      1. Google Geolocation (Wi-Fi scan)  — best coverage in East Africa
      2. Windows Location Service          — Wi-Fi/IP, coverage-dependent
    Returns (lat, lon, accuracy_m); sets _loc_cache['src'] to the method used.
    """
    if _loc_cache["lat"] is not None and (time.time() - _loc_cache["ts"] < max_age):
        return _loc_cache["lat"], _loc_cache["lon"], _loc_cache["acc"]
    lat, lon, acc, src = None, None, None, None
    g_lat, g_lon, g_acc = get_wifi_location_google()
    if g_lat is not None:
        lat, lon, acc, src = g_lat, g_lon, g_acc, "WIFI-GOOGLE"
    else:
        w_lat, w_lon, w_acc = get_windows_location()
        if w_lat is not None:
            lat, lon, acc, src = w_lat, w_lon, w_acc, "WIN-LOC"
    if lat is not None:
        _loc_cache.update({"lat": lat, "lon": lon, "acc": acc, "src": src, "ts": time.time()})
        return lat, lon, acc
    return None, None, None


def secure_data(device_id):
    """Encrypt the owner's vault folders; generate + register a key if needed."""
    if not _HAS_VAULT:
        print("Data vault unavailable"); return
    try:
        cfg = triggers.fetch_config(device_id) if _HAS_TRIGGERS else {}
        key = cfg.get("vault_key")
        if not key:
            key = datavault.new_key()
            requests.post(f"{BASE_URL}/api/device/vault-key",
                          json={"device_id": device_id, "key": key}, timeout=10)
            print("Vault: generated and registered new key")
        n = datavault.protect(key)
        print(f"Vault: encrypted {n} file(s)")
    except Exception as e:
        print(f"secure_data error: {e}")

def restore_data(device_id):
    """Decrypt the owner's vault folders using the stored key."""
    if not _HAS_VAULT:
        print("Data vault unavailable"); return
    try:
        cfg = triggers.fetch_config(device_id) if _HAS_TRIGGERS else {}
        key = cfg.get("vault_key")
        if not key:
            print("Vault: no key on record — nothing to restore"); return
        n = datavault.restore(key)
        print(f"Vault: decrypted {n} file(s)")
    except Exception as e:
        print(f"restore_data error: {e}")


# ── T8: BitLocker orchestration + instant crypto-erase ────────────────────────
def report_bitlocker_status(device_id):
    """Send the current BitLocker status of every volume to the backend."""
    if not _HAS_BITLOCKER:
        return
    try:
        volumes = bitlocker.status_all()
        requests.post(f"{BASE_URL}/api/device/bitlocker-status",
                      json={"device_id": device_id, "volumes": volumes},
                      timeout=10)
        for v in volumes:
            print(f"BitLocker {v['volume']}: {v['protection']} / {v['conversion']}")
    except Exception as e:
        print(f"bitlocker status report failed: {e}")


def escrow_bitlocker_key(device_id, letter="C:"):
    """
    Add PhantomTrace's own recovery-password protector to the given volume
    and upload the 48-digit recovery key to the backend so the owner can
    recover data after a wipe or hardware failure. Idempotent.
    """
    if not _HAS_BITLOCKER:
        print("BitLocker module unavailable"); return
    try:
        if bitlocker.has_escrowed_key():
            print("BitLocker: key already escrowed — skipping")
            return
        rec = bitlocker.add_recovery_password_protector(letter)
        if not rec:
            print(f"BitLocker: could not add recovery protector on {letter}")
            return
        r = requests.post(f"{BASE_URL}/api/device/bitlocker-key",
                          json={"device_id": device_id,
                                "volume":    letter,
                                "key_id":    rec["key_id"],
                                "recovery_key": rec["recovery_key"]},
                          timeout=15)
        if r.status_code < 400:
            bitlocker.mark_escrowed(rec["key_id"])
            print(f"BitLocker: recovery key escrowed for {letter}")
        else:
            print(f"BitLocker key escrow rejected: {r.status_code} {r.text[:120]}")
    except Exception as e:
        print(f"escrow_bitlocker_key error: {e}")


def enable_bitlocker(device_id, letter="C:"):
    """Turn BitLocker on for the volume, then escrow the key."""
    if not _HAS_BITLOCKER:
        print("BitLocker module unavailable"); return
    try:
        st = bitlocker.status_for_volume(letter)
        if st["protection"] == "On":
            print(f"BitLocker already ON for {letter}")
        else:
            ok = bitlocker.enable(letter)
            if not ok:
                triggers.send_alert(device_id, "BitLocker enable failed",
                    f"Could not turn on BitLocker for {letter} — may need admin.")
                return
            print(f"BitLocker enable requested for {letter}")
        escrow_bitlocker_key(device_id, letter)
        report_bitlocker_status(device_id)
    except Exception as e:
        print(f"enable_bitlocker error: {e}")


def instant_wipe(device_id):
    """
    The INSTANT_WIPE command. Crypto-erase the system volume by deleting
    every BitLocker key protector, then reboot. After this, the drive is
    unreadable unless the owner has the recovery key from the backend.

    ONLY runs if the device is marked STOLEN on the backend AND BitLocker
    is currently ON. Refuses in every other case to avoid an accidental
    self-destruct.
    """
    if not _HAS_BITLOCKER:
        print("INSTANT_WIPE refused: BitLocker module unavailable"); return
    try:
        # Safety gate 1: server-side status must be STOLEN
        cfg = triggers.fetch_config(device_id) if _HAS_TRIGGERS else {}
        if cfg.get("status") != "STOLEN":
            print("INSTANT_WIPE refused: device is not marked STOLEN on server")
            triggers.send_alert(device_id, "Instant wipe refused",
                "The device is not marked STOLEN. Mark it first, then re-issue.")
            return
        # Safety gate 2: BitLocker must be ON (otherwise there is nothing
        # to crypto-erase — falling through would leave the drive fully
        # readable). Fall back to the legacy overwrite wipe in that case.
        st = bitlocker.status_for_volume("C:")
        if st["protection"] != "On":
            print("INSTANT_WIPE: BitLocker OFF — falling back to overwrite wipe")
            wipe_user_data()
            triggers.send_alert(device_id, "Overwrite wipe running",
                "BitLocker was OFF on this device. Files being deleted instead. "
                "Enable BitLocker to get instant crypto-erase in future.")
            return
        # Do the deed
        triggers.send_alert(device_id, "Instant wipe engaged",
            "Crypto-erase in progress. Drive will be unreadable after reboot.")
        ok = bitlocker.crypto_erase("C:")
        if ok:
            print("INSTANT_WIPE: crypto-erase complete, rebooting")
        else:
            print("INSTANT_WIPE: crypto-erase failed")
    except Exception as e:
        print(f"instant_wipe error: {e}")


def send_location(device_id):
    try:
        # ISP/IP lookup gives city / country / ISP / public IP (network context)
        geo = {}
        try:
            geo = requests.get(
                "http://ip-api.com/json/?fields=lat,lon,city,regionName,country,isp,query,zip,district",
                timeout=8).json()
        except Exception as ge:
            print(f"ip geo failed: {ge}")

        # Prefer the REAL device location; fall back to ISP coordinates
        plat, plon, pacc = get_precise_location()
        if plat is not None:
            lat, lon, source = plat, plon, (_loc_cache.get("src") or "DEVICE")
        else:
            lat, lon, source = geo.get("lat"), geo.get("lon"), "ISP"

        area = geo.get("district") or geo.get("regionName") or ""
        if lat is not None and lon is not None:
            try:
                nom = requests.get(
                    f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1",
                    headers={"User-Agent": "PhantomTrace/1.0"}, timeout=6).json()
                addr = nom.get("address", {})
                area = (addr.get("suburb") or addr.get("neighbourhood") or addr.get("quarter")
                        or addr.get("city_district") or addr.get("district")
                        or addr.get("county") or geo.get("regionName") or "")
            except Exception as ne:
                print(f"Nominatim fallback: {ne}")
        city    = geo.get("city", "")
        country = geo.get("country", "")
        full_area = f"{area}, {city}" if area and area != city else city
        r = requests.post(f"{BASE_URL}/api/device/location",
            json={"device_id": device_id, "latitude": lat, "longitude": lon,
                  "city": city, "country": country, "isp": geo.get("isp"),
                  "ip_address": geo.get("query"), "area": full_area,
                  "source": source, "accuracy": pacc}, timeout=10)
        acc_txt = f" ~{int(pacc)}m" if pacc else ""
        print(f"LOCATION [{source}{acc_txt}]: {r.status_code} — {full_area}, {country}")
    except Exception as e:
        print(f"location error: {e}")

def auto_report(device_id):
    print("--- Auto-report ---")
    for fn in [send_system_info, send_network_info, send_disk_info, send_process_info, send_location]:
        try: fn(device_id)
        except Exception as e: print(f"{fn.__name__} error: {e}")
    # T8: also report BitLocker status so the owner can see it in the app
    try: report_bitlocker_status(device_id)
    except Exception as e: print(f"bitlocker status error: {e}")
    print("--- Done ---")

# ── Command handlers ───────────────────────────────────────────────────────────
def lock_device():
    try:
        if IS_WINDOWS:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            print("LOCKED via LockWorkStation")
        else:
            env = os.environ.copy()
            env['DISPLAY'] = ':0'
            subprocess.run(["xset","s","activate"], env=env, capture_output=True, check=False)
            print("LOCKED via xset")
    except Exception as e:
        print(f"Lock failed: {e}")

# ── Alarm: force-max-volume + synthesized irritating two-tone siren ───────────
#
# The old alarm used console beeps that were quiet, polite, and completely
# useless when the thief had already turned the volume down. This rewrite:
#   1. Forces the Windows master volume to 100% and unmutes BEFORE playing,
#      using pycaw (hardware mixer access, same thing the volume slider uses).
#   2. Synthesizes a loud two-tone siren WAV directly (no ffmpeg needed, no
#      external files). Frequency swings between ~700 Hz and ~1400 Hz every
#      0.4s to produce the deliberately irritating "police siren" feel.
#   3. Plays it with winsound in LOOP mode so it never stops until the owner
#      sends STOP_ALARM or the device is unlocked.
#   4. Re-asserts max volume every 2 seconds — if the thief frantically grabs
#      the volume slider, it snaps back up within 2s.
def _force_max_volume_windows():
    """Set master volume to 100% and unmute. Hardware level, bypasses UI."""
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        volume.SetMute(0, None)
        volume.SetMasterVolumeLevelScalar(1.0, None)
    except Exception as e:
        print(f"Volume force failed: {e}")

def _synthesize_siren_wav(path, duration_seconds=6):
    """Write a looping two-tone siren WAV to `path`. 22.05 kHz, 16-bit mono.
    Sweeps between ~700 Hz and ~1400 Hz every 0.4s. Harmonically layered so it
    sounds grating and attention-grabbing, not musical."""
    import wave, math, struct
    rate = 22050
    n = int(rate * duration_seconds)
    amp = 32000  # near-max 16-bit
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        frames = bytearray()
        for i in range(n):
            t = i / rate
            # Sweep 700 Hz <-> 1400 Hz on 0.4s period
            phase = (t % 0.4) / 0.4
            freq = 700 + 700 * phase if int(t / 0.4) % 2 == 0 else 1400 - 700 * phase
            # Fundamental + 2nd harmonic for the grating "siren" feel
            s = math.sin(2 * math.pi * freq * t) * 0.7
            s += math.sin(2 * math.pi * freq * 2 * t) * 0.3
            val = int(s * amp)
            if val > 32767: val = 32767
            if val < -32768: val = -32768
            frames.extend(struct.pack("<h", val))
        w.writeframes(bytes(frames))

def trigger_alarm(device_id):
    global _alarm_active
    _alarm_active = True

    def _alarm_windows():
        try:
            import winsound
            siren_path = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"),
                                      "pt_siren.wav")
            # (Re-)synthesize each time the alarm fires so a thief who deleted
            # the previous WAV from TEMP can't disable the alarm.
            try:
                _synthesize_siren_wav(siren_path, duration_seconds=6)
            except Exception as e:
                print(f"Siren synth failed, falling back to beeps: {e}")
                while _alarm_active:
                    winsound.Beep(1000, 500)
                    winsound.Beep(1400, 500)
                return

            # Force volume BEFORE playing so the first second is already loud.
            _force_max_volume_windows()
            # SND_LOOP + SND_ASYNC = plays in background, loops forever until
            # we call PlaySound(None, SND_PURGE) in stop_alarm().
            winsound.PlaySound(siren_path,
                               winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP)

            # Re-assert volume every 2s in case the thief tries to mute.
            while _alarm_active:
                time.sleep(2)
                _force_max_volume_windows()
        except Exception as e:
            print(f"Alarm (win) error: {e}")

    def _alarm_linux():
        try:
            alarm_file = "/tmp/pt_alarm.wav"
            try:
                _synthesize_siren_wav(alarm_file, duration_seconds=6)
            except Exception:
                subprocess.run([
                    "ffmpeg", "-y", "-f", "lavfi",
                    "-i", "sine=frequency=1000:duration=6", alarm_file
                ], capture_output=True, check=False)
            env = os.environ.copy()
            env['DISPLAY'] = ':0'
            subprocess.run(["amixer", "sset", "Master", "100%", "unmute"],
                           capture_output=True, check=False)
            while _alarm_active:
                subprocess.run(["ffplay", "-nodisp", "-autoexit", "-volume", "100",
                                alarm_file], env=env, capture_output=True, check=False)
        except Exception as e:
            print(f"Alarm (linux) error: {e}")

    threading.Thread(
        target=_alarm_windows if IS_WINDOWS else _alarm_linux,
        daemon=True
    ).start()
    lock_device()
    print("ALARM TRIGGERED (max volume, looping siren)")

def stop_alarm():
    global _alarm_active
    _alarm_active = False
    if IS_WINDOWS:
        try:
            import winsound
            # Purge the looping siren immediately.
            winsound.PlaySound(None, winsound.SND_PURGE)
        except Exception as e:
            print(f"winsound purge failed: {e}")
        # Belt-and-braces: kill any lingering ffplay from older alarm paths.
        subprocess.run(["taskkill", "/F", "/IM", "ffplay.exe"],
                       check=False, capture_output=True, creationflags=NO_WINDOW)
        subprocess.run(["taskkill", "/F", "/IM", "ffplay_g.exe"],
                       check=False, capture_output=True, creationflags=NO_WINDOW)
    else:
        subprocess.run(["pkill", "-f", "ffplay"], check=False)
        subprocess.run(["pkill", "-f", "aplay"],  check=False)
        subprocess.run(["pkill", "-f", "paplay"], check=False)
    print("ALARM STOPPED")

def take_photo():
    try:
        import cv2
        tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "pt_webcam.jpg")
        for idx in range(4):
            cam = cv2.VideoCapture(idx)
            time.sleep(0.5)
            ret, frame = cam.read()
            cam.release()
            if ret:
                cv2.imwrite(tmp, frame)
                print(f"Webcam captured at index {idx}")
                return tmp
        print("No webcam found")
    except Exception as e:
        print(f"Photo error: {e}")
    return None

def take_screenshot():
    try:
        if IS_WINDOWS:
            from PIL import ImageGrab
            tmp = os.path.join(os.environ.get("TEMP", "."), f"pt_screenshot_{int(time.time())}.jpg")
            ImageGrab.grab().save(tmp, "JPEG")
            return tmp
        else:
            tmp = f"/tmp/pt_screenshot_{int(time.time())}.jpg"
            import glob
            xauth_files = (glob.glob("/run/user/*/xauthority") +
                           glob.glob("/tmp/.xauth*") +
                           glob.glob("/root/.Xauthority") +
                           glob.glob("/home/*/.Xauthority"))
            xauth = next((f for f in xauth_files if os.path.exists(f)), None)
            env = os.environ.copy()
            env['DISPLAY'] = ':0'
            if xauth: env['XAUTHORITY'] = xauth
            for cmd in [["gnome-screenshot","-f",tmp], ["scrot",tmp], ["import","-window","root",tmp]]:
                try:
                    r = subprocess.run(cmd, env=env, capture_output=True, timeout=15)
                    if r.returncode == 0 and os.path.exists(tmp):
                        print(f"Screenshot: {cmd[0]}")
                        return tmp
                except Exception: pass
    except Exception as e:
        print(f"Screenshot error: {e}")
    return None

def record_audio(device_id, duration=30):
    """Record {duration} seconds of microphone audio and upload."""
    try:
        tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "pt_audio.wav")
        if IS_WINDOWS:
            # Use ffmpeg with DirectShow
            result = subprocess.run([
                "ffmpeg","-y","-f","dshow","-i","audio=Microphone Array (Realtek)",
                "-t", str(duration), tmp
            ], capture_output=True, timeout=duration+15, creationflags=NO_WINDOW)
            if result.returncode != 0:
                # Fallback: list devices and use first available
                subprocess.run(["ffmpeg","-y","-f","dshow","-i","audio=Microphone",
                    "-t", str(duration), tmp], capture_output=True, timeout=duration+15, creationflags=NO_WINDOW)
        else:
            subprocess.run(["ffmpeg","-y","-f","alsa","-i","default",
                "-t", str(duration), tmp], capture_output=True, timeout=duration+15)
        if os.path.exists(tmp):
            with open(tmp, 'rb') as f:
                r = requests.post(f"{BASE_URL}/api/evidence/audio",
                    files={"audio": f}, data={"device_id": device_id}, timeout=60)
            print(f"AUDIO SENT: {r.status_code}")
            try: os.remove(tmp)
            except: pass
        else:
            print("Audio capture produced no file")
    except Exception as e:
        print(f"Audio error: {e}")

def wipe_user_data():
    """
    Remove user files from standard locations.
    Called only on WIPE command (requires confirmed=true from mobile app).
    """
    if IS_WINDOWS:
        home = os.environ.get('USERPROFILE', '')
        targets = ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos']
        dirs_to_wipe = [os.path.join(home, t) for t in targets]
    else:
        home = os.path.expanduser('~')
        targets = ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos']
        dirs_to_wipe = [os.path.join(home, t) for t in targets]

    for d in dirs_to_wipe:
        if os.path.exists(d):
            try:
                shutil.rmtree(d)
                os.makedirs(d)   # recreate empty folder
                print(f"Wiped: {d}")
            except Exception as e:
                print(f"Wipe failed for {d}: {e}")
    print("WIPE complete")

def send_evidence(device_id, filename, photo_type):
    if filename and os.path.exists(filename):
        with open(filename, 'rb') as f:
            r = requests.post(f"{BASE_URL}/api/evidence/photo",
                files={"photo": f},
                data={"device_id": device_id, "photo_type": photo_type},
                timeout=60)
        print(f"{photo_type} SENT: {r.status_code}")
        try: os.remove(filename)
        except: pass

# ── Shutdown protection ────────────────────────────────────────────────────────
def on_shutdown_signal(device_id, signum=None, frame=None):
    """Called when OS signals shutdown / reboot / Ctrl+C."""
    print(f"Shutdown signal received ({signum})")

    # T-SHUTDOWN: if the device is under deterrent lock, actively block the
    # shutdown regardless of what the backend says. The overlay + registry
    # already hid the Power button, but a scripted `shutdown /s` still
    # reaches us here — abort it.
    locally_locked = False
    if _HAS_DETERRENT:
        try:
            locally_locked = deterrent_lock.is_locked()
        except Exception:
            pass

    if locally_locked and IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.advapi32.AbortSystemShutdownW(None)
            print("Shutdown BLOCKED — device is under PhantomTrace deterrent lock")
        except Exception as e:
            print(f"AbortSystemShutdown (local) failed: {e}")
        # Also tell the owner that someone tried to power it off
        try:
            requests.post(f"{BASE_URL}/api/device/alert",
                json={"device_id": device_id,
                      "title": "Shutdown attempt blocked",
                      "body":  "Someone tried to shut down your locked device. "
                               "Location is still active."},
                timeout=6)
        except Exception:
            pass
        return

    # Otherwise: existing behavior — ask the backend if we should resist
    try:
        r = requests.post(f"{BASE_URL}/api/device/shutdown-alert",
            json={"device_id": device_id, "reason": "SHUTDOWN_SIGNAL"}, timeout=8)
        data = r.json()
        if data.get('resist'):
            # Device is STOLEN — fire a SILENT forensic burst (webcam shot of
            # the thief, screenshot of what they were doing, last location),
            # then try to abort the shutdown. We DO NOT sound the alarm here:
            # a loud siren at the moment of shutdown would push the thief to
            # physically destroy the device before our uploads finish, and
            # the thief isn't near the owner anyway so no one would hear it.
            print("Device is STOLEN — resisting shutdown + capturing evidence (silent)")

            # Fire the burst in background threads so we don't block the
            # AbortSystemShutdown call — we have seconds, not minutes.
            def _burst_webcam():
                try:
                    fp = take_photo()
                    if fp: send_evidence(device_id, fp, "WEBCAM")
                except Exception as be: print(f"shutdown webcam burst: {be}")
            def _burst_screen():
                try:
                    fp = take_screenshot()
                    if fp: send_evidence(device_id, fp, "SCREENSHOT")
                except Exception as be: print(f"shutdown screen burst: {be}")
            def _burst_loc():
                try: send_location(device_id)
                except Exception as be: print(f"shutdown loc burst: {be}")
            for fn in (_burst_webcam, _burst_screen, _burst_loc):
                threading.Thread(target=fn, daemon=True).start()

            if IS_WINDOWS:
                try:
                    import ctypes
                    ctypes.windll.advapi32.AbortSystemShutdownW(None)
                    print("Shutdown aborted via AbortSystemShutdownW")
                except Exception as e:
                    print(f"AbortSystemShutdown failed: {e}")
    except Exception as e:
        print(f"Shutdown alert failed: {e}")

def setup_shutdown_protection(device_id):
    """Register shutdown/terminate signal handlers."""
    if IS_WINDOWS:
        try:
            import win32api, win32con
            def _handler(event):
                if event in (win32con.CTRL_SHUTDOWN_EVENT, win32con.CTRL_LOGOFF_EVENT,
                             win32con.CTRL_CLOSE_EVENT):
                    on_shutdown_signal(device_id)
                    return True  # Handled
                return False
            win32api.SetConsoleCtrlHandler(_handler, True)
            print("Windows shutdown protection active")
        except Exception as e:
            print(f"Windows shutdown handler failed: {e}")
    else:
        # Linux/Mac: hook SIGTERM and SIGHUP
        for sig in [signal.SIGTERM, signal.SIGHUP]:
            signal.signal(sig, lambda s, f: on_shutdown_signal(device_id, s, f))
        print("Unix shutdown protection active (SIGTERM/SIGHUP)")

# ── Watchdog mode ────────────────────────────────────────────────────────────
# Launched as "…--watchdog" (by persistence.ensure_watchdog): run only the
# watchdog loop, which relaunches the agent if it dies, then exit.
if _HAS_PERSISTENCE and "--watchdog" in sys.argv:
    persistence.run_watchdog()
    sys.exit(0)

# ── Main loop ──────────────────────────────────────────────────────────────────
print("PhantomTrace Agent starting...")

# T1 persistence: only one agent at a time; restore config; keep the watchdog up
if _HAS_PERSISTENCE:
    if not persistence.single_instance():
        print("Another PhantomTrace agent is already running - exiting this copy.")
        sys.exit(0)
    persistence.restore_device_config(CONFIG_FILE)   # rebuild device.json if deleted

DEVICE_ID, BEACON_ID = get_or_register_device()

if _HAS_PERSISTENCE:
    persistence.backup_device_config(CONFIG_FILE)    # keep a registry copy
    persistence.ensure_watchdog()                    # make sure the watchdog is up

setup_shutdown_protection(DEVICE_ID)
ensure_location(startup=True)   # ask consent once, then keep Location on

# ── BIOS wizard: tell the backend what laptop model this is so the mobile
# app can show the right instructions for setting a BIOS password.
if _HAS_BIOS_WIZARD:
    try:
        mfg, mdl = bios_wizard.detect_model()
        bios_info = bios_wizard.steps_for(mfg, mdl)
        requests.post(f"{BASE_URL}/api/device/bios-info",
                      json={"device_id": DEVICE_ID,
                            "manufacturer": mfg,
                            "model": mdl,
                            "enter_key": bios_info['enter_key'],
                            "fallback_key": bios_info['fallback_key'],
                            "steps": bios_info['steps']},
                      timeout=10)
        print(f"[bios] reported model: {mfg} / {mdl}")
    except Exception as _bw_err:
        print(f"[bios] model report failed: {_bw_err}")

# ── Mark the device stolen from the agent side ────────────────────────────
# Used by factory_reset_detector when it catches the thief hitting
# Settings → Reset this PC. Flipping status server-side triggers push
# notifications to the owner's phone and switches the agent into aggressive
# tracking mode.
def mark_self_stolen(device_id, reason="agent-detected-trigger"):
    try:
        r = requests.post(f"{BASE_URL}/api/device/self-mark-stolen",
                          json={"device_id": device_id, "reason": reason,
                                "beacon_id": BEACON_ID},
                          timeout=10)
        print(f"[auto-stolen] marked via agent ({reason}): {r.status_code}")
    except Exception as e:
        print(f"[auto-stolen] failed: {e}")

# ── T-FACTORY-RESET-DETECT: watch for Settings → Reset this PC ────────────
try:
    import factory_reset_detector as _frd
    _frd.start_factory_reset_watcher(sys.modules[__name__], DEVICE_ID)
    print("[factory-reset] watcher armed")
except Exception as _fe:
    print(f"[factory-reset] watcher NOT armed: {_fe}")

# T4: if the device rebooted while under deterrent lock, put the overlay back
if _HAS_DETERRENT:
    try: deterrent_lock.restore_on_boot()
    except Exception as _re: print(f"deterrent restore failed: {_re}")

# T8: if BitLocker is already ON but we haven't escrowed a key yet, do it now.
# This is idempotent — bitlocker.has_escrowed_key() short-circuits repeats.
if _HAS_BITLOCKER:
    try:
        _st = bitlocker.status_for_volume("C:")
        if _st.get("protection") == "On" and not bitlocker.has_escrowed_key():
            escrow_bitlocker_key(DEVICE_ID, "C:")
    except Exception as _be: print(f"bitlocker startup escrow error: {_be}")

auto_report(DEVICE_ID)

AUTO_REPORT_INTERVAL = 60   # seconds between full auto-reports
last_report = time.time()
LOCATION_ASSERT_INTERVAL = 300   # re-assert Location every 5 min
last_loc_assert = time.time()

# ── T2 trigger state ─────────────────────────────────────────────────────────
TRIGGER_INTERVAL       = 30   # seconds between automatic-trigger checks
FAILED_LOGIN_THRESHOLD = 3    # failed unlocks in the window before we react
last_trigger_check = 0
last_fail_alert    = 0
_stolen_handled    = False

while True:
    try:
        # T1 persistence: prove we're alive, keep the watchdog up, obey stop flag
        if _HAS_PERSISTENCE:
            if persistence.should_stop():
                print("Stop flag present - agent exiting cleanly.")
                break
            persistence.touch_heartbeat()   # tell the watchdog we're alive
            persistence.ensure_watchdog()   # relaunch the watchdog if it died

        # Keep Location on (silent; only if the owner consented and we're elevated)
        if time.time() - last_loc_assert >= LOCATION_ASSERT_INTERVAL:
            last_loc_assert = time.time()
            ensure_location(startup=False)

        # Heartbeat
        hb = requests.post(f"{BASE_URL}/api/device/heartbeat",
            json={"device_id": DEVICE_ID}, timeout=8)
        print(f"Heartbeat: {hb.status_code}")

        # T7: record a successful heartbeat so the offline-lock clock resets
        if _HAS_TRIGGERS and hb.status_code < 500:
            try: triggers.mark_heartbeat_ok()
            except Exception: pass

        # ── Last-online snapshot ────────────────────────────────────────────
        # If the device is STOLEN and we've just come online after being
        # offline for 60+ seconds (think: thief powered it off then on, or
        # it was out of network range), fire a SILENT forensic burst — one
        # webcam shot + one screenshot + a fresh location. This catches the
        # moment the thief first interacts with the laptop after taking it.
        # No alarm (same reasoning as the shutdown trap).
        try:
            if hb.status_code == 200:
                hb_data = hb.json()
                is_stolen_now = hb_data.get('status') == 'STOLEN'
                now = time.time()
                _last_hb_ok = globals().get('_last_hb_ok', now)
                offline_gap = now - _last_hb_ok
                globals()['_last_hb_ok'] = now
                _last_snapshot_ts = globals().get('_last_snapshot_ts', 0)
                # Fire if stolen + offline > 60s + last snapshot > 2 min ago
                if (is_stolen_now and offline_gap > 60
                        and (now - _last_snapshot_ts) > 120):
                    globals()['_last_snapshot_ts'] = now
                    print(f"[last-online] Device came online after {int(offline_gap)}s "
                          "offline while STOLEN — firing silent evidence burst")
                    def _lo_webcam():
                        try:
                            fp = take_photo()
                            if fp: send_evidence(DEVICE_ID, fp, "WEBCAM")
                        except Exception as be: print(f"last-online webcam: {be}")
                    def _lo_screen():
                        try:
                            fp = take_screenshot()
                            if fp: send_evidence(DEVICE_ID, fp, "SCREENSHOT")
                        except Exception as be: print(f"last-online screen: {be}")
                    def _lo_loc():
                        try: send_location(DEVICE_ID)
                        except Exception as be: print(f"last-online loc: {be}")
                    for fn in (_lo_webcam, _lo_screen, _lo_loc):
                        threading.Thread(target=fn, daemon=True).start()
        except Exception as _loe:
            print(f"last-online snapshot check error: {_loe}")

        # Auto-report every minute
        if time.time() - last_report >= AUTO_REPORT_INTERVAL:
            auto_report(DEVICE_ID)
            last_report = time.time()

        # Poll for pending commands
        resp = requests.get(f"{BASE_URL}/api/command/pending/{DEVICE_ID}", timeout=8)
        if resp.status_code == 200:
            commands = resp.json().get("commands", [])
            for cmd in commands:
                ctype = cmd["command_type"]
                cid   = cmd["id"]
                print(f"▶ Command: {ctype}")

                if ctype == "PING":
                    print("Alive")

                elif ctype == "LOCK":
                    lock_device()

                elif ctype == "ALARM":
                    trigger_alarm(DEVICE_ID)

                elif ctype == "STOP_ALARM":
                    stop_alarm()

                elif ctype == "PHOTO":
                    f = take_photo()
                    send_evidence(DEVICE_ID, f, "WEBCAM")

                elif ctype == "SCREENSHOT":
                    f = take_screenshot()
                    send_evidence(DEVICE_ID, f, "SCREENSHOT")

                elif ctype == "AUDIO":
                    threading.Thread(
                        target=record_audio, args=(DEVICE_ID, 30), daemon=True
                    ).start()

                elif ctype == "WIPE":
                    wipe_user_data()

                elif ctype == "SYSTEM_INFO":
                    send_system_info(DEVICE_ID)

                elif ctype == "GET_NETWORK":
                    send_network_info(DEVICE_ID)

                elif ctype == "GET_DISKS":
                    send_disk_info(DEVICE_ID)

                elif ctype == "GET_PROCESSES":
                    send_process_info(DEVICE_ID)

                elif ctype == "GET_LOCATION":
                    send_location(DEVICE_ID)

                elif ctype == "SECURE_DATA":
                    secure_data(DEVICE_ID)

                elif ctype == "RESTORE_DATA":
                    restore_data(DEVICE_ID)

                elif ctype == "DETERRENT_LOCK":
                    # T4: full-screen deterrent lock with owner's message.
                    # The command carries a JSON payload:
                    #   { "message": "...", "unlock_code": "1234" }
                    if _HAS_DETERRENT:
                        try:
                            payload = cmd.get("payload") or {}
                            if isinstance(payload, str):
                                try: payload = json.loads(payload)
                                except Exception: payload = {}
                            msg  = payload.get("message", "").strip() \
                                   or "This device has been reported stolen."
                            code = str(payload.get("unlock_code", "")).strip() \
                                   or "0000"
                            deterrent_lock.activate(msg, DEVICE_ID, code)
                        except Exception as _de:
                            print(f"DETERRENT_LOCK failed: {_de}")
                    else:
                        print("Deterrent lock module unavailable")

                elif ctype == "UNLOCK_DETERRENT":
                    if _HAS_DETERRENT:
                        deterrent_lock.deactivate()
                    else:
                        print("Deterrent lock module unavailable")

                # T8: BitLocker orchestration + instant crypto-erase wipe
                elif ctype == "BITLOCKER_STATUS":
                    report_bitlocker_status(DEVICE_ID)

                elif ctype == "ENABLE_BITLOCKER":
                    # Optional payload: {"volume": "C:"} — defaults to C:
                    letter = "C:"
                    try:
                        payload = cmd.get("payload") or {}
                        if isinstance(payload, str):
                            try: payload = json.loads(payload)
                            except Exception: payload = {}
                        letter = payload.get("volume", "C:") or "C:"
                    except Exception:
                        pass
                    enable_bitlocker(DEVICE_ID, letter)

                elif ctype == "INSTANT_WIPE":
                    # Irreversible. See instant_wipe() for its safety gates.
                    instant_wipe(DEVICE_ID)

                elif ctype == "USB_LOCKDOWN":
                    # Disable USB mass storage via Windows registry. Thief
                    # can't plug in a drive to copy files out.
                    if _HAS_USB_LOCKDOWN:
                        usb_lockdown.lock_usb_storage()
                    else:
                        print("USB lockdown module unavailable")

                elif ctype == "USB_UNLOCKDOWN":
                    # Owner marked device Found — re-enable USB storage.
                    if _HAS_USB_LOCKDOWN:
                        usb_lockdown.unlock_usb_storage()
                    else:
                        print("USB lockdown module unavailable")

                elif ctype == "AGENT_UNINSTALL":
                    # Owner deleted this device from the mobile app.
                    # Acknowledge the command FIRST (so the backend knows
                    # we received it and can delete the DB row), then
                    # tear down persistence + delete our files + exit.
                    print("AGENT_UNINSTALL received — acknowledging then self-destructing")
                    try:
                        requests.post(f"{BASE_URL}/api/command/acknowledge/{cid}", timeout=6)
                        requests.post(f"{BASE_URL}/api/command/result",
                            json={"device_id": DEVICE_ID,
                                  "command_type": ctype,
                                  "result": "SUCCESS"},
                            timeout=6)
                    except Exception as _ack_err:
                        print(f"AGENT_UNINSTALL ack failed (continuing anyway): {_ack_err}")
                    if _HAS_SELF_DESTRUCT:
                        self_destruct.perform_self_destruct()
                    # Fallback: at least raise the stop flag so the
                    # watchdog doesn't resurrect us.
                    try:
                        if _HAS_PERSISTENCE:
                            with open(persistence.STOP_FLAG, "w") as _f:
                                _f.write("stop")
                    except Exception: pass
                    sys.exit(0)

                # Acknowledge command
                requests.post(f"{BASE_URL}/api/command/acknowledge/{cid}", timeout=8)
                requests.post(f"{BASE_URL}/api/command/result",
                    json={"device_id": DEVICE_ID, "command_type": ctype, "result": "SUCCESS"},
                    timeout=8)
                print(f"✓ Acknowledged: {cid}")
                print("-" * 40)
        else:
            print("No pending commands")

        # ── T2: automatic triggers (every TRIGGER_INTERVAL seconds) ──────────
        if _HAS_TRIGGERS and (time.time() - last_trigger_check >= TRIGGER_INTERVAL):
            last_trigger_check = time.time()
            try:
                cfg = triggers.fetch_config(DEVICE_ID)
                status = cfg.get("status", "SAFE")
                pub_ip, iplat, iplng = triggers.get_ip_and_location()

                # Prefer the real device location for geofencing; fall back to IP
                plat, plon, _acc = get_precise_location()
                lat = plat if plat is not None else iplat
                lng = plon if plon is not None else iplng

                # 1) new network / public-IP change
                triggers.check_network_change(DEVICE_ID, pub_ip)

                # 2) left the safe zone (uses precise location when available)
                triggers.check_geofence(DEVICE_ID, cfg, lat, lng)

                # 3) repeated failed logins (Windows, best effort)
                fails = triggers.check_failed_logins()
                if fails >= FAILED_LOGIN_THRESHOLD and (time.time() - last_fail_alert > 300):
                    last_fail_alert = time.time()
                    try:
                        pf = take_photo(); send_evidence(DEVICE_ID, pf, "WEBCAM")
                    except Exception as _pe:
                        print(f"trigger photo failed: {_pe}")
                    triggers.send_alert(DEVICE_ID, "Repeated failed logins",
                        f"{fails} failed unlock attempts detected — photo captured.")

                # 4) stolen response — act once, then keep a location trail
                if status == "STOLEN":
                    if not _stolen_handled:
                        _stolen_handled = True
                        print("AUTO: stolen response engaging")
                        try: lock_device()
                        except Exception as e: print(f"auto-lock failed: {e}")
                        try:
                            pf = take_photo(); send_evidence(DEVICE_ID, pf, "WEBCAM")
                        except Exception as e: print(f"auto-photo failed: {e}")
                        send_location(DEVICE_ID)
                        triggers.send_alert(DEVICE_ID, "Stolen response active",
                            "Device locked and evidence captured automatically.")
                    else:
                        send_location(DEVICE_ID)   # ongoing evidence trail
                else:
                    _stolen_handled = False

                # 5) T7: offline auto-lock. If the agent has been unable to
                #    reach the backend for >= threshold minutes, lock the
                #    workstation locally. Defeats the thief who yanks Wi-Fi.
                try:
                    if triggers.check_offline_lock(DEVICE_ID, cfg):
                        try: lock_device()
                        except Exception as e: print(f"T7 lock failed: {e}")
                        # Queue an alert; it will send when connectivity returns
                        try:
                            triggers.send_alert(DEVICE_ID, "Offline auto-lock",
                                "Your device was offline too long and has been "
                                "locked automatically for safety.")
                        except Exception: pass
                except Exception as _oe:
                    print(f"T7 check error: {_oe}")
            except Exception as _te:
                print(f"trigger cycle error: {_te}")

    except requests.exceptions.ConnectionError:
        print("No internet — will retry")
    except Exception as e:
        print(f"Loop error: {e}")

    time.sleep(3)
