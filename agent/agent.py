"""
PhantomTrace Agent
==================
Runs silently on a protected laptop. On first launch it self-registers with
the backend, then polls for commands every 3 seconds and sends heartbeats.

Supports: LOCK, ALARM, STOP_ALARM, PHOTO, SCREENSHOT, AUDIO, WIPE,
          PING, SYSTEM_INFO, GET_NETWORK, GET_DISKS, GET_PROCESSES, GET_LOCATION,
          SECURE_DATA, RESTORE_DATA, DETERRENT_LOCK, UNLOCK_DETERRENT
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

if getattr(sys, 'frozen', False):
    CONFIG_FILE = os.path.join(os.path.dirname(sys.executable), 'device.json')
else:
    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device.json')

BASE_URL = "https://phantomtrace-backend-c0if.onrender.com"

# ── Shutdown protection globals ────────────────────────────────────────────────
_shutdown_blocked = False
_alarm_active     = False

# ── Device registration ────────────────────────────────────────────────────────
def get_or_register_device():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        print(f"Device ID: {config['device_id']}")
        return config['device_id'], config.get('beacon_id', '')

    device_name = socket.gethostname()
    # Pass the owner's email if you want the device linked to a specific account
    # Set PHANTOMTRACE_EMAIL env var or hardcode here during deployment
    owner_email = os.getenv('PHANTOMTRACE_EMAIL', '')
    response = requests.post(f"{BASE_URL}/api/device/self-register",
        json={"device_name": device_name, "owner_email": owner_email},
        timeout=15)
    if response.status_code == 201:
        data = response.json()
        device_id = data['device_id']
        beacon_id = data.get('beacon_id', '')
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"device_id": device_id, "beacon_id": beacon_id}, f)
        print(f"Registered: {device_id} | beacon: {beacon_id}")
        return device_id, beacon_id
    raise Exception(f"Registration failed: {response.text}")

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
        # Not elevated — open the settings page once so the owner flips it
        _loc_settings_opened = True
        try:
            os.system("start ms-settings:privacy-location")
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

def trigger_alarm(device_id):
    global _alarm_active
    _alarm_active = True
    def _alarm():
        try:
            if IS_WINDOWS:
                # Windows: generate and play alarm using PowerShell
                ps_script = r"""
[console]::beep(1000, 500)
$player = New-Object System.Media.SoundPlayer
for ($i=0; $i -lt 30; $i++) { [console]::beep(1000+($i*50), 200) }
"""
                for _ in range(5):
                    if not _alarm_active: break
                    subprocess.run(["powershell","-Command", ps_script], capture_output=True, timeout=10, creationflags=NO_WINDOW)
            else:
                # Linux: use ffmpeg to generate a siren wav then play it
                alarm_file = "/tmp/pt_alarm.wav"
                subprocess.run([
                    "ffmpeg","-y","-f","lavfi",
                    "-i","sine=frequency=1000:duration=30", alarm_file
                ], capture_output=True, check=False)
                current_user = getpass.getuser()
                env = os.environ.copy()
                env['DISPLAY'] = ':0'
                # Raise volume
                subprocess.run(["amixer","sset","Master","100%","unmute"],
                    capture_output=True, check=False)
                for _ in range(5):
                    if not _alarm_active: break
                    subprocess.run(["ffplay","-nodisp","-autoexit","-volume","100", alarm_file],
                        env=env, capture_output=True, check=False)
        except Exception as e:
            print(f"Alarm error: {e}")
    threading.Thread(target=_alarm, daemon=True).start()
    lock_device()
    print("ALARM TRIGGERED")

def stop_alarm():
    global _alarm_active
    _alarm_active = False
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/F", "/IM", "ffplay.exe"],  check=False, capture_output=True, creationflags=NO_WINDOW)
        subprocess.run(["taskkill", "/F", "/IM", "ffplay_g.exe"],check=False, capture_output=True, creationflags=NO_WINDOW)
    else:
        subprocess.run(["pkill","-f","ffplay"], check=False)
        subprocess.run(["pkill","-f","aplay"],  check=False)
        subprocess.run(["pkill","-f","paplay"], check=False)
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
            # Device is STOLEN — try to block shutdown and trigger alarm
            print("Device is STOLEN — resisting shutdown!")
            trigger_alarm(device_id)
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

# T4: if the device rebooted while under deterrent lock, put the overlay back
if _HAS_DETERRENT:
    try: deterrent_lock.restore_on_boot()
    except Exception as _re: print(f"deterrent restore failed: {_re}")

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
