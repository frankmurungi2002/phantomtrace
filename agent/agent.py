"""
PhantomTrace Agent
==================
Runs silently on a protected laptop. On first launch it self-registers with
the backend, then polls for commands every 3 seconds and sends heartbeats.

Supports: LOCK, ALARM, STOP_ALARM, PHOTO, SCREENSHOT, AUDIO, WIPE,
          PING, SYSTEM_INFO, GET_NETWORK, GET_DISKS, GET_PROCESSES, GET_LOCATION
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

_ensure_dependencies()

import requests, time, platform, socket, getpass, uuid, shutil, json, math, signal, threading

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

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
            out = subprocess.check_output(["tasklist","/FO","CSV","/NH"], text=True, errors="ignore")
            procs = list({line.split('","')[0].strip('"') for line in out.splitlines() if line.strip()})[:100]
        else:
            out = subprocess.check_output(["ps","-eo","comm"], text=True)
            procs = [p.strip() for p in out.splitlines()[1:] if p.strip()][:100]
        r = requests.post(f"{BASE_URL}/api/device/processes",
            json={"device_id": device_id, "processes": procs}, timeout=10)
        print(f"PROCESSES: {r.status_code}")
    except Exception as e:
        print(f"process_info error: {e}")

def send_location(device_id):
    try:
        geo = requests.get(
            "http://ip-api.com/json/?fields=lat,lon,city,regionName,country,isp,query,zip,district",
            timeout=8).json()
        lat, lon = geo.get("lat"), geo.get("lon")
        area = geo.get("district") or geo.get("regionName") or ""
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
                  "ip_address": geo.get("query"), "area": full_area}, timeout=10)
        print(f"LOCATION: {r.status_code} — {full_area}, {country}")
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
                    subprocess.run(["powershell","-Command", ps_script], capture_output=True, timeout=10)
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
    subprocess.run(["pkill","-f","ffplay"], check=False)
    subprocess.run(["pkill","-f","aplay"],  check=False)
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
            ], capture_output=True, timeout=duration+15)
            if result.returncode != 0:
                # Fallback: list devices and use first available
                subprocess.run(["ffmpeg","-y","-f","dshow","-i","audio=Microphone",
                    "-t", str(duration), tmp], capture_output=True, timeout=duration+15)
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

# ── Main loop ──────────────────────────────────────────────────────────────────
print("PhantomTrace Agent starting...")
DEVICE_ID, BEACON_ID = get_or_register_device()
setup_shutdown_protection(DEVICE_ID)
auto_report(DEVICE_ID)

AUTO_REPORT_INTERVAL = 60   # seconds between full auto-reports
last_report = time.time()

while True:
    try:
        # Heartbeat
        hb = requests.post(f"{BASE_URL}/api/device/heartbeat",
            json={"device_id": DEVICE_ID}, timeout=8)
        print(f"Heartbeat: {hb.status_code}")

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

                # Acknowledge command
                requests.post(f"{BASE_URL}/api/command/acknowledge/{cid}", timeout=8)
                requests.post(f"{BASE_URL}/api/command/result",
                    json={"device_id": DEVICE_ID, "command_type": ctype, "result": "SUCCESS"},
                    timeout=8)
                print(f"✓ Acknowledged: {cid}")
                print("-" * 40)
        else:
            print("No pending commands")

    except requests.exceptions.ConnectionError:
        print("No internet — will retry")
    except Exception as e:
        print(f"Loop error: {e}")

    time.sleep(3)
