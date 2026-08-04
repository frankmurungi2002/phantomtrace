import subprocess
import sys
import platform as _platform_check

def _ensure_dependencies():
    """Auto-install missing dependencies on first run, cross-platform."""
    required = ["requests", "opencv-python"]
    if _platform_check.system() == "Windows":
        required += ["pycaw", "comtypes"]

    import importlib
    import_names = {
        "requests": "requests",
        "opencv-python": "cv2",
        "pycaw": "pycaw",
        "comtypes": "comtypes",
    }

    missing = []
    for pkg in required:
        mod_name = import_names.get(pkg, pkg)
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"Installing missing dependencies: {missing}")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
            check=False
        )
        print("Dependency install complete.")

_ensure_dependencies()

import requests
import time
import platform
import socket
import getpass
import uuid
import shutil
import os
import json

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'device.json')
BASE_URL = "https://phantomtrace-backend-c0if.onrender.com"

def get_or_register_device():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            print(f"Device ID loaded: {config['device_id']}")
            return config['device_id']

    device_name = socket.gethostname()
    response = requests.post(
        f"{BASE_URL}/api/device/self-register",
        json={"device_name": device_name}
    )
    if response.status_code == 201:
        device_id = response.json()['device_id']
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"device_id": device_id}, f)
        print(f"Device registered: {device_id}")
        return device_id
    else:
        raise Exception(f"Registration failed: {response.text}")

def send_system_info():
    info = {
        "device_id": DEVICE_ID,
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "os": platform.system(),
        "version": platform.release()
    }
    r = requests.post(f"{BASE_URL}/api/device/systeminfo", json=info)
    print(f"SYSTEM_INFO sent: {r.status_code}")

def send_network_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac = ':'.join([
        format((uuid.getnode() >> ele) & 0xff, '02x')
        for ele in range(0, 8*6, 8)
    ][::-1])
    r = requests.post(f"{BASE_URL}/api/device/networkinfo", json={
        "device_id": DEVICE_ID,
        "hostname": hostname,
        "ip_address": ip_address,
        "mac_address": mac
    })
    print(f"NETWORK_INFO sent: {r.status_code}")

def send_disk_info():
    disk = shutil.disk_usage("/")
    r = requests.post(f"{BASE_URL}/api/device/diskinfo", json={
        "device_id": DEVICE_ID,
        "total_gb": round(disk.total / (1024**3), 2),
        "used_gb": round(disk.used / (1024**3), 2),
        "free_gb": round(disk.free / (1024**3), 2)
    })
    print(f"DISK_INFO sent: {r.status_code}")

def send_process_info():
    output = subprocess.check_output(["ps", "-eo", "comm"], text=True)
    processes = [p.strip() for p in output.splitlines()[1:] if p.strip()][:100]
    r = requests.post(f"{BASE_URL}/api/device/processes", json={
        "device_id": DEVICE_ID,
        "processes": processes
    })
    print(f"PROCESSES sent: {r.status_code}")

def send_location():
    try:
        geo = requests.get("http://ip-api.com/json/?fields=lat,lon,city,regionName,country,isp,query,zip,district", timeout=5).json()
        lat = geo.get("lat")
        lon = geo.get("lon")

        # Get suburb/neighbourhood via Nominatim reverse geocoding
        area = geo.get("district") or geo.get("regionName") or ""
        try:
            nom = requests.get(
                f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1",
                headers={"User-Agent": "PhantomTrace/1.0"},
                timeout=5
            ).json()
            addr = nom.get("address", {})
            # Pick the most specific area name available
            area = (
                addr.get("suburb") or
                addr.get("neighbourhood") or
                addr.get("quarter") or
                addr.get("city_district") or
                addr.get("district") or
                addr.get("county") or
                geo.get("regionName") or ""
            )
        except Exception as ne:
            print(f"Nominatim fallback: {ne}")

        city = geo.get("city", "")
        country = geo.get("country", "")
        full_area = f"{area}, {city}" if area and area != city else city

        r = requests.post(f"{BASE_URL}/api/device/location", json={
            "device_id": DEVICE_ID,
            "latitude": lat,
            "longitude": lon,
            "city": city,
            "country": country,
            "isp": geo.get("isp"),
            "ip_address": geo.get("query"),
            "area": full_area
        })
        print(f"LOCATION sent: {r.status_code} — {full_area}, {country}")
    except Exception as e:
        print(f"location error: {e}")

def lock_device():
    try:
        subprocess.run(["loginctl", "lock-session"], check=False)
        print("DEVICE LOCKED via loginctl")
    except Exception:
        try:
            subprocess.run(["xdg-screensaver", "lock"], check=False)
            print("DEVICE LOCKED via xdg-screensaver")
        except Exception as e:
            print(f"Lock failed: {e}")


_alarm_running = False

def _set_volume(level):
    """Cross-platform volume set. level is 0.0-1.0."""
    system = platform.system()
    if system == "Linux":
        _set_volume_linux(level)
    elif system == "Windows":
        _set_volume_windows(level)
    elif system == "Darwin":
        _set_volume_macos(level)

def _set_volume_linux(level):
    # Try PipeWire first (works on most normal Linux setups)
    try:
        result = subprocess.run(
            ["su", "francis", "-c",
             f"XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus wpctl set-volume @DEFAULT_AUDIO_SINK@ {level}"],
            check=False, capture_output=True, text=True
        )
        if result.returncode == 0 and "error" not in (result.stderr or "").lower():
            return
    except Exception:
        pass
    # Fallback: raw ALSA amixer (covers machines where PipeWire routing is broken)
    try:
        pct = int(level * 100)
        subprocess.run(["amixer", "sset", "Master", f"{pct}%", "unmute"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["amixer", "sset", "Speaker", f"{pct}%", "unmute"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"Linux volume fallback error: {e}")

def _set_volume_windows(level):
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        volume.SetMasterVolumeLevelScalar(level, None)
    except Exception as e:
        print(f"Windows volume error (is pycaw installed? pip install pycaw comtypes): {e}")

def _set_volume_macos(level):
    try:
        pct = int(level * 100)
        subprocess.run(["osascript", "-e", f"set volume output volume {pct}"], check=False)
    except Exception as e:
        print(f"macOS volume error: {e}")

def _play_sound_linux(path):
    try:
        proc = subprocess.Popen(["ffplay", "-nodisp", "-autoexit", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc
    except Exception:
        try:
            proc = subprocess.Popen(["aplay", "-D", "plughw:0,0", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return proc
        except Exception as e:
            print(f"Linux playback error: {e}")
            return None

def _play_sound_windows(path):
    try:
        import winsound
        winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP)
        return "winsound"
    except Exception as e:
        print(f"Windows playback error: {e}")
        return None

def _play_sound_macos(path):
    try:
        proc = subprocess.Popen(["afplay", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc
    except Exception as e:
        print(f"macOS playback error: {e}")
        return None

def play_alarm():
    global _alarm_running
    _alarm_running = True
    system = platform.system()
    print(f"ALARM STARTED (OS: {system})")
    import time as _t

    if system == "Windows":
        alarm_file = os.path.join(os.environ.get("TEMP", "."), "pt_alarm.wav")
    else:
        alarm_file = "/tmp/pt_alarm.wav"

    try:
        subprocess.run([
            "ffmpeg", "-y", "-f", "lavfi",
            "-i", "sine=frequency=1000:duration=30",
            alarm_file
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception as e:
        print(f"ffmpeg not available, alarm may be silent: {e}")

    # Gradual ramp from 10% to 100% over ~5 seconds
    for step in [0.10, 0.25, 0.40, 0.55, 0.70, 0.85, 1.0]:
        _set_volume(step)
        _t.sleep(0.7)

    while _alarm_running:
        try:
            _set_volume(1.0)
            if system == "Linux":
                proc = _play_sound_linux(alarm_file)
            elif system == "Windows":
                proc = _play_sound_windows(alarm_file)
            elif system == "Darwin":
                proc = _play_sound_macos(alarm_file)
            else:
                proc = None

            if proc == "winsound":
                while _alarm_running:
                    _set_volume(1.0)
                    _t.sleep(1)
                import winsound
                winsound.PlaySound(None, winsound.SND_PURGE)
            elif proc is not None:
                while _alarm_running and proc.poll() is None:
                    _set_volume(1.0)
                    _t.sleep(1)
                proc.terminate()
            else:
                print("No playback method available on this OS")
                _t.sleep(2)
        except Exception as e:
            print(f"Alarm error: {e}")
            _t.sleep(1)
    print("ALARM STOPPED")

def auto_report():
    print("--- Auto-reporting device info ---")
    try: send_system_info()
    except Exception as e: print(f"system_info error: {e}")
    try: send_network_info()
    except Exception as e: print(f"network_info error: {e}")
    try: send_disk_info()
    except Exception as e: print(f"disk_info error: {e}")
    try: send_process_info()
    except Exception as e: print(f"process_info error: {e}")
    try: send_location()
    except Exception as e: print(f"location error: {e}")
    print("--- Auto-report done ---")

DEVICE_ID = get_or_register_device()

auto_report()

AUTO_REPORT_INTERVAL = 60
last_report_time = time.time()

while True:
    try:
        hb = requests.post(f"{BASE_URL}/api/device/heartbeat", json={"device_id": DEVICE_ID})
        print("Heartbeat:", hb.status_code)

        if time.time() - last_report_time >= AUTO_REPORT_INTERVAL:
            auto_report()
            last_report_time = time.time()

        response = requests.get(f"{BASE_URL}/api/command/pending/{DEVICE_ID}")

        if response.status_code == 200:
            data = response.json()
            if data["commands"]:
                for cmd in data["commands"]:
                    print("Received:", cmd["command_type"])

                    if cmd["command_type"] == "PING":
                        print("Device Alive")

                    elif cmd["command_type"] == "ALARM":
                        import threading
                        _alarm_running = True
                        t = threading.Thread(target=play_alarm, daemon=True)
                        t.start()
                        lock_device()
                        print("ALARM TRIGGERED")

                    elif cmd["command_type"] == "STOP_ALARM":
                        _alarm_running = False
                        subprocess.run(["pkill", "-f", "pw-cat"], check=False)
                        subprocess.run(["pkill", "-f", "pw-play"], check=False)
                        print("ALARM STOPPED")

                    elif cmd["command_type"] == "LOCK":
                        lock_device()

                    elif cmd["command_type"] == "SYSTEM_INFO":
                        send_system_info()

                    elif cmd["command_type"] == "GET_NETWORK":
                        send_network_info()

                    elif cmd["command_type"] == "GET_DISKS":
                        send_disk_info()

                    elif cmd["command_type"] == "GET_PROCESSES":
                        send_process_info()

                    elif cmd["command_type"] == "GET_LOCATION":
                        send_location()

                    elif cmd["command_type"] == "PHOTO":
                        import cv2
                        ret, frame = False, None
                        camera = None
                        for cam_index in range(4):
                            try:
                                camera = cv2.VideoCapture(cam_index)
                                time.sleep(0.5)
                                ret, frame = camera.read()
                                camera.release()
                                if ret:
                                    print(f"Webcam found at index {cam_index}")
                                    break
                            except Exception:
                                if camera:
                                    camera.release()
                        if ret and frame is not None:
                            filename = "/tmp/pt_webcam.jpg"
                            cv2.imwrite(filename, frame)
                            with open(filename, "rb") as photo_file:
                                r = requests.post(
                                    f"{BASE_URL}/api/evidence/photo",
                                    files={"photo": photo_file},
                                    data={"device_id": DEVICE_ID, "photo_type": "WEBCAM"}
                                )
                            print("WEBCAM PHOTO SENT:", r.status_code)
                        else:
                            print("Webcam not available on any index")

                    elif cmd["command_type"] == "SCREENSHOT":
                        import time as _time
                        filename = f"/tmp/pt_screenshot_{int(_time.time())}.jpg"
                        subprocess.run(["scrot", filename], check=True)
                        with open(filename, "rb") as screen_file:
                            r = requests.post(
                                f"{BASE_URL}/api/evidence/photo",
                                files={"photo": screen_file},
                                data={"device_id": DEVICE_ID, "photo_type": "SCREENSHOT"}
                            )
                        os.remove(filename)
                        print("SCREENSHOT SENT:", r.status_code)

                    requests.post(f"{BASE_URL}/api/command/acknowledge/{cmd['id']}")
                    requests.post(
                        f"{BASE_URL}/api/command/result",
                        json={"device_id": DEVICE_ID, "command_type": cmd["command_type"], "result": "SUCCESS"}
                    )
                    print("Acknowledged:", cmd["id"])
                    print("-" * 40)
            else:
                print("No pending commands")

    except Exception as e:
        print("Exception:", e)

    time.sleep(3)
