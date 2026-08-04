import subprocess
import sys
import platform as _platform_check

def _ensure_dependencies():
    required = ["requests", "opencv-python"]
    if _platform_check.system() == "Windows":
        required += ["pycaw", "comtypes", "pillow"]

    import importlib
    import_names = {
        "requests": "requests",
        "opencv-python": "cv2",
        "pycaw": "pycaw",
        "comtypes": "comtypes",
        "pillow": "PIL",
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

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

if getattr(sys, 'frozen', False):
    # Running as PyInstaller exe
    CONFIG_FILE = os.path.join(os.path.dirname(sys.executable), 'device.json')
else:
    # Running as script
    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device.json')
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
    path = "C:\\" if IS_WINDOWS else "/"
    disk = shutil.disk_usage(path)
    r = requests.post(f"{BASE_URL}/api/device/diskinfo", json={
        "device_id": DEVICE_ID,
        "total_gb": round(disk.total / (1024**3), 2),
        "used_gb": round(disk.used / (1024**3), 2),
        "free_gb": round(disk.free / (1024**3), 2)
    })
    print(f"DISK_INFO sent: {r.status_code}")

def send_process_info():
    try:
        if IS_WINDOWS:
            output = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, errors="ignore")
            processes = []
            for line in output.splitlines():
                if line.strip():
                    name = line.split('","')[0].strip('"')
                    if name:
                        processes.append(name)
            processes = list(set(processes))[:100]
        else:
            output = subprocess.check_output(["ps", "-eo", "comm"], text=True)
            processes = [p.strip() for p in output.splitlines()[1:] if p.strip()][:100]

        r = requests.post(f"{BASE_URL}/api/device/processes", json={
            "device_id": DEVICE_ID,
            "processes": processes
        })
        print(f"PROCESSES sent: {r.status_code}")
    except Exception as e:
        print(f"process_info error: {e}")

def send_location():
    try:
        geo = requests.get(
            "http://ip-api.com/json/?fields=lat,lon,city,regionName,country,isp,query,zip,district",
            timeout=5
        ).json()
        lat = geo.get("lat")
        lon = geo.get("lon")
        area = geo.get("district") or geo.get("regionName") or ""
        try:
            nom = requests.get(
                f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1",
                headers={"User-Agent": "PhantomTrace/1.0"},
                timeout=5
            ).json()
            addr = nom.get("address", {})
            area = (
                addr.get("suburb") or addr.get("neighbourhood") or
                addr.get("quarter") or addr.get("city_district") or
                addr.get("district") or addr.get("county") or
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
        if IS_WINDOWS:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            print("DEVICE LOCKED via LockWorkStation")
        else:
            env = os.environ.copy()
            env['DISPLAY'] = ':0'
            env['XAUTHORITY'] = '/tmp/pt_xauth'
            subprocess.run(["xset", "s", "activate"], env=env,
                capture_output=True, check=False)
            print("DEVICE LOCKED via xset")
    except Exception as e:
        print(f"Lock failed: {e}")

def take_screenshot():
    try:
        if IS_WINDOWS:
            from PIL import ImageGrab
            import tempfile
            filename = os.path.join(tempfile.gettempdir(), f"pt_screenshot_{int(time.time())}.jpg")
            img = ImageGrab.grab()
            img.save(filename, "JPEG")
        else:
            filename = f"/tmp/pt_screenshot_{int(time.time())}.jpg"
            # Find correct XAUTHORITY file
            import glob
            xauth_files = glob.glob("/run/user/*/xauthority") +                           glob.glob("/tmp/.xauth*") +                           glob.glob("/root/.Xauthority") +                           glob.glob("/home/*/.Xauthority")
            xauth = next((f for f in xauth_files if os.path.exists(f)), None)
            env = os.environ.copy()
            env['DISPLAY'] = ':0'
            if xauth:
                env['XAUTHORITY'] = xauth
                print(f"Using XAUTHORITY: {xauth}")
            # Use gnome-screenshot or scrot with proper env
            taken = False
            for cmd_try in [
                ["gnome-screenshot", "-f", filename],
                ["scrot", filename],
                ["import", "-window", "root", filename],
            ]:
                try:
                    r = subprocess.run(cmd_try, env=env, 
                        capture_output=True, timeout=15)
                    if r.returncode == 0 and os.path.exists(filename):
                        taken = True
                        print(f"Screenshot taken with {cmd_try[0]}")
                        break
                except Exception as ex:
                    print(f"{cmd_try[0]} failed: {ex}")
            if not taken:
                raise Exception("All screenshot methods failed")
        return filename
    except Exception as e:
        print(f"Screenshot error: {e}")
        return None

def take_photo():
    try:
        import cv2
        if IS_WINDOWS:
            tmp = os.path.join(os.environ.get("TEMP", "."), "pt_webcam.jpg")
        else:
            tmp = "/tmp/pt_webcam.jpg"

        for cam_index in range(4):
            try:
                camera = cv2.VideoCapture(cam_index)
                time.sleep(0.5)
                ret, frame = camera.read()
                camera.release()
                if ret:
                    cv2.imwrite(tmp, frame)
                    print(f"Webcam captured at index {cam_index}")
                    return tmp
            except Exception:
                pass
        print("No webcam found")
        return None
    except Exception as e:
        print(f"Photo error: {e}")
        return None

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

                    elif cmd["command_type"] == "LOCK":
                        lock_device()

                    elif cmd["command_type"] == "STOP_ALARM":
                        subprocess.run(["pkill", "-f", "ffplay"], check=False)
                        subprocess.run(["pkill", "-f", "aplay"], check=False)
                        subprocess.run(["pkill", "-f", "paplay"], check=False)
                        print("ALARM STOPPED")

                    elif cmd["command_type"] == "ALARM":
                        import threading
                        def alarm_thread():
                            try:
                                env = os.environ.copy()
                                env['DISPLAY'] = ':0'
                                env['XAUTHORITY'] = '/tmp/pt_xauth'
                                env['XDG_RUNTIME_DIR'] = '/run/user/1000'
                                env['PULSE_RUNTIME_PATH'] = '/run/user/1000/pulse'
                                env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/run/user/1000/bus'
                                # Generate alarm sound
                                alarm_file = "/tmp/pt_alarm.wav"
                                subprocess.run([
                                    "ffmpeg", "-y", "-f", "lavfi",
                                    "-i", "sine=frequency=1000:duration=30",
                                    alarm_file
                                ], capture_output=True, check=False)
                                # Max volume via multiple methods
                                subprocess.run(["amixer", "sset", "Master", "100%", "unmute"],
                                    capture_output=True, check=False)
                                subprocess.run(
                                    ["su", "francis", "-c",
                                     "XDG_RUNTIME_DIR=/run/user/1000 wpctl set-volume @DEFAULT_AUDIO_SINK@ 1.0"],
                                    capture_output=True, check=False
                                )
                                # Play alarm 5 times using ffplay
                                for _ in range(5):
                                    subprocess.run([
                                        "ffplay", "-nodisp", "-autoexit",
                                        "-volume", "100", alarm_file
                                    ], env=env, capture_output=True, check=False)
                            except Exception as e:
                                print(f"Alarm error: {e}")
                        threading.Thread(target=alarm_thread, daemon=True).start()
                        lock_device()
                        print("ALARM TRIGGERED")

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
                        filename = take_photo()
                        if filename:
                            with open(filename, "rb") as photo_file:
                                r = requests.post(
                                    f"{BASE_URL}/api/evidence/photo",
                                    files={"photo": photo_file},
                                    data={"device_id": DEVICE_ID, "photo_type": "WEBCAM"}
                                )
                            print("WEBCAM PHOTO SENT:", r.status_code)
                            try: os.remove(filename)
                            except: pass

                    elif cmd["command_type"] == "SCREENSHOT":
                        filename = take_screenshot()
                        if filename:
                            with open(filename, "rb") as screen_file:
                                r = requests.post(
                                    f"{BASE_URL}/api/evidence/photo",
                                    files={"photo": screen_file},
                                    data={"device_id": DEVICE_ID, "photo_type": "SCREENSHOT"}
                                )
                            print("SCREENSHOT SENT:", r.status_code)
                            try: os.remove(filename)
                            except: pass

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
