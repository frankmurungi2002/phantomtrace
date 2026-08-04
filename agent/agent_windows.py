import requests
import time
import platform
import socket
import getpass
import uuid
import shutil
import subprocess
import os
import json
import sys
import threading

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device.json')
BASE_URL = "https://phantomtrace-backend-c0if.onrender.com"

def get_or_register_device():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
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
    requests.post(f"{BASE_URL}/api/device/systeminfo", json=info)

def send_network_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac = ':'.join([
        format((uuid.getnode() >> ele) & 0xff, '02x')
        for ele in range(0, 8*6, 8)
    ][::-1])
    requests.post(f"{BASE_URL}/api/device/networkinfo", json={
        "device_id": DEVICE_ID,
        "hostname": hostname,
        "ip_address": ip_address,
        "mac_address": mac
    })

def send_disk_info():
    disk = shutil.disk_usage("C:\\")
    requests.post(f"{BASE_URL}/api/device/diskinfo", json={
        "device_id": DEVICE_ID,
        "total_gb": round(disk.total / (1024**3), 2),
        "used_gb": round(disk.used / (1024**3), 2),
        "free_gb": round(disk.free / (1024**3), 2)
    })

def send_process_info():
    output = subprocess.check_output(["tasklist", "/fo", "csv", "/nh"], text=True)
    processes = []
    for line in output.splitlines():
        if line.strip():
            parts = line.strip('"').split('","')
            if parts:
                processes.append(parts[0])
    processes = list(set(processes))[:100]
    requests.post(f"{BASE_URL}/api/device/processes", json={
        "device_id": DEVICE_ID,
        "processes": processes
    })

def send_location():
    try:
        geo = requests.get(
            "http://ip-api.com/json/?fields=lat,lon,city,regionName,country,isp,query",
            timeout=5
        ).json()
        lat = geo.get("lat")
        lon = geo.get("lon")
        try:
            nom = requests.get(
                f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json&addressdetails=1",
                headers={"User-Agent": "PhantomTrace/1.0"},
                timeout=5
            ).json()
            addr = nom.get("address", {})
            area = (addr.get("suburb") or addr.get("neighbourhood") or
                    addr.get("quarter") or addr.get("city_district") or
                    addr.get("district") or addr.get("county") or
                    geo.get("regionName") or "")
        except:
            area = geo.get("regionName", "")
        city = geo.get("city", "")
        full_area = f"{area}, {city}" if area and area != city else city
        requests.post(f"{BASE_URL}/api/device/location", json={
            "device_id": DEVICE_ID,
            "latitude": lat,
            "longitude": lon,
            "city": city,
            "country": geo.get("country"),
            "isp": geo.get("isp"),
            "ip_address": geo.get("query"),
            "area": full_area
        })
    except Exception as e:
        pass

def lock_device():
    try:
        import ctypes
        ctypes.windll.user32.LockWorkStation()
    except Exception as e:
        pass

def set_volume_max():
    try:
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume = cast(interface, POINTER(IAudioEndpointVolume))
        volume.SetMasterVolumeLevelScalar(1.0, None)
        volume.SetMute(0, None)
    except Exception as e:
        try:
            subprocess.run(
                ["powershell", "-c",
                 "$obj = New-Object -ComObject WScript.Shell; "
                 "1..50 | ForEach-Object { $obj.SendKeys([char]175) }"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except:
            pass

_alarm_running = False

def play_alarm():
    global _alarm_running
    _alarm_running = True
    import winsound
    import tempfile
    # Generate WAV alarm using subprocess ffmpeg if available, else use winsound beep
    alarm_file = os.path.join(tempfile.gettempdir(), "pt_alarm.wav")
    try:
        subprocess.run([
            "ffmpeg", "-y", "-f", "lavfi",
            "-i", "sine=frequency=1000:duration=30",
            alarm_file
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except:
        alarm_file = None

    while _alarm_running:
        try:
            set_volume_max()
            if alarm_file and os.path.exists(alarm_file):
                winsound.PlaySound(alarm_file, winsound.SND_FILENAME | winsound.SND_ASYNC)
            else:
                winsound.Beep(1000, 500)
            # Re-lock screen every 0.5s
            lock_device()
            time.sleep(0.5)
        except Exception as e:
            time.sleep(1)

def take_screenshot():
    try:
        from PIL import ImageGrab
        import tempfile
        filename = os.path.join(tempfile.gettempdir(), f"pt_screenshot_{int(time.time())}.jpg")
        screenshot = ImageGrab.grab()
        screenshot.save(filename, "JPEG")
        return filename
    except Exception as e:
        return None

def take_webcam_photo():
    try:
        import cv2
        for idx in range(4):
            cap = cv2.VideoCapture(idx)
            time.sleep(0.5)
            ret, frame = cap.read()
            cap.release()
            if ret:
                import tempfile
                filename = os.path.join(tempfile.gettempdir(), f"pt_webcam_{int(time.time())}.jpg")
                cv2.imwrite(filename, frame)
                return filename
        return None
    except:
        return None

def auto_report():
    try: send_system_info()
    except: pass
    try: send_network_info()
    except: pass
    try: send_disk_info()
    except: pass
    try: send_process_info()
    except: pass
    try: send_location()
    except: pass

DEVICE_ID = get_or_register_device()

auto_report()

AUTO_REPORT_INTERVAL = 60
last_report_time = time.time()

while True:
    try:
        hb = requests.post(f"{BASE_URL}/api/device/heartbeat", json={"device_id": DEVICE_ID})

        if time.time() - last_report_time >= AUTO_REPORT_INTERVAL:
            auto_report()
            last_report_time = time.time()

        response = requests.get(f"{BASE_URL}/api/command/pending/{DEVICE_ID}")

        if response.status_code == 200:
            data = response.json()
            if data["commands"]:
                for cmd in data["commands"]:
                    if cmd["command_type"] == "PING":
                        pass

                    elif cmd["command_type"] == "LOCK":
                        lock_device()

                    elif cmd["command_type"] == "ALARM":
                        _alarm_running = True
                        t = threading.Thread(target=play_alarm, daemon=True)
                        t.start()

                    elif cmd["command_type"] == "STOP_ALARM":
                        _alarm_running = False
                        try:
                            import winsound
                            winsound.PlaySound(None, winsound.SND_ASYNC)
                        except:
                            pass

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

                    elif cmd["command_type"] == "SCREENSHOT":
                        filename = take_screenshot()
                        if filename:
                            with open(filename, "rb") as f:
                                requests.post(
                                    f"{BASE_URL}/api/evidence/photo",
                                    files={"photo": f},
                                    data={"device_id": DEVICE_ID, "photo_type": "SCREENSHOT"}
                                )
                            os.remove(filename)

                    elif cmd["command_type"] == "PHOTO":
                        filename = take_webcam_photo()
                        if filename:
                            with open(filename, "rb") as f:
                                requests.post(
                                    f"{BASE_URL}/api/evidence/photo",
                                    files={"photo": f},
                                    data={"device_id": DEVICE_ID, "photo_type": "WEBCAM"}
                                )
                            os.remove(filename)

                    requests.post(f"{BASE_URL}/api/command/acknowledge/{cmd['id']}")
                    requests.post(
                        f"{BASE_URL}/api/command/result",
                        json={"device_id": DEVICE_ID, "command_type": cmd["command_type"], "result": "SUCCESS"}
                    )

    except Exception as e:
        pass

    time.sleep(3)
