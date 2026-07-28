import requests
import time
import platform
import socket
import getpass
import uuid
import shutil

DEVICE_ID = "bad8b4b5-1b2c-4de5-a3db-a575eaafac43"

while True:
    try:
        hb = requests.post(
            "http://127.0.0.1:5000/api/device/heartbeat",
            json={"device_id": DEVICE_ID}
        )

        print("Heartbeat:", hb.status_code)

        response = requests.get(
            f"http://127.0.0.1:5000/api/command/pending/{DEVICE_ID}"
        )

        if response.status_code == 200:
            data = response.json()

            if data["commands"]:

                for cmd in data["commands"]:

                    print("Received:", cmd["command_type"])

                    if cmd["command_type"] == "PING":
                        print("Device Alive")

                    elif cmd["command_type"] == "SYSTEM_INFO":

                        info = {
                            "device_id": DEVICE_ID,
                            "hostname": socket.gethostname(),
                            "user": getpass.getuser(),
                            "os": platform.system(),
                            "version": platform.release()
                        }

                        requests.post(
                            "http://127.0.0.1:5000/api/device/systeminfo",
                            json=info
                        )

                        print("SYSTEM_INFO sent")

                    elif cmd["command_type"] == "GET_NETWORK":

                        hostname = socket.gethostname()
                        ip_address = socket.gethostbyname(hostname)

                        mac = ':'.join([
                            format((uuid.getnode() >> ele) & 0xff, '02x')
                            for ele in range(0, 8*6, 8)
                        ][::-1])

                        network_info = {
                            "device_id": DEVICE_ID,
                            "hostname": hostname,
                            "ip_address": ip_address,
                            "mac_address": mac
                        }

                        requests.post(
                            "http://127.0.0.1:5000/api/device/networkinfo",
                            json=network_info
                        )

                        print("NETWORK INFO SENT")

                    elif cmd["command_type"] == "GET_DISKS":

                        disk = shutil.disk_usage("/")

                        disk_info = {
                            "device_id": DEVICE_ID,
                            "total_gb": round(disk.total / (1024**3), 2),
                            "used_gb": round(disk.used / (1024**3), 2),
                            "free_gb": round(disk.free / (1024**3), 2)
                        }

                        requests.post(
                            "http://127.0.0.1:5000/api/device/diskinfo",
                            json=disk_info
                        )

                        print("DISK INFO SENT")
                        print(disk_info)


                    elif cmd["command_type"] == "GET_PROCESSES":

                        import subprocess

                        output = subprocess.check_output(
                            ["ps", "-eo", "comm"],
                            text=True
                        )

                        processes = [
                            p.strip()
                            for p in output.splitlines()[1:]
                            if p.strip()
                        ][:100]

                        requests.post(
                            "http://127.0.0.1:5000/api/device/processes",
                            json={
                                "device_id": DEVICE_ID,
                                "processes": processes
                            }
                        )

                        print("PROCESSES SENT")
                        print("Count:", len(processes))

                    elif cmd["command_type"] == "SCREENSHOT":

                        import pyautogui

                        filename = "/tmp/screenshot.png"

                        pyautogui.screenshot().save(filename)

                        files = {
                            "photo": open(filename, "rb")
                        }

                        data = {
                            "device_id": DEVICE_ID
                        }

                        r = requests.post(
                            "http://127.0.0.1:5000/api/evidence/photo",
                            files=files,
                            data=data
                        )

                        print("SCREENSHOT SENT:", r.status_code)


                    requests.post(
                        f"http://127.0.0.1:5000/api/command/acknowledge/{cmd['id']}"
                    )

                    requests.post(
                        "http://127.0.0.1:5000/api/command/result",
                        json={
                            "device_id": DEVICE_ID,
                            "command_type": cmd["command_type"],
                            "result": "SUCCESS"
                        }
                    )

                    print("Acknowledged:", cmd["id"])
                    print("-" * 40)

            else:
                print("No pending commands")

    except Exception as e:
        print("Exception:", e)

    time.sleep(10)
# NOTE: PHOTO handler is added inside the command loop above
# Run this to patch agent.py with webcam support
