"""
PhantomTrace Automatic Triggers (T2)
====================================
Hands-off theft detection. The agent runs these checks on a timer and reacts
without the owner pressing anything:

  * network / public-IP change  -> alert the owner
  * geofence exit (safe zone)   -> alert the owner
  * repeated failed logins      -> (Windows, best effort) count 4625 events
  * device status               -> so the agent can auto-respond when STOLEN

This module only DETECTS and sends alerts. The agent decides what ACTION to
take (lock / photo / locate), so triggers never imports the agent — no
circular import. Legitimate anti-theft on a device you own.
"""
import os, json, math, requests

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE_DIR, "trigger_state.json")
BASE_URL   = "https://phantomtrace-backend-c0if.onrender.com"


# ── small persistent state (last IP, inside/outside geofence) ────────────────
def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(s):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(s, f)
    except Exception:
        pass


# ── backend helpers ──────────────────────────────────────────────────────────
def fetch_config(device_id):
    """Return {status, home_lat, home_lng, geofence_radius} or {} on failure."""
    try:
        r = requests.get(f"{BASE_URL}/api/device/agent-config/{device_id}", timeout=8)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"trigger: config fetch failed: {e}")
    return {}


def send_alert(device_id, title, body):
    """Ask the backend to push an alert to the owner's phone."""
    try:
        requests.post(f"{BASE_URL}/api/device/alert",
                      json={"device_id": device_id, "title": title, "body": body},
                      timeout=8)
        print(f"AUTO-ALERT: {title} - {body}")
    except Exception as e:
        print(f"trigger: alert send failed: {e}")


def get_ip_and_location():
    """One request -> (public_ip, lat, lng). Any field may be None on failure."""
    try:
        g = requests.get("http://ip-api.com/json/?fields=lat,lon,query", timeout=8).json()
        return g.get("query"), g.get("lat"), g.get("lon")
    except Exception:
        return None, None, None


def _haversine_m(lat1, lng1, lat2, lng2):
    R = 6371000.0  # earth radius, metres
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


# ── the checks ───────────────────────────────────────────────────────────────
def check_network_change(device_id, current_ip):
    """Alert if the public IP changed since last time. Returns True on change."""
    if not current_ip:
        return False
    st = _load_state()
    last = st.get("last_ip")
    if last is None:
        st["last_ip"] = current_ip
        _save_state(st)
        return False
    if current_ip != last:
        st["last_ip"] = current_ip
        _save_state(st)
        send_alert(device_id, "New network detected",
                   f"Your device connected to a new network (IP {current_ip}). "
                   "If this wasn't you, it may be stolen.")
        return True
    return False


def check_geofence(device_id, config, lat, lng):
    """Alert if the device is outside its safe zone. Returns True on exit."""
    hlat = config.get("home_lat")
    hlng = config.get("home_lng")
    rad  = config.get("geofence_radius")
    if None in (hlat, hlng, rad, lat, lng) or not rad:
        return False
    dist = _haversine_m(lat, lng, hlat, hlng)
    st = _load_state()
    was_inside = st.get("geofence_inside", True)
    inside = dist <= rad
    st["geofence_inside"] = inside
    _save_state(st)
    if was_inside and not inside:
        send_alert(device_id, "Device left safe zone",
                   f"Your device is {int(dist)} m away - outside its "
                   f"{int(rad)} m safe zone.")
        return True
    return False


def check_failed_logins(window_minutes=5):
    """
    Windows best-effort: count failed logon events (ID 4625) in the last window.
    Reading the Security log usually needs admin; returns 0 if not permitted.
    """
    if os.name != 'nt':
        return 0
    try:
        import subprocess
        ms = window_minutes * 60 * 1000
        q = (f"*[System[(EventID=4625) and "
             f"TimeCreated[timediff(@SystemTime)<={ms}]]]")
        r = subprocess.run(
            ["wevtutil", "qe", "Security", f"/q:{q}", "/f:text", "/c:50"],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return 0
        return r.stdout.count("Event ID:")
    except Exception:
        return 0
