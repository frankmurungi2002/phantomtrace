"""
PhantomTrace Automatic Triggers (T2 + T7)
=========================================
Hands-off theft detection. The agent runs these checks on a timer and reacts
without the owner pressing anything:

  * network / public-IP change  -> alert the owner            (T2)
  * geofence exit (safe zone)   -> alert the owner            (T2)
  * repeated failed logins      -> Windows Event 4625 count   (T2)
  * device status               -> auto-response when STOLEN  (T2)
  * OFFLINE too long            -> auto-lock the workstation  (T7)

T7 (Offline Auto-Lock) copies Android's Offline Device Lock: if the agent
loses all connectivity for N minutes while the device is unlocked, we lock
it anyway — defeating the thief who yanks Wi-Fi to dodge tracking. The
lock happens LOCALLY (LockWorkStation), so no network round-trip needed.

This module only DETECTS and returns True when the agent should ACT.
agent.py owns the actual lock/photo/locate calls, so triggers never
imports agent — no circular import. Legitimate anti-theft on a device
you own.
"""
import os, sys, json, math, time, requests

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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


# ── T7: Offline auto-lock ────────────────────────────────────────────────────
# Cheapest high-value feature in the roadmap. If the agent has failed to
# reach the backend for N minutes, we lock the workstation locally so a
# thief who yanks Wi-Fi can't just walk away and use the laptop offline.
#
# Rate-limited: at most 2 offline-locks per rolling 24 h, so a genuine dead
# zone (no signal in a lecture room, on a bus) doesn't turn the laptop into
# a constant lock-out for the owner.

OFFLINE_LOCK_DEFAULT_MIN = 15   # minutes without heartbeat before we lock
OFFLINE_LOCK_MAX_PER_24H = 2    # cap on auto-lock triggers per rolling day


def mark_heartbeat_ok():
    """Called from agent.py after every successful backend heartbeat."""
    st = _load_state()
    st["last_hb_ok"] = time.time()
    _save_state(st)


def _prune_lock_history(history, now):
    """Drop entries older than 24 h from the rolling history list."""
    return [t for t in history if now - t < 86400]


def check_offline_lock(device_id, config):
    """
    If the agent has been offline for >= threshold minutes, return True.
    Rate-limited so a bad-connectivity day doesn't lock the owner out.

    Callers:
      * agent.py trigger cycle passes config from fetch_config()
      * config may include 'offline_lock_minutes' to override the default
    """
    st = _load_state()
    last_hb = st.get("last_hb_ok")
    if not last_hb:
        # First run — assume we're online, start the clock
        st["last_hb_ok"] = time.time()
        _save_state(st)
        return False

    threshold_min = int(config.get("offline_lock_minutes") or OFFLINE_LOCK_DEFAULT_MIN)
    threshold_sec = max(60, threshold_min * 60)

    now  = time.time()
    gap  = now - last_hb
    if gap < threshold_sec:
        return False

    # Rate limit: at most N auto-locks per rolling 24 h
    history = _prune_lock_history(st.get("offline_lock_history", []), now)
    if len(history) >= OFFLINE_LOCK_MAX_PER_24H:
        # Save pruned history but skip the lock
        st["offline_lock_history"] = history
        _save_state(st)
        return False

    # We'll lock. Record it and reset the offline clock so we don't
    # re-trigger every cycle while still offline.
    history.append(now)
    st["offline_lock_history"] = history
    st["last_hb_ok"]           = now      # reset — next miss starts a fresh window
    _save_state(st)

    print(f"T7: OFFLINE {int(gap/60)} min >= {threshold_min} min — auto-locking")
    return True


def offline_lock_stats():
    """For debugging / display in the app: current T7 state."""
    st = _load_state()
    now = time.time()
    history = _prune_lock_history(st.get("offline_lock_history", []), now)
    last_hb = st.get("last_hb_ok")
    return {
        "seconds_since_last_heartbeat": (now - last_hb) if last_hb else None,
        "auto_locks_in_last_24h":       len(history),
    }
