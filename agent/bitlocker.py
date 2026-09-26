"""
PhantomTrace BitLocker Orchestrator (T8)
=========================================
Full-disk encryption is Windows' strongest native anti-theft protection.
Since Windows 11 24H2, Device Encryption is on by default on most laptops.
PhantomTrace does NOT re-implement crypto — instead it:

  * READS BitLocker status via `manage-bde -status` / WMI
  * TURNS BitLocker ON if the owner allows it (needs admin)
  * ESCROWS the 48-digit recovery key to the PhantomTrace backend
  * on WIPE, performs a CRYPTO-ERASE — delete the key protectors so the
    disk becomes cryptographically unrecoverable INSTANTLY (no slow
    overwrite, no network needed once triggered)

Copied ideas: Apple FileVault (crypto-erase = throw away the key) +
Microsoft BitLocker itself.

Safety rails:
  * enable() requires admin
  * crypto_erase() is one-way — after this the drive is unreadable
    forever unless the recovery key on the backend is retrieved
  * Never called automatically — only from the INSTANT_WIPE command
    from an authenticated owner
"""
import os, sys, subprocess, re, json

IS_WINDOWS = os.name == 'nt'
NO_WINDOW  = 0x08000000 if IS_WINDOWS else 0

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BL_STATE_FILE = os.path.join(BASE_DIR, "bitlocker_state.json")


def _run(cmd, timeout=30):
    """Run a subprocess silently, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return -1, "", str(e)


# ── Status ───────────────────────────────────────────────────────────────────
def status_for_volume(letter="C:"):
    """
    Return a dict for one volume:
       {
         'volume':          'C:',
         'protection':      'On' / 'Off' / 'Unknown',
         'conversion':      'Fully Encrypted' / 'Encrypting' / 'Fully Decrypted' / ...,
         'percent':          <int or None>,
         'encryption_method': 'XTS-AES 128' / ...,
       }
    """
    out = {"volume": letter, "protection": "Unknown",
           "conversion": "Unknown", "percent": None, "encryption_method": None}
    if not IS_WINDOWS:
        return out

    rc, stdout, _ = _run(["manage-bde", "-status", letter], timeout=20)
    if rc != 0 or not stdout:
        return out

    for line in stdout.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("protection status"):
            v = s.split(":", 1)[1].strip()
            out["protection"] = "On" if "on" in v.lower() else ("Off" if "off" in v.lower() else v)
        elif low.startswith("conversion status"):
            out["conversion"] = s.split(":", 1)[1].strip()
        elif low.startswith("percentage encrypted"):
            m = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*%", s)
            if m:
                try: out["percent"] = int(float(m.group(1)))
                except Exception: pass
        elif low.startswith("encryption method"):
            out["encryption_method"] = s.split(":", 1)[1].strip()
    return out


def status_all():
    """Return status for every volume (C:, D:, ...) BitLocker knows about."""
    if not IS_WINDOWS:
        return []
    rc, stdout, _ = _run(["manage-bde", "-status"], timeout=30)
    if rc != 0 or not stdout:
        return []
    # `manage-bde -status` prints per-volume blocks starting with e.g. "Volume C: [OSDrive]"
    letters = re.findall(r"Volume\s+([A-Z]:)", stdout, flags=re.IGNORECASE)
    return [status_for_volume(v) for v in dict.fromkeys(letters)]


# ── Recovery key extraction ──────────────────────────────────────────────────
_RECOVERY_KEY_RE = re.compile(
    r"([0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6})"
)
_KEY_ID_RE = re.compile(r"ID:\s*\{([0-9A-F-]{36})\}", flags=re.IGNORECASE)


def get_recovery_key(letter="C:"):
    """
    Extract the 48-digit numerical recovery password (and its GUID) for the
    given volume. Returns {'key_id': '...', 'recovery_key': '...'} or None.
    Needs admin.
    """
    if not IS_WINDOWS:
        return None
    rc, stdout, _ = _run(["manage-bde", "-protectors", "-get", letter], timeout=20)
    if rc != 0 or not stdout:
        return None
    # The output has "Numerical Password:" sections. Find the key + its ID.
    key_id = None
    rec_key = None
    in_numerical = False
    for line in stdout.splitlines():
        s = line.strip()
        if "numerical password" in s.lower():
            in_numerical = True
            continue
        if in_numerical:
            m_id = _KEY_ID_RE.search(s)
            if m_id and key_id is None:
                key_id = m_id.group(1)
            m_key = _RECOVERY_KEY_RE.search(s)
            if m_key and rec_key is None:
                rec_key = m_key.group(1)
            if key_id and rec_key:
                break
    if rec_key:
        return {"key_id": key_id or "", "recovery_key": rec_key}
    return None


def add_recovery_password_protector(letter="C:"):
    """
    Add a new numerical-password protector to the volume. Returns the new
    {key_id, recovery_key} or None. Idempotent — a volume can have several
    recovery passwords; PhantomTrace adds its own so it can crypto-erase
    later by deleting only that one, without touching the user's own key.
    """
    if not IS_WINDOWS:
        return None
    rc, _out, _err = _run(
        ["manage-bde", "-protectors", "-add", letter, "-RecoveryPassword"],
        timeout=30)
    if rc != 0:
        return None
    return get_recovery_key(letter)


# ── Enable BitLocker ─────────────────────────────────────────────────────────
def enable(letter="C:"):
    """
    Turn BitLocker on for `letter`. Uses TPM protector by default (silent
    on encrypted-by-default 24H2 machines). Returns True on success.
    Needs admin.
    """
    if not IS_WINDOWS:
        return False
    # PowerShell Enable-BitLocker is cleaner and works with TPM by default
    ps = (f"Enable-BitLocker -MountPoint '{letter}' "
          f"-EncryptionMethod XtsAes128 -UsedSpaceOnly "
          f"-TpmProtector -SkipHardwareTest -ErrorAction Stop")
    rc, out, err = _run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=60)
    if rc != 0:
        print(f"BitLocker enable failed: {err.strip() or out.strip()}")
        return False
    return True


# ── Crypto-erase (INSTANT WIPE) ──────────────────────────────────────────────
def crypto_erase(letter="C:"):
    """
    IRREVERSIBLE: delete every key protector on the volume so the drive is
    cryptographically unrecoverable. Faster than any overwrite-based wipe
    and works even if the machine goes offline seconds later.

    Note: on the SYSTEM volume this cannot fully take effect until reboot
    (Windows holds the FVEK in memory), so we also schedule a shutdown.

    Returns True on success. Needs admin.
    """
    if not IS_WINDOWS:
        return False
    # 1) Disable auto-unlock (data volumes) — best effort
    _run(["manage-bde", "-autounlock", "-disable", letter], timeout=15)

    # 2) List all protectors on the volume and delete each by ID
    rc, out, _ = _run(["manage-bde", "-protectors", "-get", letter], timeout=20)
    if rc != 0:
        print("crypto_erase: could not enumerate protectors")
        return False
    ids = _KEY_ID_RE.findall(out)
    if not ids:
        print("crypto_erase: no protectors to delete")
        # still fall through to force-lock
    for kid in ids:
        rc2, _o, e = _run(
            ["manage-bde", "-protectors", "-delete", letter, "-id", "{" + kid + "}"],
            timeout=20)
        if rc2 != 0:
            print(f"crypto_erase: delete {kid} failed: {e.strip()}")

    # 3) For data volumes, -lock makes it immediately unreadable
    if letter.upper() != "C:":
        _run(["manage-bde", "-lock", letter, "-forcedismount"], timeout=15)

    # 4) For the system volume, request an immediate reboot so the FVEK
    #    leaves RAM and the drive becomes unreadable at next boot.
    if letter.upper() == "C:":
        try:
            subprocess.Popen(
                ["shutdown", "/r", "/t", "10",
                 "/c", "PhantomTrace instant wipe complete. Rebooting."],
                creationflags=NO_WINDOW)
        except Exception:
            pass
    return True


# ── State persistence ────────────────────────────────────────────────────────
def _save_state(s):
    try:
        with open(BL_STATE_FILE, "w") as f:
            json.dump(s, f)
    except Exception:
        pass


def _load_state():
    try:
        with open(BL_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def has_escrowed_key():
    """True if PhantomTrace has already added + escrowed its own recovery key."""
    return bool(_load_state().get("escrowed"))


def mark_escrowed(key_id):
    st = _load_state()
    st["escrowed"] = True
    st["key_id"]   = key_id
    _save_state(st)
