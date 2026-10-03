from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os, uuid, bcrypt
from datetime import datetime, timedelta
from flask import send_file
load_dotenv()
import firebase_admin
from firebase_admin import credentials, messaging
import base64, json as _json

# ── Cloudinary setup for persistent evidence storage ──────────────────────────
# Render's filesystem is EPHEMERAL — every redeploy wipes evidence_vault/.
# Cloudinary gives us permanent image hosting with a free 25GB tier. If
# the CLOUDINARY_URL env var is set (format cloudinary://KEY:SECRET@CLOUD),
# cloudinary.config() reads it automatically on import.
try:
    import cloudinary, cloudinary.uploader
    cloudinary.config()  # reads CLOUDINARY_URL env var
    CLOUDINARY_READY = bool(os.getenv('CLOUDINARY_URL'))
    if CLOUDINARY_READY:
        print("[cloudinary] configured — evidence photos will be uploaded to the cloud")
    else:
        print("[cloudinary] CLOUDINARY_URL not set — falling back to local evidence_vault/")
except Exception as _ce:
    CLOUDINARY_READY = False
    print(f"[cloudinary] import failed, falling back to local disk: {_ce}")

# Initialize Firebase — try multiple credential sources
_fb_initialized = False
try:
    _cred_dict = None

    # Method 1: individual env vars (easiest to set in Render)
    _fb_client_email = os.environ.get('FIREBASE_CLIENT_EMAIL', '')
    # Accept private key as base64 (preferred, avoids newline corruption) or raw PEM
    _fb_pk_b64 = os.environ.get('FIREBASE_PRIVATE_KEY_B64', '').strip()
    _fb_pk_raw = os.environ.get('FIREBASE_PRIVATE_KEY', '').strip()
    if _fb_pk_b64:
        _fb_private_key = base64.b64decode(_fb_pk_b64).decode()
        print(f"Firebase: private key from FIREBASE_PRIVATE_KEY_B64 (b64 len={len(_fb_pk_b64)})")
    elif _fb_pk_raw:
        # Normalize: handle literal \n sequences and Windows CRLF
        _fb_private_key = _fb_pk_raw.replace('\\n', '\n').replace('\r\n', '\n').replace('\r', '\n').strip()
        if not _fb_private_key.endswith('\n'):
            _fb_private_key += '\n'
        print("Firebase: private key from FIREBASE_PRIVATE_KEY")
    else:
        _fb_private_key = ''
    if _fb_private_key and _fb_client_email:
        _cred_dict = {
            "type": "service_account",
            "project_id": os.environ.get('FIREBASE_PROJECT_ID', 'phantomtrace-ce048'),
            "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID', ''),
            "private_key": _fb_private_key,
            "client_email": _fb_client_email,
            "client_id": os.environ.get('FIREBASE_CLIENT_ID', ''),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{_fb_client_email.replace('@', '%40')}",
            "universe_domain": "googleapis.com"
        }
        # Fingerprint lets us verify the key survived copy/paste intact.
        # Expected: c1de05387e18
        import hashlib as _hashlib
        _fp = _hashlib.sha256(_fb_private_key.encode()).hexdigest()[:12]
        print(f"Firebase: using individual env vars (key fingerprint={_fp}, expected=c1de05387e18)")

    # Method 2: base64-encoded JSON blob
    if _cred_dict is None:
        _cred_b64 = os.environ.get('FIREBASE_CREDENTIALS_B64', '').strip()
        if _cred_b64:
            # Fix padding if truncated
            _cred_b64 += '=' * (4 - len(_cred_b64) % 4) if len(_cred_b64) % 4 else ''
            _cred_dict = _json.loads(base64.b64decode(_cred_b64).decode())
            print("Firebase: using base64 env var")

    # Method 3: local JSON file
    if _cred_dict is None:
        _cred_path = os.path.join(os.path.dirname(__file__), 'firebase-service-account.json')
        if os.path.exists(_cred_path):
            with open(_cred_path) as _f:
                _cred_dict = _json.load(_f)
            print("Firebase: using local file")

    if _cred_dict:
        firebase_admin.initialize_app(credentials.Certificate(_cred_dict))
        _fb_initialized = True
        print("Firebase initialized OK")
    else:
        print("WARNING: No Firebase credentials found — push notifications disabled")
except Exception as _fb_err:
    print(f"Firebase init error: {_fb_err}")

def send_push(token, title, body, data=None):
    if not _fb_initialized:
        print("Push skipped: Firebase not initialized")
        return
    if not token:
        print("Push skipped: no FCM token")
        return
    try:
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            data={k: str(v) for k, v in (data or {}).items()},
            token=token,
        )
        messaging.send(message)
        print(f"Push sent: {title}")
    except Exception as e:
        print(f"Push failed: {e}")



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = __import__('datetime').timedelta(days=7)

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    fcm_token = db.Column(db.Text)  # phone's Firebase Cloud Messaging token for push notifications
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # 2FA (TOTP, Google Authenticator compatible)
    totp_secret = db.Column(db.String(64))     # base32 secret; null = 2FA not set up
    totp_enabled = db.Column(db.Boolean, default=False)
    totp_recovery_codes = db.Column(db.Text)   # comma-separated, one-use each
    # Tracks when the password was last reset. Used to invalidate old JWTs.
    password_reset_at = db.Column(db.DateTime)
    # When the user agreed to the Terms of Service + Privacy Policy. Required
    # at signup from v1.1 onward; existing accounts are grandfathered in on
    # their next login (we'll back-fill a timestamp then).
    legal_accepted_at = db.Column(db.DateTime)
    legal_version     = db.Column(db.String(20))   # which version they accepted


# Password reset OTP — sent via SMS to the phone registered with the account.
# Two-factor proof (email + phone) prevents a single-channel compromise.
class PasswordResetOtp(db.Model):
    __tablename__ = 'password_reset_otps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    code_hash = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(64))

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    beacon_id = db.Column(db.String(64), unique=True, nullable=False)
    gsm_number = db.Column(db.String(20))
    status = db.Column(db.String(10), default='SAFE')
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    stolen_at = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    # T2 geofence (safe zone) — set by the owner, read by the agent
    home_lat = db.Column(db.Float)
    home_lng = db.Column(db.Float)
    geofence_radius = db.Column(db.Float)  # metres
    # T5 data vault — key the agent uses to encrypt/decrypt the owner's folders
    vault_key = db.Column(db.Text)
    # T7 offline auto-lock threshold in minutes (agent default = 15)
    offline_lock_minutes = db.Column(db.Integer)
    # T8 BitLocker orchestration
    bitlocker_protection   = db.Column(db.String(20))    # On / Off / Unknown
    bitlocker_conversion   = db.Column(db.String(40))    # Fully Encrypted / ...
    bitlocker_percent      = db.Column(db.Integer)
    bitlocker_method       = db.Column(db.String(40))    # XTS-AES 128 / ...
    bitlocker_key_id       = db.Column(db.String(40))    # GUID of our protector
    bitlocker_recovery_key = db.Column(db.String(80))    # 48-digit recovery key
    bitlocker_updated_at   = db.Column(db.DateTime)
    # BIOS protection wizard — the owner confirms they set a BIOS password
    # that blocks USB boot. The dashboard shows a yellow warning badge
    # until this is marked true.
    bios_manufacturer = db.Column(db.String(80))
    bios_model        = db.Column(db.String(120))
    bios_enter_key    = db.Column(db.String(60))
    bios_fallback_key = db.Column(db.String(80))
    bios_steps_json   = db.Column(db.Text)       # list[str] JSON
    bios_protected    = db.Column(db.Boolean, default=False)
    bios_protected_at = db.Column(db.DateTime)

class Sighting(db.Model):
    __tablename__ = 'sightings'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float)
    method = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Command(db.Model):
    __tablename__ = 'commands'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    command_type = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(10), default='PENDING')
    # T4: JSON payload for commands that carry data (e.g. DETERRENT_LOCK
    # carries the owner's custom message + a one-time unlock code)
    payload = db.Column(db.Text)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at = db.Column(db.DateTime)

class EmergencyContact(db.Model):
    """People to notify in addition to the owner when a device is marked stolen.
    Think: spouse, flatmate, campus security, driver. On mark-stolen the
    backend emails each contact (and SMSes if phone is set) with the recovery
    report attached."""
    __tablename__ = 'emergency_contacts'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(30))
    relationship = db.Column(db.String(60))   # 'spouse', 'security', 'flatmate', etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class EvidencePhoto(db.Model):
    __tablename__ = 'evidence_photos'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    photo_type = db.Column(db.String(20), default='SCREENSHOT')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class DeviceLocation(db.Model):
    __tablename__ = 'device_location'
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    isp = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    area = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class LocationHistory(db.Model):
    """Movement trail — one row per meaningful location report from the agent."""
    __tablename__ = 'location_history'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    isp = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    area = db.Column(db.String(200))
    method = db.Column(db.String(20), default='WIFI')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceSystemInfo(db.Model):
    __tablename__ = 'device_system_info'
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    hostname = db.Column(db.String(100))
    username = db.Column(db.String(100))
    os_name = db.Column(db.String(100))
    os_version = db.Column(db.String(100))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceNetworkInfo(db.Model):
    __tablename__ = 'device_network_info'
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    hostname = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceDiskInfo(db.Model):
    __tablename__ = 'device_disk_info'
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    total_gb = db.Column(db.String(20))
    used_gb = db.Column(db.String(20))
    free_gb = db.Column(db.String(20))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceProcess(db.Model):
    __tablename__ = 'device_processes'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'))
    process_name = db.Column(db.String(100))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class CommandHistory(db.Model):
    __tablename__ = 'command_history'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'))
    command_type = db.Column(db.String(50))
    result = db.Column(db.String(50))
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)


# ── T9: Quick Lock by Phone Number ───────────────────────────────────────────
# A panic-lock path that needs only the owner's registered phone number +
# an SMS OTP — no full login. For the victim who just had their laptop
# stolen and grabs a stranger's phone in a lecture room.
class QuickLockOtp(db.Model):
    __tablename__ = 'quick_lock_otps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    phone = db.Column(db.String(20), nullable=False, index=True)
    code_hash = db.Column(db.String(80), nullable=False)   # sha256
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(64))


# ── Device pairing codes (fixes broken auto-registration) ────────────────────
# The old /api/device/self-register attached every new laptop to whichever
# user was created first in the DB. This flow replaces that:
# 1. User taps "Add Device" in the app → server creates a short pairing
#    code tied to their user_id.
# 2. User runs the agent on their laptop → agent prompts for the code.
# 3. Agent posts to /api/device/pair with the code → device is created
#    under the CORRECT user, agent gets device_id back.
# Codes expire in 30 min so a leaked code isn't useful indefinitely.
class DevicePairCode(db.Model):
    __tablename__ = 'device_pair_codes'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    code = db.Column(db.String(16), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_name_hint = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    device_id = db.Column(db.String(36))   # populated once paired


class EvidenceKeylog(db.Model):
    __tablename__ = 'evidence_keylog'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    keylog_text = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def notify_device_owner(device_id, title, body, data=None):
    try:
        result = db.session.execute(
            db.text("SELECT u.fcm_token FROM users u JOIN devices d ON d.user_id = u.id WHERE d.id=:id"),
            {"id": device_id}
        ).first()
        if result and result[0]:
            print(f"notify: owner has FCM token, sending '{title}'")
            send_push(result[0], title, body, data or {})
        else:
            print(f"notify: NO FCM token for device {device_id} — owner must log in on the app to register it")
    except Exception as e:
        print(f"notify error: {e}")


# ── Public legal pages ─────────────────────────────────────────────────────
# Served as static HTML so Google Play Store and users can link to them
# publicly. The actual text lives in backend/legal/*.html so updates are
# just git-pushes without touching Python.
import pathlib as _pathlib
_LEGAL_DIR = _pathlib.Path(__file__).parent / 'legal'

@app.route('/terms', methods=['GET'])
@app.route('/tos',   methods=['GET'])     # friendly alias
def legal_terms():
    try:
        return send_file(_LEGAL_DIR / 'terms.html', mimetype='text/html')
    except Exception:
        return "Terms of Service not available", 500

@app.route('/privacy', methods=['GET'])
@app.route('/privacy-policy', methods=['GET'])
def legal_privacy():
    try:
        return send_file(_LEGAL_DIR / 'privacy.html', mimetype='text/html')
    except Exception:
        return "Privacy Policy not available", 500

@app.route('/', methods=['GET'])
def legal_root():
    # Friendly landing for anyone who types the backend URL in a browser.
    return ('<html><body style="background:#0A0A0A;color:#F3F4F6;'
            'font-family:system-ui;padding:48px;text-align:center">'
            '<h1>PhantomTrace</h1>'
            '<p>Anti-theft and recovery platform for Windows laptops.</p>'
            '<p><a style="color:#DC2626" href="/terms">Terms of Service</a> &middot; '
            '<a style="color:#DC2626" href="/privacy">Privacy Policy</a></p>'
            '</body></html>')


@app.route('/api/auth/fcm-token', methods=['POST'])
@jwt_required()
def save_fcm_token():
    user_id = get_jwt_identity()
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({"error": "No token"}), 400
    db.session.execute(
        db.text("UPDATE users SET fcm_token=:token WHERE id=:id"),
        {"token": token, "id": user_id}
    )
    db.session.commit()
    return jsonify({"message": "FCM token saved"}), 200

LEGAL_VERSION = '2026-10-03'   # bump when the Terms/Privacy text materially changes

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ['name','email','phone','password']):
        return jsonify({'error': 'Missing required fields'}), 400
    # Legal: block signup if the user hasn't accepted Terms + Privacy. The
    # mobile app shows a required checkbox; this is defense-in-depth so a
    # custom client cannot bypass it.
    if not data.get('accepted_terms'):
        return jsonify({'error':
            'You must accept the Terms of Service and Privacy Policy to '
            'create an account.'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(
        name=data['name'], email=data['email'], phone=data['phone'],
        password_hash=password_hash,
        legal_accepted_at=datetime.utcnow(),
        legal_version=LEGAL_VERSION,
    )
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Account created', 'token': token, 'user': {'id': user.id, 'name': user.name}}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(k in data for k in ['email','password']):
        return jsonify({'error': 'Missing email or password'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    # 2FA: if enabled, don't issue a full token yet — return a short-lived
    # "pre-auth" token that only the /verify-login-2fa endpoint accepts.
    if getattr(user, 'totp_enabled', False):
        pre_token = create_access_token(
            identity=user.id, expires_delta=timedelta(minutes=5),
            additional_claims={'stage': 'pre-2fa'})
        return jsonify({
            'requires_2fa': True,
            'pre_auth_token': pre_token,
            'user': {'id': user.id, 'name': user.name},
        }), 200
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'token': token, 'user': {'id': user.id, 'name': user.name}}), 200


@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def profile():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone,
        'totp_enabled': bool(getattr(user, 'totp_enabled', False)),
    }), 200


# ── Password reset (email + SMS OTP — needs proof of BOTH channels) ─────────
# Copied from the industry-standard flow: knowing the email alone isn't
# enough. The OTP goes to the phone registered against that email; a
# hijacker who only has the email can't complete the reset.
_PW_RESET_TTL_MIN     = 10
_PW_RESET_MAX_PER_HR  = 5
_PW_RESET_MAX_ATTEMPTS = 5


@app.route('/api/auth/forgot-password/request', methods=['POST'])
def forgot_password_request():
    data = request.get_json() or {}
    email = str(data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400

    # Always return 200 whether or not the email exists — prevents user
    # enumeration. Only actually create + send an OTP if the account exists.
    user = User.query.filter(db.func.lower(User.email) == email).first()
    if user:
        # Rate limit by user
        since = datetime.utcnow() - timedelta(hours=1)
        recent = PasswordResetOtp.query.filter(
            PasswordResetOtp.user_id == user.id,
            PasswordResetOtp.created_at >= since).count()
        if recent < _PW_RESET_MAX_PER_HR:
            code = ''.join(_random.choices(_string.digits, k=6))
            otp = PasswordResetOtp(
                user_id=user.id,
                code_hash=_sha(code),
                expires_at=datetime.utcnow() + timedelta(minutes=_PW_RESET_TTL_MIN),
                ip_address=request.headers.get('X-Forwarded-For', request.remote_addr or ''))
            db.session.add(otp)
            db.session.commit()
            body = (f"PhantomTrace password reset code: {code}. "
                    f"Valid {_PW_RESET_TTL_MIN} minutes. If you didn't request this, "
                    "someone may be trying to access your account.")
            _send_sms_generic(user.phone, body)
    return jsonify({
        'message': 'If an account exists for that email, a reset code was sent to its phone.',
        'ttl_minutes': _PW_RESET_TTL_MIN,
    }), 200


def _send_sms_generic(phone, body):
    """Same Africa's Talking flow as quick-lock, extracted for reuse."""
    at_user = os.getenv('AT_USERNAME')
    at_key  = os.getenv('AT_API_KEY')
    at_from = os.getenv('AT_SENDER_ID', 'PhantomTrace')
    if at_user and at_key:
        try:
            import requests as _rq
            _rq.post("https://api.africastalking.com/version1/messaging",
                     headers={"apiKey": at_key, "Accept": "application/json"},
                     data={"username": at_user, "to": phone, "from": at_from, "message": body},
                     timeout=15)
        except Exception as e:
            print(f"AT SMS failed: {e}")
    else:
        print(f"[SMS] to={phone} body={body}   (no SMS provider configured)")


@app.route('/api/auth/forgot-password/verify', methods=['POST'])
def forgot_password_verify():
    data = request.get_json() or {}
    email = str(data.get('email') or '').strip().lower()
    code  = str(data.get('code') or '').strip()
    new_password = str(data.get('new_password') or '')
    if not email or not code or not new_password:
        return jsonify({'error': 'email, code, and new_password required'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    user = User.query.filter(db.func.lower(User.email) == email).first()
    if not user:
        return jsonify({'error': 'Invalid code'}), 401  # don't leak account existence
    otp = (PasswordResetOtp.query
           .filter_by(user_id=user.id, used=False)
           .order_by(PasswordResetOtp.created_at.desc())
           .first())
    if not otp or otp.expires_at < datetime.utcnow():
        return jsonify({'error': 'Code expired or not found'}), 410
    if otp.attempts >= _PW_RESET_MAX_ATTEMPTS:
        otp.used = True; db.session.commit()
        return jsonify({'error': 'Too many wrong attempts. Request a new code.'}), 429
    otp.attempts += 1
    if _sha(code) != otp.code_hash:
        db.session.commit()
        return jsonify({'error': 'Wrong code'}), 401
    # Success — set new password + mark reset time (invalidates old JWTs
    # for endpoints that check it) + burn the OTP.
    user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.password_reset_at = datetime.utcnow()
    otp.used = True
    db.session.commit()
    # Alert the owner via push, in case someone else did this
    try:
        notify_user_direct(user, "Password was reset",
            "Your PhantomTrace password was just reset. If this wasn't you, "
            "contact support immediately.")
    except Exception as e:
        print(f"pw-reset push failed: {e}")
    # Issue a fresh token — user is now logged in with the new password
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Password updated', 'token': token,
                    'user': {'id': user.id, 'name': user.name}}), 200


def notify_user_direct(user, title, body):
    """Send an FCM push straight to a user (used by password reset)."""
    if not user or not user.fcm_token:
        return
    try:
        from firebase_admin import messaging
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            token=user.fcm_token)
        messaging.send(message)
    except Exception as e:
        print(f"notify_user_direct failed: {e}")


# ── Two-Factor Authentication (TOTP — Google Authenticator compatible) ─────
@app.route('/api/auth/2fa/setup', methods=['POST'])
@jwt_required()
def totp_setup():
    """
    Owner calls this from Settings → returns a base32 secret + provisioning
    URI (usable as a QR code). The secret is stored but 2FA isn't enabled
    yet — the client must call verify-setup with a valid code first.
    """
    import pyotp
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name='PhantomTrace')
    user.totp_secret = secret
    user.totp_enabled = False   # not enabled until verified
    db.session.commit()
    return jsonify({'secret': secret, 'otpauth_url': uri}), 200


@app.route('/api/auth/2fa/verify-setup', methods=['POST'])
@jwt_required()
def totp_verify_setup():
    """User confirms they can generate codes → 2FA turns on + recovery codes returned."""
    import pyotp, secrets as _secrets
    data = request.get_json() or {}
    code = str(data.get('code') or '').strip()
    user = User.query.get(get_jwt_identity())
    if not user or not user.totp_secret:
        return jsonify({'error': 'No 2FA setup in progress'}), 400
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        return jsonify({'error': 'Wrong code — check the time on your phone'}), 401
    # Generate 10 one-use recovery codes
    codes = ['-'.join(_secrets.token_hex(2)[i:i+4]
                      for i in (0, 4)) for _ in range(10)]
    user.totp_recovery_codes = ','.join(codes)
    user.totp_enabled = True
    db.session.commit()
    return jsonify({'message': '2FA enabled', 'recovery_codes': codes}), 200


@app.route('/api/auth/2fa/verify-login', methods=['POST'])
@jwt_required()
def totp_verify_login():
    """
    Called after /login when the login returned requires_2fa. Consumes the
    short-lived pre-auth token and, if the code is valid, returns the real
    JWT. Also accepts a one-use recovery code as the `code`.
    """
    import pyotp
    from flask_jwt_extended import get_jwt
    claims = get_jwt()
    if claims.get('stage') != 'pre-2fa':
        return jsonify({'error': 'Wrong token stage'}), 401
    data = request.get_json() or {}
    code = str(data.get('code') or '').strip().replace(' ', '')
    user = User.query.get(get_jwt_identity())
    if not user or not user.totp_enabled:
        return jsonify({'error': '2FA not enabled'}), 400

    ok = pyotp.TOTP(user.totp_secret).verify(code, valid_window=1)
    if not ok and user.totp_recovery_codes:
        # Try recovery codes (one-use each)
        codes = user.totp_recovery_codes.split(',')
        if code in codes:
            codes.remove(code)
            user.totp_recovery_codes = ','.join(codes)
            db.session.commit()
            ok = True

    if not ok:
        return jsonify({'error': 'Invalid 2FA code'}), 401

    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'token': token,
                    'user': {'id': user.id, 'name': user.name}}), 200


@app.route('/api/auth/2fa/disable', methods=['POST'])
@jwt_required()
def totp_disable():
    """Requires current password + a valid TOTP code."""
    import pyotp
    data = request.get_json() or {}
    password = str(data.get('password') or '')
    code = str(data.get('code') or '').strip()
    user = User.query.get(get_jwt_identity())
    if not user or not user.totp_enabled:
        return jsonify({'error': '2FA not enabled'}), 400
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Wrong password'}), 401
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        return jsonify({'error': 'Wrong 2FA code'}), 401
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_recovery_codes = None
    db.session.commit()
    return jsonify({'message': '2FA disabled'}), 200

@app.route('/api/device/self-register', methods=['POST'])
def self_register_device():
    """
    LEGACY / DEV endpoint. Attaches the device to whichever user was
    created first. Kept for backwards compatibility with older agent
    builds; new agents use /api/device/pair with a pairing code instead.
    Refuses if there is more than one user, so a broadcast .exe can't
    hijack an arbitrary account.
    """
    data = request.get_json() or {}
    # Prefer owner_email if the caller supplied it — this makes the
    # legacy endpoint at least behave sensibly for a single-user install.
    owner_email = (data.get('owner_email') or '').strip().lower()
    user = None
    if owner_email:
        user = User.query.filter(db.func.lower(User.email) == owner_email).first()
    if not user:
        # Only fall back to the first user if there is EXACTLY one
        # user in the DB (single-user dev install). Otherwise refuse.
        n = User.query.count()
        if n == 1:
            user = User.query.first()
        else:
            return jsonify({
                'error': 'This build cannot self-register. Update to a newer '
                         'agent and use a pairing code from the mobile app.'
            }), 409
    device = Device(
        user_id=user.id,
        device_name=data.get('device_name', 'Unknown'),
        beacon_id=str(uuid.uuid4()).replace('-',''),
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({'message': 'Registered', 'device_id': device.id}), 201


# ── Device pairing (correct multi-user flow) ─────────────────────────────────
_PAIR_CODE_TTL_MIN = 30

def _generate_pair_code():
    """8-char human-readable code, chunked like '83-KFN-217'."""
    import random as _r, string as _s
    # Avoid ambiguous chars (0/O, 1/I/L)
    alphabet = ''.join(c for c in _s.ascii_uppercase + _s.digits
                       if c not in '0O1IL')
    parts = [
        ''.join(_r.choices(_s.digits, k=2)),
        ''.join(_r.choices(alphabet, k=3)),
        ''.join(_r.choices(_s.digits, k=3)),
    ]
    return '-'.join(parts)


@app.route('/api/device/create-pair-code', methods=['POST'])
@jwt_required()
def create_pair_code():
    """
    Owner (in the app) creates a pairing code. Returns the code + TTL.
    Any existing un-used codes for this user are invalidated so we
    never leave old codes lying around.
    """
    data = request.get_json() or {}
    user_id = get_jwt_identity()

    # Invalidate any active codes this user already has
    now = datetime.utcnow()
    DevicePairCode.query.filter(
        DevicePairCode.user_id == user_id,
        DevicePairCode.used_at.is_(None),
        DevicePairCode.expires_at > now,
    ).update({DevicePairCode.expires_at: now})

    # Generate a unique code (retry on the astronomically unlikely collision)
    for _ in range(10):
        code = _generate_pair_code()
        if not DevicePairCode.query.filter_by(code=code).first():
            break

    row = DevicePairCode(
        code=code,
        user_id=user_id,
        device_name_hint=(data.get('device_name') or '').strip() or None,
        expires_at=now + timedelta(minutes=_PAIR_CODE_TTL_MIN),
    )
    db.session.add(row)
    db.session.commit()

    return jsonify({
        'code':        code,
        'expires_in':  _PAIR_CODE_TTL_MIN * 60,   # seconds
        'expires_at':  row.expires_at.isoformat(),
    }), 201


@app.route('/api/device/pair', methods=['POST'])
def pair_device():
    """
    Agent side of the pairing flow. Takes a code + a device_name and
    returns a device_id + user_id. Public (no JWT) — the code itself
    is the authorization.
    """
    data = request.get_json() or {}
    code = str(data.get('code') or '').strip().upper()
    device_name = (data.get('device_name') or 'My Laptop').strip()[:100]
    if not code:
        return jsonify({'error': 'code required'}), 400

    row = DevicePairCode.query.filter_by(code=code).first()
    if not row:
        return jsonify({'error': 'Invalid pairing code'}), 404
    if row.used_at is not None:
        return jsonify({'error': 'Pairing code already used'}), 409
    if row.expires_at < datetime.utcnow():
        return jsonify({'error': 'Pairing code expired. Generate a new one.'}), 410

    device = Device(
        user_id=row.user_id,
        device_name=(row.device_name_hint or device_name),
        beacon_id=str(uuid.uuid4()).replace('-', ''),
    )
    db.session.add(device)
    row.used_at   = datetime.utcnow()
    row.device_id = device.id
    db.session.commit()

    # Notify the owner's phone that pairing succeeded
    try:
        notify_device_owner(device.id,
            "Device paired",
            f"'{device.device_name}' is now protected by PhantomTrace.",
            {'source': 'pairing'})
    except Exception as e:
        print(f"pair-owner-push failed: {e}")

    return jsonify({
        'message':   'Device paired',
        'device_id': device.id,
        'user_id':   row.user_id,
        'beacon_id': device.beacon_id,
        'device_name': device.device_name,
    }), 201


@app.route('/api/device/pair-status/<code>', methods=['GET'])
def pair_status(code):
    """
    The mobile app polls this while showing the pairing code, so it can
    switch to 'Device paired!' automatically without a manual refresh.

    Public — no JWT required. Knowing the code is already the token
    needed to see its own status. The response (paired yes/no + a
    device_id) gives no attacker anything actionable — the pair action
    itself still consumes the code. Making this public also avoids the
    'stale JWT during polling' failure mode that caused the phone to
    hang on 'Waiting for your laptop...'.
    """
    row = DevicePairCode.query.filter_by(code=code.strip().upper()).first()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    print(f"[PAIR-STATUS] code={row.code} paired={row.used_at is not None}")
    return jsonify({
        'code':      row.code,
        'paired':    row.used_at is not None,
        'device_id': row.device_id,
        'expired':   row.expires_at < datetime.utcnow(),
        'expires_at': row.expires_at.isoformat(),
    }), 200

@app.route('/api/device/register', methods=['POST'])
@jwt_required()
def register_device():
    data = request.get_json()
    if not data or 'device_name' not in data:
        return jsonify({'error': 'Device name required'}), 400
    device = Device(
        user_id=get_jwt_identity(),
        device_name=data['device_name'],
        beacon_id=str(uuid.uuid4()).replace('-',''),
        gsm_number=data.get('gsm_number','')
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({'message': 'Device registered', 'device': {'id': device.id, 'beacon_id': device.beacon_id, 'status': device.status}}), 201

@app.route('/api/device/list', methods=['GET'])
@jwt_required()
def list_devices():
    devices = Device.query.filter_by(user_id=get_jwt_identity()).all()
    result = []
    for d in devices:
        online = False
        if d.last_seen:
            online = (datetime.utcnow() - d.last_seen).total_seconds() < 30
        result.append({
            'id': d.id,
            'device_name': d.device_name,
            'status': d.status,
            'online': online,
            'last_seen': d.last_seen.isoformat() if d.last_seen else None,
            # Dashboard needs these to render the yellow BIOS warning badge.
            'bios_protected': bool(d.bios_protected),
            'bios_manufacturer': d.bios_manufacturer,
            'bios_model': d.bios_model,
        })
    return jsonify({'devices': result}), 200


# Delete a device — owner-only.
#
# Two-phase so the laptop isn't orphaned with a running agent:
#   1. Default (?mode=graceful): queue AGENT_UNINSTALL + mark the device as
#      pending delete. The agent, on its next poll, sees the command, tears
#      itself down (persistence, device.json, exe) and acknowledges. Only
#      THEN do we delete the DB rows. The mobile shows "pending" state in
#      the meantime.
#   2. mode=force: delete DB rows immediately. Use this if the laptop is
#      offline/lost and will never come back. Any still-running agent
#      becomes a dead-letter.
@app.route('/api/device/<device_id>', methods=['DELETE'])
@jwt_required()
def delete_device(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device_name = device.device_name
    mode = (request.args.get('mode') or 'force').lower()

    # Always queue the uninstall so the agent can self-destruct if it ever
    # comes online again, even in force mode.
    try:
        db.session.add(Command(device_id=device_id, command_type='AGENT_UNINSTALL'))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"delete_device: queue AGENT_UNINSTALL: {e}")

    if mode == 'graceful':
        # Leave the device + its data in place for 24h so the agent has a
        # window to pick up the uninstall command. The mobile hides the
        # device until the backing row is actually deleted; the client can
        # tap "force delete" to skip this wait.
        return jsonify({
            'message': f'Uninstall command sent to "{device_name}". '
                       'The agent will clean itself up on its next check-in '
                       '(up to a few seconds while online, longer if offline).',
            'phase': 'uninstall_queued',
        }), 202

    # Force / immediate: cascade clean-up now.
    for tbl in ('commands', 'command_history', 'evidence_photos',
                'sightings', 'location_history', 'device_location',
                'device_system_info', 'device_network_info',
                'device_disk_info', 'device_processes'):
        try:
            db.session.execute(
                db.text(f"DELETE FROM {tbl} WHERE device_id = :did"),
                {"did": device_id})
        except Exception as e:
            db.session.rollback()
            print(f"delete_device: cascade on {tbl}: {e}")
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': f'"{device_name}" deleted'}), 200


# Rename a device from the mobile app. Device name is cosmetic — doesn't
# affect pairing, beacon, or identity.
@app.route('/api/device/<device_id>/rename', methods=['POST'])
@jwt_required()
def rename_device(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Name cannot be empty'}), 400
    device.device_name = name[:100]
    db.session.commit()
    return jsonify({'message': 'Device renamed', 'device_name': device.device_name}), 200


# ── BIOS protection reporting ─────────────────────────────────────────────
# Agent reports its laptop model + the matching BIOS instructions. Owner
# confirms via the mobile app once they've set a BIOS password + locked
# USB boot. Public: no JWT needed, device_id is the proof — this endpoint
# only writes columns, no sensitive data is returned.
@app.route('/api/device/bios-info', methods=['POST'])
def report_bios_info():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'Missing device_id'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.bios_manufacturer = (data.get('manufacturer') or '')[:80]
    device.bios_model        = (data.get('model') or '')[:120]
    device.bios_enter_key    = (data.get('enter_key') or '')[:60]
    device.bios_fallback_key = (data.get('fallback_key') or '')[:80]
    steps = data.get('steps') or []
    try:
        device.bios_steps_json = _json.dumps(steps[:12])   # cap size
    except Exception:
        device.bios_steps_json = None
    db.session.commit()
    return jsonify({'message': 'BIOS info stored'}), 200


# Mobile app reads this to show the setup wizard for a device.
@app.route('/api/device/<device_id>/bios-info', methods=['GET'])
@jwt_required()
def get_bios_info(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    try:
        steps = _json.loads(device.bios_steps_json or '[]')
    except Exception:
        steps = []
    return jsonify({
        'manufacturer': device.bios_manufacturer,
        'model': device.bios_model,
        'enter_key': device.bios_enter_key,
        'fallback_key': device.bios_fallback_key,
        'steps': steps,
        'protected': bool(device.bios_protected),
        'protected_at': device.bios_protected_at.isoformat() if device.bios_protected_at else None,
    }), 200


# Owner marks "I've set my BIOS password".
@app.route('/api/device/<device_id>/bios-protected', methods=['POST'])
@jwt_required()
def set_bios_protected(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    data = request.get_json() or {}
    protected = bool(data.get('protected', True))
    device.bios_protected = protected
    device.bios_protected_at = datetime.utcnow() if protected else None
    db.session.commit()
    return jsonify({'message': 'BIOS protection status updated',
                    'protected': protected}), 200


# ── Account management: profile, password change, deletion ────────────────
@app.route('/api/user/me', methods=['GET'])
@jwt_required()
def get_me():
    """Returns the current user's profile for the Settings screen."""
    uid = get_jwt_identity()
    user = User.query.filter_by(id=uid).first()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    device_count = Device.query.filter_by(user_id=uid).count()
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'totp_enabled': bool(user.totp_enabled),
        'legal_accepted_at': user.legal_accepted_at.isoformat() if user.legal_accepted_at else None,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        'device_count': device_count,
    }), 200


@app.route('/api/user/update-profile', methods=['POST'])
@jwt_required()
def update_profile():
    """Updates the editable fields on the user profile: name + phone.
    Email changes are deliberately NOT allowed here — email is the primary
    identity + the password-reset channel, so changing it needs a dedicated
    verification flow we have not built yet."""
    uid = get_jwt_identity()
    user = User.query.filter_by(id=uid).first()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    phone = (data.get('phone') or '').strip()
    if name:
        user.name = name[:100]
    if phone:
        user.phone = phone[:20]
    db.session.commit()
    return jsonify({'message': 'Profile updated',
                    'name': user.name, 'phone': user.phone}), 200


@app.route('/api/user/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Requires current password + new password. On success, the user's
    existing tokens continue to work (they're already authenticated); the
    stored hash just changes."""
    uid = get_jwt_identity()
    user = User.query.filter_by(id=uid).first()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json() or {}
    current = data.get('current_password') or ''
    new_pass = data.get('new_password') or ''
    if not current or not new_pass:
        return jsonify({'error': 'Both current and new passwords are required'}), 400
    if len(new_pass) < 8:
        return jsonify({'error': 'New password must be at least 8 characters long'}), 400
    if not bcrypt.checkpw(current.encode('utf-8'),
                          user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Your current password is incorrect'}), 403
    user.password_hash = bcrypt.hashpw(
        new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.password_reset_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Password changed'}), 200


@app.route('/api/user/account', methods=['DELETE'])
@jwt_required()
def delete_account():
    """Hard-deletes the user account AND all their devices + related rows.
    Danger zone: typed email confirmation enforced here. Agents on paired
    devices will stop seeing valid heartbeats and self-stop after a few
    offline-lock cycles."""
    uid = get_jwt_identity()
    user = User.query.filter_by(id=uid).first()
    if not user:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json() or {}
    confirm = (data.get('confirm_email') or '').strip().lower()
    if confirm != (user.email or '').lower():
        return jsonify({'error':
            'Please type your email address exactly to confirm the deletion.'}), 400
    try:
        # Cascade clean-up. SQL foreign keys would do this for us but we
        # delete explicitly so the order is deterministic in SQLite dev mode.
        devices = Device.query.filter_by(user_id=user.id).all()
        for d in devices:
            # Queue a self-destruct for the agent on each device, in case
            # one of them is still online and able to receive it.
            try:
                db.session.add(Command(device_id=d.id, command_type='AGENT_UNINSTALL'))
            except Exception:
                pass
        db.session.commit()
        for d in devices:
            Command.query.filter_by(device_id=d.id).delete()
            EvidencePhoto.query.filter_by(device_id=d.id).delete()
            try: EvidenceKeylog.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: DeviceLocation.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: DeviceSystemInfo.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: DeviceNetworkInfo.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: DeviceDiskInfo.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: DeviceProcess.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: LocationHistory.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: Sighting.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            try: CommandHistory.query.filter_by(device_id=d.id).delete()
            except Exception: pass
            db.session.delete(d)
        EmergencyContact.query.filter_by(user_id=user.id).delete()
        try: PasswordResetOtp.query.filter_by(user_id=user.id).delete()
        except Exception: pass
        try: QuickLockOtp.query.filter_by(user_id=user.id).delete()
        except Exception: pass
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Deletion failed: {e}'}), 500
    return jsonify({'message': 'Account deleted'}), 200


# ── Emergency contacts: CRUD endpoints ────────────────────────────────────
@app.route('/api/user/emergency-contacts', methods=['GET'])
@jwt_required()
def list_emergency_contacts():
    uid = get_jwt_identity()
    contacts = EmergencyContact.query.filter_by(user_id=uid)\
        .order_by(EmergencyContact.created_at.asc()).all()
    return jsonify({'contacts': [
        {'id': c.id, 'name': c.name, 'email': c.email, 'phone': c.phone,
         'relationship': c.relationship} for c in contacts
    ]}), 200


@app.route('/api/user/emergency-contacts', methods=['POST'])
@jwt_required()
def add_emergency_contact():
    uid = get_jwt_identity()
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    email = (data.get('email') or '').strip() or None
    phone = (data.get('phone') or '').strip() or None
    if not email and not phone:
        return jsonify({'error': 'email or phone must be provided'}), 400
    c = EmergencyContact(
        user_id=uid, name=name, email=email, phone=phone,
        relationship=(data.get('relationship') or '').strip() or None,
    )
    db.session.add(c)
    db.session.commit()
    return jsonify({'id': c.id, 'message': 'Emergency contact added'}), 201


@app.route('/api/user/emergency-contacts/<contact_id>', methods=['DELETE'])
@jwt_required()
def delete_emergency_contact(contact_id):
    uid = get_jwt_identity()
    c = EmergencyContact.query.filter_by(id=contact_id, user_id=uid).first()
    if not c:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(c)
    db.session.commit()
    return jsonify({'message': 'Emergency contact removed'}), 200


# ── Email sender: used to deliver recovery PDF on mark-stolen ──────────────
# Reads SMTP settings from env vars; silently no-ops if any are missing so
# the backend keeps working for dev without SMTP configured.
#   SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS, SMTP_FROM
# For Gmail use smtp.gmail.com port 587 with an App Password (not your
# regular Gmail password — 2FA must be on).
def send_email_with_pdf(to_addrs, subject, body_text, pdf_bytes, pdf_filename,
                        reply_to=None):
    host = os.getenv('SMTP_HOST')
    user = os.getenv('SMTP_USER')
    pw   = os.getenv('SMTP_PASS')
    sender = os.getenv('SMTP_FROM') or user
    port = int(os.getenv('SMTP_PORT', '587'))
    if not (host and user and pw and sender):
        print("[email] SMTP not configured — skipping")
        return False
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]
    to_addrs = [a for a in to_addrs if a and '@' in a]
    if not to_addrs:
        print("[email] no valid recipients")
        return False
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.application import MIMEApplication
        msg = MIMEMultipart()
        msg['From'] = f'PhantomTrace <{sender}>'
        msg['To']   = ', '.join(to_addrs)
        msg['Subject'] = subject
        if reply_to:
            msg['Reply-To'] = reply_to
        msg.attach(MIMEText(body_text, 'plain'))
        if pdf_bytes:
            part = MIMEApplication(pdf_bytes, _subtype='pdf')
            part.add_header('Content-Disposition', 'attachment',
                            filename=pdf_filename)
            msg.attach(part)
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            s.login(user, pw)
            s.sendmail(sender, to_addrs, msg.as_string())
        print(f"[email] sent to {to_addrs} subj={subject!r}")
        return True
    except Exception as e:
        print(f"[email] send failed: {e}")
        return False


def dispatch_stolen_notifications(device):
    """When a device is marked stolen, build the recovery PDF and deliver
    it by email to the owner + all their emergency contacts, in a
    background thread so the HTTP response returns immediately."""
    def _work():
        try:
            owner = User.query.filter_by(id=device.user_id).first()
            if not owner:
                return
            pdf_buf = build_recovery_pdf(device.id, device)
            pdf_bytes = pdf_buf.read()
            pdf_name = f"PhantomTrace_Report_{(device.device_name or 'device').replace(' ', '_')}.pdf"

            recipients = []
            if owner.email: recipients.append(owner.email)
            contacts = EmergencyContact.query.filter_by(user_id=owner.id).all()
            for c in contacts:
                if c.email: recipients.append(c.email)
            if not recipients:
                print(f"[stolen-notify] device {device.id}: no email recipients configured")
                return

            subject = f"⚠️ {device.device_name or 'Your laptop'} marked STOLEN — PhantomTrace recovery report"
            body = (
                f"Hello,\n\n"
                f"{owner.name or 'The owner'} has marked the device '{device.device_name}' as STOLEN "
                f"on PhantomTrace. The initial recovery report is attached — it includes the last "
                f"known location, system fingerprint, and the latest captured evidence.\n\n"
                f"If you are not {owner.name or 'the owner'}, you were listed as an emergency contact. "
                f"Please get in touch with them immediately and share this report with the "
                f"authorities as needed.\n\n"
                f"— PhantomTrace\n"
            )
            send_email_with_pdf(recipients, subject, body, pdf_bytes, pdf_name,
                                reply_to=owner.email)
        except Exception as e:
            print(f"[stolen-notify] background job failed: {e}")

    import threading as _th
    _th.Thread(target=_work, daemon=True).start()


# ── Agent-triggered self-mark-stolen (no JWT, uses beacon_id proof) ────────
# Called by factory_reset_detector in the agent when it catches the thief
# in the middle of a Reset This PC. The agent is about to be wiped — we
# can't rely on it having a cached JWT. Instead we authenticate with the
# device's beacon_id (immutable, known only to the paired agent) + the
# device_id. If both match a Device row, we flip status.
@app.route('/api/device/self-mark-stolen', methods=['POST'])
def self_mark_stolen():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    beacon_id = data.get('beacon_id')
    reason    = data.get('reason', 'agent-trigger')
    if not device_id or not beacon_id:
        return jsonify({'error': 'Missing device_id or beacon_id'}), 400
    device = Device.query.filter_by(id=device_id, beacon_id=beacon_id).first()
    if not device:
        return jsonify({'error': 'Device + beacon mismatch'}), 403
    device.status = 'STOLEN'
    device.stolen_at = datetime.utcnow()
    db.session.commit()
    # Push notify the owner — this is urgent, the thief is literally wiping.
    try:
        notify_device_owner(
            device.id,
            '⚠️ Factory-reset attempt detected',
            f'Someone is wiping {device.device_name or "your laptop"} right now. '
            f'Fresh evidence captured. Reason: {reason}',
            {'device_id': str(device.id), 'kind': 'auto-stolen', 'reason': reason},
        )
    except Exception as e:
        print(f"[self-stolen] notify failed: {e}")
    # Also email the recovery PDF to the owner + emergency contacts.
    dispatch_stolen_notifications(device)
    return jsonify({'message': 'Device marked stolen', 'reason': reason}), 200


@app.route('/api/device/<device_id>/mark-stolen', methods=['POST'])
@jwt_required()
def mark_stolen(device_id):
    """Flip status to STOLEN AND immediately queue a 3-command evidence burst:
    one PHOTO + one SCREENSHOT + LOCK. The moment the owner realises the
    laptop is missing, we capture who is using it right now and lock the
    screen before the thief can react — three things in one tap."""
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.status = 'STOLEN'
    device.stolen_at = datetime.utcnow()

    # Auto-queue the forensic burst. Even if the device is offline right now,
    # these commands sit in the queue and fire the moment it comes back online.
    #   PHOTO + SCREENSHOT      — immediate evidence of who's using it
    #   LOCK                    — screen lock
    #   USB_LOCKDOWN            — disable USB mass storage, blocks data
    #                             exfiltration + USB-tool execution while
    #                             the thief is logged in
    #   ENABLE_BITLOCKER        — full-disk encryption so even if they wipe
    #                             the drive, your data is cryptographically gone
    for cmd_type in ('PHOTO', 'SCREENSHOT', 'LOCK',
                     'USB_LOCKDOWN', 'ENABLE_BITLOCKER'):
        db.session.add(Command(device_id=device_id, command_type=cmd_type))

    db.session.commit()

    # Background: email the recovery PDF to the owner and all their
    # emergency contacts. Fire-and-forget so the mobile request returns fast.
    dispatch_stolen_notifications(device)

    return jsonify({'message': 'Device marked stolen', 'status': 'STOLEN',
                    'auto_commands': ['PHOTO', 'SCREENSHOT', 'LOCK']}), 200

@app.route('/api/device/<device_id>/mark-found', methods=['POST'])
@jwt_required()
def mark_found(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.status = 'SAFE'
    # Reverse the USB storage lockdown so the owner can plug in their own
    # USB drives again. BitLocker stays on (that's a healthy default).
    db.session.add(Command(device_id=device_id, command_type='USB_UNLOCKDOWN'))
    db.session.commit()
    return jsonify({'message': 'Device marked safe', 'status': 'SAFE',
                    'auto_commands': ['USB_UNLOCKDOWN']}), 200

# ── T2: geofence (safe zone) — owner sets it, agent reads it ──────────────────
@app.route('/api/device/<device_id>/geofence', methods=['GET', 'POST'])
@jwt_required()
def device_geofence(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if request.method == 'POST':
        data = request.get_json() or {}
        device.home_lat = data.get('home_lat')
        device.home_lng = data.get('home_lng')
        device.geofence_radius = data.get('geofence_radius')
        db.session.commit()
        return jsonify({'message': 'Geofence saved'}), 200
    return jsonify({
        'home_lat': device.home_lat,
        'home_lng': device.home_lng,
        'geofence_radius': device.geofence_radius,
    }), 200

# ── T2: agent polls this for its status + geofence (no JWT, keyed by device id) ─
@app.route('/api/device/agent-config/<device_id>', methods=['GET'])
def agent_config(device_id):
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    return jsonify({
        'status': device.status,
        'home_lat': device.home_lat,
        'home_lng': device.home_lng,
        'geofence_radius': device.geofence_radius,
        'vault_key': device.vault_key,
        # T7: offline auto-lock threshold in minutes. Uses column if set,
        # else the agent falls back to its own default (15 min).
        'offline_lock_minutes': getattr(device, 'offline_lock_minutes', None),
        # T8: BitLocker status so the mobile app can show a shield state
        'bitlocker': {
            'protection':  getattr(device, 'bitlocker_protection', None),
            'conversion':  getattr(device, 'bitlocker_conversion', None),
            'percent':     getattr(device, 'bitlocker_percent', None),
            'method':      getattr(device, 'bitlocker_method', None),
            'key_escrowed': bool(getattr(device, 'bitlocker_recovery_key', None)),
        },
    }), 200


# T7: let the owner tune the offline-auto-lock threshold from the app
@app.route('/api/device/offline-lock-config', methods=['POST'])
@jwt_required()
def set_offline_lock_config():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    minutes   = data.get('minutes')
    if not device_id or minutes is None:
        return jsonify({'error': 'device_id and minutes required'}), 400
    try:
        minutes = int(minutes)
    except Exception:
        return jsonify({'error': 'minutes must be integer'}), 400
    if minutes < 1 or minutes > 240:
        return jsonify({'error': 'minutes must be 1..240'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.offline_lock_minutes = minutes
    db.session.commit()
    return jsonify({'message': f'Offline-lock threshold set to {minutes} min'}), 200


# ── T8: BitLocker orchestration ────────────────────────────────────────────
# 1) Agent → backend: report current BitLocker status of the C: volume (and
#    any others). We keep the SYSTEM volume's status on the device row.
@app.route('/api/device/bitlocker-status', methods=['POST'])
def bitlocker_status():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    volumes   = data.get('volumes', [])
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    sys_vol = next((v for v in volumes if str(v.get('volume','')).upper() == 'C:'), None)
    if sys_vol:
        device.bitlocker_protection = sys_vol.get('protection')
        device.bitlocker_conversion = sys_vol.get('conversion')
        try:
            p = sys_vol.get('percent')
            device.bitlocker_percent = int(p) if p is not None else None
        except Exception:
            device.bitlocker_percent = None
        device.bitlocker_method = sys_vol.get('encryption_method')
        device.bitlocker_updated_at = datetime.utcnow()
        db.session.commit()
    return jsonify({'message': 'BitLocker status recorded'}), 200


# 2) Agent → backend: escrow the 48-digit recovery key so the owner can
#    always recover data even if the device is wiped. Stored server-side
#    and only ever released to the authenticated owner via the endpoint
#    below.
@app.route('/api/device/bitlocker-key', methods=['POST'])
def bitlocker_key():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    key       = data.get('recovery_key')
    key_id    = data.get('key_id')
    if not device_id or not key:
        return jsonify({'error': 'device_id and recovery_key required'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.bitlocker_recovery_key = key
    device.bitlocker_key_id       = key_id
    db.session.commit()
    return jsonify({'message': 'Recovery key escrowed'}), 200


# 3) Owner → backend: fetch the recovery key. JWT-protected. Meant for the
#    "I need to recover my data" flow shown in the app after a wipe.
@app.route('/api/device/<device_id>/bitlocker-key', methods=['GET'])
@jwt_required()
def get_bitlocker_key(device_id):
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if not device.bitlocker_recovery_key:
        return jsonify({'error': 'No recovery key on file'}), 404
    return jsonify({
        'key_id':       device.bitlocker_key_id,
        'recovery_key': device.bitlocker_recovery_key,
    }), 200


# 4) Owner → backend: issue INSTANT_WIPE. Requires the device to already
#    be marked STOLEN and requires explicit "confirmed": true in the body.
#    Adds an extra layer above the agent's own safety gates.
@app.route('/api/device/instant-wipe', methods=['POST'])
@jwt_required()
def instant_wipe_endpoint():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    confirmed = bool(data.get('confirmed'))
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    if not confirmed:
        return jsonify({'error': 'confirmed=true required for destructive action'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if device.status != 'STOLEN':
        return jsonify({'error': 'Device is not marked STOLEN. Mark it first.'}), 409
    cmd = Command(device_id=device_id, command_type='INSTANT_WIPE')
    db.session.add(cmd)
    db.session.commit()
    return jsonify({'message': 'Instant wipe queued', 'command_id': cmd.id}), 201


# ── T9: Quick Lock by Phone Number ─────────────────────────────────────────
# Two endpoints + a public HTML page so a panicked victim on a borrowed
# phone can lock every device on their account with just their phone number
# + an SMS OTP. Modeled on Google's android.com/lock.
import hashlib as _hashlib, random as _random, string as _string

_QL_OTP_TTL_MIN     = 10   # OTP valid for 10 min
_QL_MAX_PER_HOUR    = 5    # anti-spam: max OTP requests per phone per hour
_QL_MAX_ATTEMPTS    = 5    # OTP tried wrong this many times → invalidated


def _normalize_phone(p):
    """Trim, strip spaces/dashes, keep the leading + if present."""
    if not p: return ""
    p = str(p).strip().replace(" ", "").replace("-", "")
    # Uganda-friendly nudge: '0712...' → '+256712...'
    if p.startswith("0") and len(p) == 10:
        p = "+256" + p[1:]
    return p


def _sha(x):
    return _hashlib.sha256(str(x).encode()).hexdigest()


def _send_otp_sms(phone, code):
    """
    Send the OTP by SMS. Uses Africa's Talking if AT_USERNAME + AT_API_KEY
    are set. Otherwise logs the code (dev mode) so you can read it in the
    Render logs while testing.
    """
    at_user = os.getenv('AT_USERNAME')
    at_key  = os.getenv('AT_API_KEY')
    at_from = os.getenv('AT_SENDER_ID', 'PhantomTrace')
    body    = f"PhantomTrace quick-lock code: {code}. Valid 10 min. Never share it."
    if at_user and at_key:
        try:
            import requests as _rq
            r = _rq.post(
                "https://api.africastalking.com/version1/messaging",
                headers={"apiKey": at_key, "Accept": "application/json"},
                data={"username": at_user, "to": phone, "from": at_from, "message": body},
                timeout=15)
            print(f"AT SMS to {phone}: {r.status_code}")
        except Exception as e:
            print(f"AT SMS failed: {e}")
    else:
        # Dev mode: log to Render so we can read it.
        print(f"[QUICK-LOCK OTP] phone={phone} code={code}  (no SMS provider configured)")


@app.route('/api/quick-lock/request-otp', methods=['POST'])
def quick_lock_request_otp():
    data = request.get_json() or {}
    phone = _normalize_phone(data.get('phone'))
    if not phone or len(phone) < 8:
        return jsonify({'error': 'Valid phone number required'}), 400

    # Rate limit: max N in last hour
    since = datetime.utcnow() - timedelta(hours=1)
    recent = QuickLockOtp.query.filter(
        QuickLockOtp.phone == phone,
        QuickLockOtp.created_at >= since).count()
    if recent >= _QL_MAX_PER_HOUR:
        return jsonify({'error': 'Too many requests. Try again in an hour.'}), 429

    # Whether or not the number is registered, respond identically to avoid
    # leaking which numbers belong to PhantomTrace accounts. Only really
    # send an SMS if the number IS registered.
    user = User.query.filter_by(phone=phone).first()
    if user:
        code = ''.join(_random.choices(_string.digits, k=6))
        otp = QuickLockOtp(
            phone=phone,
            code_hash=_sha(code),
            expires_at=datetime.utcnow() + timedelta(minutes=_QL_OTP_TTL_MIN),
            ip_address=request.headers.get('X-Forwarded-For', request.remote_addr or ''),
        )
        db.session.add(otp)
        db.session.commit()
        _send_otp_sms(phone, code)

    return jsonify({
        'message': 'If that number is registered, a code has been sent by SMS.',
        'ttl_minutes': _QL_OTP_TTL_MIN,
    }), 200


@app.route('/api/quick-lock/verify', methods=['POST'])
def quick_lock_verify():
    data = request.get_json() or {}
    phone = _normalize_phone(data.get('phone'))
    code  = str(data.get('code') or '').strip()
    if not phone or not code:
        return jsonify({'error': 'phone and code required'}), 400

    # Pick the newest un-used OTP for this phone
    otp = (QuickLockOtp.query
           .filter_by(phone=phone, used=False)
           .order_by(QuickLockOtp.created_at.desc())
           .first())
    if not otp:
        return jsonify({'error': 'No pending code for this number'}), 404
    if otp.expires_at < datetime.utcnow():
        return jsonify({'error': 'Code expired. Request a new one.'}), 410
    if otp.attempts >= _QL_MAX_ATTEMPTS:
        otp.used = True; db.session.commit()
        return jsonify({'error': 'Too many wrong attempts. Request a new code.'}), 429

    otp.attempts += 1
    if _sha(code) != otp.code_hash:
        db.session.commit()
        return jsonify({'error': 'Wrong code'}), 401

    otp.used = True
    db.session.commit()

    # Queue LOCK on every device this user owns
    user = User.query.filter_by(phone=phone).first()
    if not user:
        # Extra safety — shouldn't happen if we got here
        return jsonify({'error': 'No account for this number'}), 404

    devices = Device.query.filter_by(user_id=user.id).all()
    locked = []
    for d in devices:
        cmd = Command(device_id=d.id, command_type='LOCK')
        db.session.add(cmd)
        locked.append(d.id)
        # Also mark STOLEN so the agent's auto-response engages
        d.status = 'STOLEN'
        d.stolen_at = datetime.utcnow()
    db.session.commit()

    # Fire push to the owner's phone too, in case they've since found it
    try:
        notify_device_owner(devices[0].id if devices else None,
            "Quick Lock triggered",
            f"Your PhantomTrace-protected {'device' if len(locked)==1 else 'devices'} "
            f"({len(locked)}) have been locked from the quick-lock page.",
            {'source': 'quick-lock'})
    except Exception as e:
        print(f"quick-lock owner push failed: {e}")

    return jsonify({
        'message': f'Lock queued for {len(locked)} device(s)',
        'device_ids': locked,
    }), 200


# Simple public HTML page: the panic-lock screen
_QUICK_LOCK_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhantomTrace — Quick Lock</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box }
  body {
    margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0a0a0a; color: #eee; min-height: 100vh;
    display: flex; align-items: center; justify-content: center; padding: 16px;
  }
  .card {
    width: 100%; max-width: 420px; background: #141414;
    border: 1px solid #262626; border-radius: 16px; padding: 28px;
  }
  h1 { margin: 0 0 6px; font-size: 22px; color: #ff3b3b; }
  p.sub { margin: 0 0 22px; color: #999; font-size: 14px; }
  label { display: block; font-size: 13px; color: #aaa; margin-bottom: 6px }
  input {
    width: 100%; background: #0a0a0a; border: 1px solid #333; color: #fff;
    padding: 12px 14px; border-radius: 10px; font-size: 16px; outline: none;
  }
  input:focus { border-color: #ff3b3b }
  button {
    width: 100%; margin-top: 14px; background: #ff3b3b; color: #fff;
    border: 0; padding: 13px; font-size: 15px; font-weight: 600;
    border-radius: 10px; cursor: pointer;
  }
  button[disabled] { background: #4a2020; cursor: not-allowed }
  .msg { margin-top: 14px; font-size: 13px; color: #ffbb33; min-height: 18px }
  .ok  { color: #33cc66 }
  .hidden { display: none }
  .foot { margin-top: 22px; font-size: 12px; color: #666; text-align: center }
</style>
</head>
<body>
<div class="card">
  <h1>🔒 Quick Lock</h1>
  <p class="sub">Lock every PhantomTrace-protected device on your account. Only your phone number + an SMS code needed.</p>

  <div id="step1">
    <label for="phone">Your registered phone number</label>
    <input id="phone" type="tel" placeholder="+256712345678 or 0712345678" autofocus>
    <button id="btnSend" onclick="sendOtp()">Send code</button>
    <div id="msg1" class="msg"></div>
  </div>

  <div id="step2" class="hidden">
    <label for="code">Enter the 6-digit code from SMS</label>
    <input id="code" inputmode="numeric" maxlength="6" placeholder="••••••">
    <button id="btnLock" onclick="verify()">Lock my devices</button>
    <div id="msg2" class="msg"></div>
  </div>

  <div class="foot">PhantomTrace anti-theft · <span id="year"></span></div>
</div>
<script>
  document.getElementById('year').textContent = new Date().getFullYear();
  let phone = '';
  async function sendOtp(){
    const p = document.getElementById('phone').value.trim();
    if(!p){ return; }
    const btn = document.getElementById('btnSend');
    btn.disabled = true; btn.textContent = 'Sending…';
    const msg = document.getElementById('msg1');
    msg.textContent = ''; msg.className = 'msg';
    try{
      const r = await fetch('/api/quick-lock/request-otp', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({phone:p})
      });
      const d = await r.json();
      if(r.ok){
        phone = p;
        msg.textContent = d.message || 'Check your SMS.';
        msg.className = 'msg ok';
        document.getElementById('step1').classList.add('hidden');
        document.getElementById('step2').classList.remove('hidden');
        document.getElementById('code').focus();
      } else {
        msg.textContent = d.error || 'Failed to send code.';
      }
    } catch(e){ msg.textContent = 'Network error. Try again.'; }
    finally { btn.disabled = false; btn.textContent = 'Send code'; }
  }
  async function verify(){
    const code = document.getElementById('code').value.trim();
    if(!code){ return; }
    const btn = document.getElementById('btnLock');
    btn.disabled = true; btn.textContent = 'Locking…';
    const msg = document.getElementById('msg2');
    msg.textContent = ''; msg.className = 'msg';
    try{
      const r = await fetch('/api/quick-lock/verify', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({phone, code})
      });
      const d = await r.json();
      if(r.ok){
        msg.textContent = '✓ ' + (d.message || 'Devices locked.');
        msg.className = 'msg ok';
        btn.textContent = 'Locked';
      } else {
        msg.textContent = d.error || 'Verification failed.';
        btn.disabled = false; btn.textContent = 'Lock my devices';
      }
    } catch(e){ msg.textContent = 'Network error.'; btn.disabled = false;
      btn.textContent = 'Lock my devices'; }
  }
  document.getElementById('code')?.addEventListener('keydown', e => {
    if(e.key==='Enter') verify();
  });
  document.getElementById('phone').addEventListener('keydown', e => {
    if(e.key==='Enter') sendOtp();
  });
</script>
</body></html>
"""


@app.route('/quicklock', methods=['GET'])
def quick_lock_page():
    from flask import Response
    return Response(_QUICK_LOCK_HTML, mimetype='text/html')


# ── T5: agent stores the vault key it generated (so the owner can restore) ─────
@app.route('/api/device/vault-key', methods=['POST'])
def store_vault_key():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    key = data.get('key')
    if not device_id or not key:
        return jsonify({'error': 'Missing device_id or key'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.vault_key = key
    db.session.commit()
    return jsonify({'message': 'Vault key stored'}), 200

# ── T2: agent reports an automatic trigger → push to the owner ────────────────
@app.route('/api/device/alert', methods=['POST'])
def device_alert():
    data = request.get_json() or {}
    device_id = data.get('device_id')
    title = data.get('title', 'PhantomTrace alert')
    body = data.get('body', '')
    if not device_id:
        return jsonify({'error': 'Missing device_id'}), 400
    notify_device_owner(device_id, title, body, {'device_id': str(device_id), 'kind': 'auto'})
    print(f"Auto-alert for {device_id}: {title} — {body}")
    return jsonify({'message': 'Alert dispatched'}), 200

# ── T3: police-ready recovery report (PDF) ────────────────────────────────────
@app.route('/api/device/<device_id>/report', methods=['GET'])
@jwt_required()
def recovery_report(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    # ?capture_fresh=1  → queue a fresh PHOTO + SCREENSHOT and wait up to
    # ~25 seconds for them to arrive before building the report. This gives
    # the owner current evidence of exactly who is using the laptop at
    # report-generation time, not a mix of old pictures from before theft.
    capture_fresh = request.args.get('capture_fresh', '').lower() in ('1', 'true', 'yes')
    capture_status = None
    if capture_fresh:
        capture_status = _capture_fresh_evidence(device_id, device)

    pdf = build_recovery_pdf(device_id, device,
                             fresh_capture_status=capture_status)
    fname = f"PhantomTrace_Report_{(device.device_name or 'device').replace(' ', '_')}.pdf"
    return send_file(pdf, mimetype='application/pdf',
                     as_attachment=True, download_name=fname)


def _capture_fresh_evidence(device_id, device, timeout_seconds=55):
    """Queue PHOTO + SCREENSHOT commands and wait for BOTH new EvidencePhoto
    rows to arrive before returning.

    Behaviour: keep waiting UNTIL either
      (a) both captures have arrived in the DB (ideal),
      (b) the device goes offline during the wait (no point waiting more),
      (c) we hit timeout_seconds (default 55s — mobile receiveTimeout is
          60s, so we leave 5s headroom to render + ship the PDF).

    Returns a dict used by the PDF builder for its "capture status" banner.
    """
    import time as _time

    # Baseline: how many photos exist RIGHT NOW. We'll poll until it grows.
    baseline_count = EvidencePhoto.query.filter_by(device_id=device_id).count()

    def _is_online():
        """Re-check heartbeat freshness. We re-read Device so we see the
        agent's latest heartbeat during the wait, not a stale snapshot."""
        d = Device.query.filter_by(id=device_id).first()
        if not d or not d.last_seen: return False
        return (datetime.utcnow() - d.last_seen).total_seconds() < 30

    if not _is_online():
        return {'attempted': True, 'online': False,
                'new_photos': 0,
                'message': 'Device was offline — fresh capture skipped. '
                           'The report uses the latest existing images.'}

    # Queue both commands. Agent polls every 3s, so first command fires <3s.
    try:
        for cmd_type in ('PHOTO', 'SCREENSHOT'):
            db.session.add(Command(device_id=device_id, command_type=cmd_type))
        db.session.commit()
    except Exception as e:
        return {'attempted': True, 'online': True, 'new_photos': 0,
                'message': f'Could not queue capture: {e}'}

    # Poll until BOTH captures arrive, the device goes offline, or timeout.
    # Faster poll cadence (1.5s) so the PDF ships the moment the second
    # image lands — no artificial waiting past "done".
    deadline = _time.monotonic() + timeout_seconds
    last_count = baseline_count
    while _time.monotonic() < deadline:
        _time.sleep(1.5)
        try:
            db.session.expire_all()
            last_count = EvidencePhoto.query.filter_by(device_id=device_id).count()
            if last_count >= baseline_count + 2:
                break   # BOTH arrived — stop waiting
            # If the device drops offline during the wait, there's no point
            # staring at the clock waiting for a disconnected laptop.
            if not _is_online():
                return {'attempted': True, 'online': False,
                        'new_photos': max(0, last_count - baseline_count),
                        'message': 'Device went offline during capture. '
                                   'The report uses whatever arrived + '
                                   'the latest existing images.'}
        except Exception:
            pass

    new_photos = max(0, last_count - baseline_count)
    if new_photos >= 2:
        msg = 'Fresh webcam shot and screenshot captured just now.'
    elif new_photos == 1:
        msg = ('One fresh capture arrived in time; the other is still '
               'uploading and will appear in the next report.')
    else:
        msg = ('Capture commands were sent but no new evidence arrived '
               'in time (the device may be slow or the thief may have '
               'disabled the camera). The report uses the latest existing images.')
    return {'attempted': True, 'online': True,
            'new_photos': new_photos, 'message': msg}


def build_recovery_pdf(device_id, device, fresh_capture_status=None):
    """Assemble a recovery report PDF from everything we know about the device.
    `fresh_capture_status` is the dict returned by _capture_fresh_evidence()
    when the owner asked for fresh pictures; the PDF prints a short banner
    telling the reader whether current evidence was captured or not."""
    import io, requests as _rq
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Image as RLImage)

    owner = User.query.filter_by(id=device.user_id).first()
    loc = db.session.execute(
        db.text("SELECT * FROM device_location WHERE device_id=:id"),
        {"id": device_id}).mappings().first()
    sysinfo = db.session.execute(
        db.text("SELECT * FROM device_system_info WHERE device_id=:id"),
        {"id": device_id}).mappings().first()
    netinfo = db.session.execute(
        db.text("SELECT * FROM device_network_info WHERE device_id=:id"),
        {"id": device_id}).mappings().first()
    # ── Evidence selection: latest 2 webcam shots + latest 2 screenshots ──
    # Dumping every photo ever captured pollutes the report with old test
    # shots from before the device was stolen. Pick only the freshest
    # evidence of each kind — that's what police need: "the person using it
    # right now" and "what they are doing on the screen right now".
    _MAX_PER_TYPE = 2

    def _latest_of(keywords, limit):
        """Return up to `limit` latest photos whose photo_type contains any
        of the given keywords (case-insensitive match on substring)."""
        return [p for p in EvidencePhoto.query.filter_by(device_id=device_id)
                .order_by(EvidencePhoto.timestamp.desc()).all()
                if any(k in (p.photo_type or '').lower() for k in keywords)][:limit]

    webcam_photos = _latest_of(('webcam', 'photo', 'camera'), _MAX_PER_TYPE)
    screen_photos = _latest_of(('screen',), _MAX_PER_TYPE)

    # Interleave: webcam first (the face is the strongest evidence), then
    # screenshot, alternating so the report doesn't dump every face page before
    # the first screen capture.
    photos = []
    for i in range(_MAX_PER_TYPE):
        if i < len(webcam_photos): photos.append(webcam_photos[i])
        if i < len(screen_photos): photos.append(screen_photos[i])
    sightings = LocationHistory.query.filter_by(device_id=device_id)\
        .order_by(LocationHistory.timestamp.desc()).limit(30).all()

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle('h1', parent=styles['Title'], fontSize=20, spaceAfter=2)
    sub = ParagraphStyle('sub', parent=styles['Normal'], fontSize=9,
                         textColor=colors.grey)
    h2 = ParagraphStyle('h2', parent=styles['Heading2'], fontSize=13,
                        textColor=colors.HexColor('#1F2937'), spaceBefore=14, spaceAfter=6)
    normal = styles['Normal']

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=18*mm, rightMargin=18*mm,
                            topMargin=16*mm, bottomMargin=16*mm)
    story = []

    def kv_table(rows):
        t = Table([[Paragraph(f"<b>{k}</b>", normal), Paragraph(str(v), normal)]
                   for k, v in rows], colWidths=[55*mm, 110*mm])
        t.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (-1, -1), 0.25, colors.HexColor('#E5E7EB')),
        ]))
        return t

    # Header
    story.append(Paragraph("PhantomTrace", h1))
    story.append(Paragraph("Device Recovery Report", sub))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub))
    story.append(Spacer(1, 8))
    status_color = '#EF4444' if device.status == 'STOLEN' else '#22C55E'
    story.append(Paragraph(
        f'<font color="{status_color}"><b>STATUS: {device.status}</b></font>', normal))

    # Owner
    story.append(Paragraph("Registered Owner", h2))
    story.append(kv_table([
        ("Name", owner.name if owner else "—"),
        ("Email", owner.email if owner else "—"),
        ("Phone", owner.phone if owner else "—"),
    ]))

    # Device
    story.append(Paragraph("Device", h2))
    story.append(kv_table([
        ("Device name", device.device_name),
        ("Device ID", device.id),
        ("Beacon ID", device.beacon_id),
        ("Registered", device.registered_at.strftime('%Y-%m-%d %H:%M') if device.registered_at else "—"),
        ("Marked stolen", device.stolen_at.strftime('%Y-%m-%d %H:%M') if device.stolen_at else "—"),
        ("Last seen", device.last_seen.strftime('%Y-%m-%d %H:%M') if device.last_seen else "—"),
    ]))

    # System + network
    if sysinfo or netinfo:
        story.append(Paragraph("System & Network", h2))
        rows = []
        if sysinfo:
            rows += [("Hostname", sysinfo.get('hostname', '—')),
                     ("Username", sysinfo.get('username', '—')),
                     ("OS", f"{sysinfo.get('os_name','')} {sysinfo.get('os_version','')}".strip() or '—')]
        if netinfo:
            rows += [("IP address", netinfo.get('ip_address', '—')),
                     ("MAC address", netinfo.get('mac_address', '—'))]
        story.append(kv_table(rows))

    # Last known location
    if loc:
        story.append(Paragraph("Last Known Location", h2))
        lat, lng = loc.get('latitude'), loc.get('longitude')
        maps = f"https://www.google.com/maps?q={lat},{lng}" if lat and lng else "—"
        story.append(kv_table([
            ("Coordinates", f"{lat}, {lng}" if lat and lng else "—"),
            ("Area", loc.get('area') or "—"),
            ("City", loc.get('city') or "—"),
            ("Country", loc.get('country') or "—"),
            ("ISP", loc.get('isp') or "—"),
            ("IP at location", loc.get('ip_address') or "—"),
            ("Updated", str(loc.get('updated_at') or "—")),
            ("Map link", f'<link href="{maps}"><font color="#3B82F6">{maps}</font></link>'),
        ]))

    # Location history
    if sightings:
        story.append(Paragraph("Location History", h2))
        data = [["Timestamp (UTC)", "Latitude", "Longitude", "Method"]]
        for s in sightings:
            data.append([
                s.timestamp.strftime('%Y-%m-%d %H:%M') if s.timestamp else "—",
                f"{s.latitude:.5f}" if s.latitude is not None else "—",
                f"{s.longitude:.5f}" if s.longitude is not None else "—",
                s.method or "—",
            ])
        t = Table(data, colWidths=[45*mm, 40*mm, 40*mm, 30*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F3F4F6')]),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#E5E7EB')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t)

    # ── Evidence photos (webcam shots of thief + screenshots of thief activity) ──
    # These are the single most important page of a recovery report: the police
    # need to SEE the person using the device. We render them large (full
    # content width, up to ~150 mm) with bold, prominent captions giving the
    # exact timestamp and whether it was a webcam shot or a screen capture.
    if photos:
        from reportlab.platypus import PageBreak, KeepTogether
        story.append(PageBreak())
        story.append(Paragraph("Captured Evidence", h1))

        # Fresh-capture banner: if the owner asked us to capture fresh evidence
        # before building the report, say what happened. This matters because
        # the reader (police, insurance) will want to know whether these images
        # are from minutes ago or weeks ago.
        if fresh_capture_status:
            msg = fresh_capture_status.get('message') or ''
            banner_color = ('#047857' if fresh_capture_status.get('new_photos', 0) >= 1
                            else '#B45309')
            story.append(Paragraph(
                f'<font color="{banner_color}"><b>Capture status:</b> {msg}</font>',
                normal))
            story.append(Spacer(1, 8))

        story.append(Paragraph(
            f"The following {len(photos)} image(s) are the most recent "
            "evidence captured by the PhantomTrace agent — up to two webcam "
            "shots of the person using the device and up to two screenshots "
            "of their on-screen activity. Older captures from before the "
            "device went missing are intentionally not included.", normal))
        story.append(Spacer(1, 12))

        # Bold, prominent caption style for each evidence item.
        evidence_cap = ParagraphStyle(
            'evcap', parent=styles['Normal'], fontSize=11,
            textColor=colors.HexColor('#111827'),
            spaceBefore=4, spaceAfter=4,
        )
        evidence_sub = ParagraphStyle(
            'evsub', parent=styles['Normal'], fontSize=9,
            textColor=colors.grey, spaceAfter=10,
        )

        for idx, p in enumerate(photos, start=1):
            try:
                # file_path may be either a Cloudinary URL (future) or a local
                # filesystem path (current). HTTP-GET only for the URL case;
                # open local files directly, no network round-trip.
                fp = p.file_path or ''
                if fp.lower().startswith(('http://', 'https://')):
                    r = _rq.get(fp, timeout=15)
                    if r.status_code != 200:
                        raise Exception(f"HTTP {r.status_code}")
                    img_bytes = r.content
                else:
                    if not os.path.exists(fp):
                        raise Exception("file no longer on disk "
                                        "(Render ephemeral storage lost it)")
                    with open(fp, 'rb') as _f:
                        img_bytes = _f.read()
                img = RLImage(io.BytesIO(img_bytes))
                iw, ih = img.imageWidth, img.imageHeight
                # Scale to full content width (A4 - margins ≈ 174mm). Cap height
                # at 180mm so a very tall screenshot still fits on one page.
                max_w = 150 * mm
                max_h = 180 * mm
                scale = min(max_w / iw, max_h / ih, 1.0)
                img.drawWidth = iw * scale
                img.drawHeight = ih * scale

                # Human-readable capture-type label.
                ptype = (p.photo_type or '').lower()
                if 'screen' in ptype:
                    kind_label = "Screenshot (thief's screen activity)"
                elif 'webcam' in ptype or 'photo' in ptype or 'camera' in ptype:
                    kind_label = "Webcam capture (person using the device)"
                else:
                    kind_label = p.photo_type or 'Capture'

                ts = p.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if p.timestamp else 'time unknown'

                # Keep each evidence item (caption + image + subcaption) on
                # one page where possible.
                story.append(KeepTogether([
                    Paragraph(f"<b>Evidence #{idx} — {kind_label}</b>", evidence_cap),
                    Paragraph(f"Captured: {ts}", evidence_sub),
                    img,
                    Spacer(1, 20),
                ]))
            except Exception as _ie:
                story.append(Paragraph(
                    f"<b>Evidence #{idx}</b> — image file could not be retrieved "
                    f"({p.photo_type or 'capture'}, "
                    f"{p.timestamp.strftime('%Y-%m-%d %H:%M') if p.timestamp else 'time unknown'}). "
                    f"Original URL: {p.file_path}", evidence_sub))
                story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Captured Evidence", h2))
        if fresh_capture_status and not fresh_capture_status.get('online'):
            story.append(Paragraph(
                "<b>Fresh capture was requested but the device is currently "
                "offline.</b> No evidence images could be gathered. New photos "
                "will arrive once the device comes online and the owner can "
                "regenerate this report.", normal))
        elif fresh_capture_status and fresh_capture_status.get('new_photos', 0) == 0:
            story.append(Paragraph(
                "Fresh capture was requested; capture commands were sent to "
                "the device but no new images arrived in time. Try regenerating "
                "this report in a minute or two.", normal))
        else:
            story.append(Paragraph(
                "No webcam captures or screenshots have been recorded for this "
                "device yet. The PhantomTrace agent captures evidence automatically "
                "once the device is marked stolen and comes online.", normal))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "This report was generated by PhantomTrace, an anti-theft and recovery "
        "platform. The information above is provided by the registered owner to "
        "assist in recovering a lost or stolen device.", sub))

    doc.build(story)
    buf.seek(0)
    return buf

@app.route('/api/sighting/bluetooth', methods=['POST'])
def bluetooth_sighting():
    data = request.get_json()
    if not data or not all(k in data for k in ['beacon_id','latitude','longitude']):
        return jsonify({'error': 'Missing fields'}), 400
    device = Device.query.filter_by(beacon_id=data['beacon_id']).first()
    if not device or device.status != 'STOLEN':
        return jsonify({'status': 'safe'}), 200
    sighting = Sighting(device_id=device.id, latitude=data['latitude'], longitude=data['longitude'], method='BLE')
    db.session.add(sighting)
    db.session.commit()
    socketio.emit(f'sighting_{device.id}', {'latitude': data['latitude'], 'longitude': data['longitude'], 'method': 'BLE'})
    return jsonify({'status': 'reported'}), 200

@app.route('/api/sighting/gsm', methods=['POST'])
def gsm_sighting():
    data = request.get_json()
    if not data or not all(k in data for k in ['device_id','latitude','longitude']):
        return jsonify({'error': 'Missing fields'}), 400
    sighting = Sighting(device_id=data['device_id'], latitude=data['latitude'], longitude=data['longitude'], method='GSM')
    db.session.add(sighting)
    db.session.commit()
    socketio.emit(f'sighting_{data["device_id"]}', {'latitude': data['latitude'], 'longitude': data['longitude'], 'method': 'GSM'})
    return jsonify({'status': 'reported'}), 200

@app.route('/api/sighting/trail/<device_id>', methods=['GET'])
@jwt_required()
def get_trail(device_id):
    sightings = Sighting.query.filter_by(device_id=device_id).order_by(Sighting.timestamp.asc()).all()
    return jsonify({'trail': [{'latitude': s.latitude, 'longitude': s.longitude, 'method': s.method, 'timestamp': s.timestamp.isoformat()} for s in sightings]}), 200

# Location trail the mobile app reads — built from the agent's own location reports
@app.route('/api/sightings/<device_id>', methods=['GET'])
@jwt_required()
def sightings_list(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    rows = LocationHistory.query.filter_by(device_id=device_id)\
        .order_by(LocationHistory.timestamp.desc()).limit(100).all()
    return jsonify({'sightings': [{
        'id': r.id,
        'latitude': r.latitude,
        'longitude': r.longitude,
        'city': r.city or 'Unknown',
        'country': r.country or 'Unknown',
        'isp': r.isp or 'Unknown',
        'ip_address': r.ip_address or 'Unknown',
        'area': r.area or '',
        'method': r.method or 'WIFI',
        'timestamp': r.timestamp.isoformat() if r.timestamp else '',
    } for r in rows]}), 200

@app.route('/api/device/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json()
    if not data or 'device_id' not in data:
        return jsonify({'error': 'Missing device_id'}), 400
    device = Device.query.filter_by(id=data['device_id']).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    was_offline = device.last_seen is None or (datetime.utcnow() - device.last_seen).total_seconds() > 30
    device.last_seen = datetime.utcnow()
    db.session.commit()
    if was_offline:
        notify_device_owner(device.id, '🟢 Device Online', f'{device.device_name} is now online', {'device_id': device.id})
    # Return status + stolen_at so the agent can decide to fire a last-online
    # evidence burst (handled in the agent's main loop).
    return jsonify({
        'message': 'Heartbeat received',
        'timestamp': device.last_seen.isoformat(),
        'status': device.status,
        'stolen_at': device.stolen_at.isoformat() if device.stolen_at else None,
    }), 200

@app.route('/api/device/systeminfo', methods=['POST'])
def device_systeminfo():
    data = request.get_json()
    sql = """
    INSERT INTO device_system_info
    (device_id, hostname, username, os_name, os_version, updated_at)
    VALUES (:device_id, :hostname, :username, :os_name, :os_version, NOW())
    ON CONFLICT (device_id)
    DO UPDATE SET
        hostname = EXCLUDED.hostname,
        username = EXCLUDED.username,
        os_name = EXCLUDED.os_name,
        os_version = EXCLUDED.os_version,
        updated_at = NOW()
    """
    db.session.execute(db.text(sql), {
        "device_id": data.get("device_id"),
        "hostname": data.get("hostname"),
        "username": data.get("user"),
        "os_name": data.get("os"),
        "os_version": data.get("version")
    })
    db.session.commit()
    return jsonify({"message":"System info saved"}), 200

@app.route('/api/device/networkinfo', methods=['POST'])
def device_networkinfo():
    data = request.get_json()
    sql = '''
    INSERT INTO device_network_info
    (device_id, hostname, ip_address, mac_address, updated_at)
    VALUES (:device_id, :hostname, :ip_address, :mac_address, NOW())
    ON CONFLICT (device_id)
    DO UPDATE SET
        hostname = EXCLUDED.hostname,
        ip_address = EXCLUDED.ip_address,
        mac_address = EXCLUDED.mac_address,
        updated_at = NOW()
    '''
    db.session.execute(db.text(sql), data)
    db.session.commit()
    return jsonify({'message':'Network info saved'}), 200

@app.route('/api/device/diskinfo', methods=['POST'])
def device_diskinfo():
    data = request.get_json()
    sql = '''
    INSERT INTO device_disk_info
    (device_id, total_gb, used_gb, free_gb, updated_at)
    VALUES (:device_id, :total_gb, :used_gb, :free_gb, NOW())
    ON CONFLICT (device_id)
    DO UPDATE SET
        total_gb = EXCLUDED.total_gb,
        used_gb = EXCLUDED.used_gb,
        free_gb = EXCLUDED.free_gb,
        updated_at = NOW()
    '''
    db.session.execute(db.text(sql), data)
    db.session.commit()
    return jsonify({'message':'Disk info saved'}), 200

@app.route('/api/device/processes', methods=['POST'])
def device_processes():
    data = request.get_json()
    device_id = data.get('device_id')
    processes = data.get('processes', [])
    db.session.execute(db.text("DELETE FROM device_processes WHERE device_id=:id"), {"id": device_id})
    for proc in processes:
        db.session.execute(
            db.text("INSERT INTO device_processes(device_id, process_name) VALUES(:device_id,:process_name)"),
            {"device_id": device_id, "process_name": proc}
        )
    db.session.commit()
    return jsonify({"message":"Processes saved"}), 200

_ALLOWED_COMMANDS = {
    'LOCK','PHOTO','ALARM','AUDIO','WIPE','SYSTEM_INFO','GET_NETWORK',
    'GET_DISKS','GET_PROCESSES','SCREENSHOT','GET_LOCATION','STOP_ALARM',
    'SECURE_DATA','RESTORE_DATA',
    'DETERRENT_LOCK','UNLOCK_DETERRENT',                        # T4
    'BITLOCKER_STATUS','ENABLE_BITLOCKER','INSTANT_WIPE',       # T8
    'USB_LOCKDOWN','USB_UNLOCKDOWN',                            # Layer A
    'AGENT_UNINSTALL',                                           # v1 self-destruct
}

@app.route('/api/command/send', methods=['POST'])
@jwt_required()
def send_command():
    data = request.get_json() or {}
    if not all(k in data for k in ['device_id','command_type']):
        return jsonify({'error': 'Missing fields'}), 400
    if data['command_type'] not in _ALLOWED_COMMANDS:
        return jsonify({'error': 'Invalid command'}), 400

    # T4: optional payload for commands that carry data
    payload_text = None
    payload = data.get('payload')
    if payload is not None:
        try:
            payload_text = _json.dumps(payload) if not isinstance(payload, str) else payload
        except Exception:
            payload_text = None

    command = Command(device_id=data['device_id'],
                      command_type=data['command_type'],
                      payload=payload_text)
    db.session.add(command)
    db.session.commit()
    return jsonify({'message': 'Command queued', 'command_id': command.id}), 201


@app.route('/api/command/pending/<device_id>', methods=['GET'])
def get_pending(device_id):
    commands = Command.query.filter_by(device_id=device_id, status='PENDING').all()
    out = []
    for c in commands:
        row = {'id': c.id, 'command_type': c.command_type}
        if c.payload:
            try:
                row['payload'] = _json.loads(c.payload)
            except Exception:
                row['payload'] = c.payload
        out.append(row)
    return jsonify({'commands': out}), 200


# T4: convenience endpoint for the mobile app. Takes the owner's message and
# either a supplied unlock_code or auto-generates one; returns the code so the
# app can show it to the owner ("your unlock code is 4829").
@app.route('/api/device/deterrent-lock', methods=['POST'])
@jwt_required()
def deterrent_lock_endpoint():
    import random, string
    data = request.get_json() or {}
    device_id = data.get('device_id')
    if not device_id:
        return jsonify({'error': 'device_id required'}), 400
    message = (data.get('message') or '').strip()
    if not message:
        return jsonify({'error': 'message required'}), 400
    unlock_code = str(data.get('unlock_code') or '').strip()
    if not unlock_code:
        unlock_code = ''.join(random.choices(string.digits, k=6))

    payload = {'message': message, 'unlock_code': unlock_code}
    cmd = Command(device_id=device_id,
                  command_type='DETERRENT_LOCK',
                  payload=_json.dumps(payload))
    db.session.add(cmd)
    db.session.commit()
    return jsonify({
        'message':    'Deterrent lock queued',
        'command_id': cmd.id,
        'unlock_code': unlock_code,   # shown to owner in the app
    }), 201

@app.route('/api/command/acknowledge/<command_id>', methods=['POST'])
def acknowledge(command_id):
    command = Command.query.get(command_id)
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    command.status = 'DONE'
    command.executed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Acknowledged'}), 200

VAULT = os.path.join(os.path.dirname(__file__), 'evidence_vault')
os.makedirs(VAULT, exist_ok=True)

@app.route('/api/evidence/photo', methods=['POST'])
def upload_photo():
    device_id = request.form.get('device_id')
    photo_type = request.form.get('photo_type', 'SCREENSHOT')
    if not device_id or 'photo' not in request.files:
        return jsonify({'error': 'Missing device_id or photo'}), 400
    file = request.files['photo']
    filename = f"{device_id}_{photo_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jpg"
    filepath = os.path.join(VAULT, filename)
    file.save(filepath)
    photo = EvidencePhoto(device_id=device_id, file_path=filepath, photo_type=photo_type)
    db.session.add(photo)
    db.session.commit()
    return jsonify({'message': 'Photo saved', 'id': photo.id, 'photo_type': photo_type}), 201


# Serve a raw evidence file by its DB id. Public (no JWT) because the id is
# a hard-to-guess integer and this endpoint is used by both the mobile app
# and the PDF generator to render inline images. Returns 404 if the file is
# missing from disk (e.g. lost in a Render container restart).
@app.route('/api/evidence/file/<int:photo_id>', methods=['GET'])
def serve_evidence_file(photo_id):
    photo = EvidencePhoto.query.filter_by(id=photo_id).first()
    if not photo:
        return jsonify({'error': 'Not found'}), 404
    # If file_path is an http(s) URL (future Cloudinary migration), redirect.
    if photo.file_path and photo.file_path.lower().startswith(('http://', 'https://')):
        from flask import redirect
        return redirect(photo.file_path, code=302)
    # Otherwise it's a local filesystem path.
    if not photo.file_path or not os.path.exists(photo.file_path):
        return jsonify({'error': 'Evidence file missing from server storage. '
                                  'This happens on Render after a redeploy — '
                                  'the next capture will persist again.'}), 410
    return send_file(photo.file_path, mimetype='image/jpeg')

@app.route('/api/evidence/keylog', methods=['POST'])
def upload_keylog():
    data = request.get_json()
    if not data or not all(k in data for k in ['device_id','keylog_text']):
        return jsonify({'error': 'Missing fields'}), 400
    keylog = EvidenceKeylog(device_id=data['device_id'], keylog_text=data['keylog_text'])
    db.session.add(keylog)
    db.session.commit()
    return jsonify({'message': 'Keylog saved'}), 201

@app.route('/api/evidence/photos/<device_id>', methods=['GET'])
@jwt_required()
def get_photos(device_id):
    photos = (
        EvidencePhoto.query
        .filter_by(device_id=device_id)
        .order_by(EvidencePhoto.timestamp.desc())
        .all()
    )
    return jsonify({
        'photos': [
            {
                'id': p.id,
                'timestamp': p.timestamp.isoformat(),
                'file_path': p.file_path,
                'photo_type': p.photo_type
            }
            for p in photos
        ]
    }), 200

@app.route('/api/evidence/photo/<photo_id>', methods=['GET', 'DELETE'])
def get_photo(photo_id):
    photo = EvidencePhoto.query.filter_by(id=photo_id).first()
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404
    if request.method == 'DELETE':
        import os
        try:
            os.remove(photo.file_path)
        except Exception:
            pass
        db.session.delete(photo)
        db.session.commit()
        return jsonify({'message': 'Deleted'}), 200
    return send_file(photo.file_path)


@app.route('/api/device/location', methods=['POST'])
def device_location():
    data = request.get_json()
    device_id = data.get('device_id')
    existing = db.session.execute(
        db.text("SELECT device_id FROM device_location WHERE device_id=:id"),
        {"id": device_id}
    ).first()
    if existing:
        db.session.execute(
            db.text("UPDATE device_location SET latitude=:lat, longitude=:lon, city=:city, country=:country, isp=:isp, ip_address=:ip, area=:area, updated_at=NOW() WHERE device_id=:device_id"),
            {"lat": data.get("latitude"), "lon": data.get("longitude"), "city": data.get("city"),
             "country": data.get("country"), "isp": data.get("isp"), "ip": data.get("ip_address"), "area": data.get("area", ""), "device_id": device_id}
        )
    else:
        db.session.execute(
            db.text("INSERT INTO device_location (device_id, latitude, longitude, city, country, isp, ip_address, area, updated_at) VALUES(:device_id,:lat,:lon,:city,:country,:isp,:ip,:area,NOW())"),
            {"device_id": device_id, "lat": data.get("latitude"), "lon": data.get("longitude"),
             "city": data.get("city"), "country": data.get("country"), "isp": data.get("isp"), "ip": data.get("ip_address"), "area": data.get("area", "")}
        )
    db.session.commit()
    # Append to the movement trail, skipping near-identical consecutive points
    try:
        lat = data.get("latitude"); lon = data.get("longitude")
        if lat is not None and lon is not None:
            last = db.session.execute(
                db.text("SELECT latitude, longitude FROM location_history "
                        "WHERE device_id=:id ORDER BY timestamp DESC LIMIT 1"),
                {"id": device_id}).first()
            moved = (last is None) or \
                    (abs((last[0] or 0) - lat) > 0.0002 or abs((last[1] or 0) - lon) > 0.0002)
            if moved:
                db.session.add(LocationHistory(
                    device_id=device_id, latitude=lat, longitude=lon,
                    city=data.get("city"), country=data.get("country"),
                    isp=data.get("isp"), ip_address=data.get("ip_address"),
                    area=data.get("area", ""), method="WIFI"))
                db.session.commit()
    except Exception as _lhe:
        db.session.rollback()
        print(f"location history error: {_lhe}")
    return jsonify({"message": "Location saved"}), 200

@app.route('/api/device/overview/<device_id>', methods=['GET'])
def device_overview(device_id):
    system_info = db.session.execute(db.text("SELECT * FROM device_system_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    network_info = db.session.execute(db.text("SELECT * FROM device_network_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    disk_info = db.session.execute(db.text("SELECT * FROM device_disk_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    process_count = db.session.execute(db.text("SELECT COUNT(*) FROM device_processes WHERE device_id=:id"), {"id": device_id}).scalar()
    location_info = db.session.execute(db.text("SELECT * FROM device_location WHERE device_id=:id"), {"id": device_id}).mappings().first()
    device = Device.query.filter_by(id=device_id).first()
    online = False
    last_seen = None
    if device:
        last_seen = device.last_seen.isoformat() if device.last_seen else None
        if device.last_seen:
            online = (datetime.utcnow() - device.last_seen).total_seconds() < 30
    return jsonify({
        "online": online,
        "last_seen": last_seen,
        "system_info": dict(system_info) if system_info else None,
        "network_info": dict(network_info) if network_info else None,
        "disk_info": dict(disk_info) if disk_info else None,
        "process_count": process_count,
        "command_count": db.session.execute(db.text("SELECT COUNT(*) FROM command_history WHERE device_id=:id"), {"id": device_id}).scalar(),
        "location_info": dict(location_info) if location_info else None
    }), 200

@app.route('/api/command/result', methods=['POST'])
def command_result():
    data = request.get_json()
    db.session.execute(
        db.text("INSERT INTO command_history (device_id, command_type, result) VALUES(:device_id,:command_type,:result)"),
        data
    )
    db.session.commit()
    # Push a notification to the owner now that the command has completed
    try:
        dev_id = data.get('device_id')
        ctype = data.get('command_type', 'Command')
        device = Device.query.filter_by(id=dev_id).first()
        dname = device.device_name if device else 'your device'
        labels = {
            'LOCK':        ('Device locked',       f'{dname} has been locked'),
            'ALARM':       ('Alarm triggered',     f'Alarm is sounding on {dname}'),
            'STOP_ALARM':  ('Alarm stopped',       f'Alarm stopped on {dname}'),
            'PHOTO':       ('Photo captured',      f'Evidence photo captured from {dname}'),
            'SCREENSHOT':  ('Screenshot captured', f'Screenshot captured from {dname}'),
            'AUDIO':       ('Audio recorded',      f'Audio evidence recorded from {dname}'),
            'GET_LOCATION':('Location updated',    f'New location received from {dname}'),
            'WIPE':        ('Wipe completed',      f'Data wipe completed on {dname}'),
            'SECURE_DATA': ('Data protected',      f'Your files on {dname} are now encrypted'),
            'RESTORE_DATA':('Data restored',       f'Your files on {dname} have been decrypted'),
        }
        title, body = labels.get(ctype, (f'{ctype} completed', f'{ctype} finished on {dname}'))
        notify_device_owner(dev_id, title, body, {'device_id': str(dev_id), 'command_type': str(ctype)})
    except Exception as _e:
        print(f"command_result notify error: {_e}")
    return jsonify({"message":"Result saved"}), 200

@app.route('/api/command/history/<device_id>', methods=['GET'])
@jwt_required()
def command_history(device_id):
    rows = db.session.execute(
        db.text("SELECT command_type, result, executed_at FROM command_history WHERE device_id=:id ORDER BY executed_at DESC"),
        {"id": device_id}
    ).mappings().all()
    return jsonify({
        "results": [
            {
                "command_type": r["command_type"],
                "result": r["result"],
                "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None
            }
            for r in rows
        ]
    }), 200

# Create tables on startup regardless of how app is run
with app.app_context():
    db.create_all()
    print("Database tables created successfully")
    # create_all() does NOT add new columns to existing tables — add fcm_token if missing
    try:
        db.session.execute(db.text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token TEXT"
        ))
        db.session.commit()
        print("Migration: fcm_token column ensured")
    except Exception as _mig_err:
        db.session.rollback()
        print(f"Migration warning (fcm_token): {_mig_err}")
    # T2/T5: geofence + vault columns on devices
    for _col in ("home_lat DOUBLE PRECISION",
                 "home_lng DOUBLE PRECISION",
                 "geofence_radius DOUBLE PRECISION",
                 "vault_key TEXT",
                 "offline_lock_minutes INTEGER",           # T7
                 "bitlocker_protection VARCHAR(20)",       # T8
                 "bitlocker_conversion VARCHAR(40)",       # T8
                 "bitlocker_percent INTEGER",              # T8
                 "bitlocker_method VARCHAR(40)",           # T8
                 "bitlocker_key_id VARCHAR(40)",           # T8
                 "bitlocker_recovery_key VARCHAR(80)",     # T8
                 "bitlocker_updated_at TIMESTAMP"):        # T8
        try:
            db.session.execute(db.text(
                f"ALTER TABLE devices ADD COLUMN IF NOT EXISTS {_col}"
            ))
            db.session.commit()
        except Exception as _mig_err2:
            db.session.rollback()
            print(f"Migration warning (devices {_col}): {_mig_err2}")
    print("Migration: geofence columns ensured")
    # Location history table may pre-exist from an older build with fewer columns
    for _col in ("latitude DOUBLE PRECISION", "longitude DOUBLE PRECISION",
                 "city VARCHAR(100)", "country VARCHAR(100)", "isp VARCHAR(200)",
                 "ip_address VARCHAR(50)", "area VARCHAR(200)",
                 "method VARCHAR(20)", "timestamp TIMESTAMP"):
        try:
            db.session.execute(db.text(
                f"ALTER TABLE location_history ADD COLUMN IF NOT EXISTS {_col}"))
            db.session.commit()
        except Exception as _mig_err3:
            db.session.rollback()
            print(f"Migration warning (location_history {_col}): {_mig_err3}")
    print("Migration: location_history columns ensured")

    # T4: payload column on commands + widen command_type for DETERRENT_LOCK
    try:
        db.session.execute(db.text(
            "ALTER TABLE commands ADD COLUMN IF NOT EXISTS payload TEXT"))
        db.session.commit()
    except Exception as _mig_err4:
        db.session.rollback()
        print(f"Migration warning (commands.payload): {_mig_err4}")
    try:
        db.session.execute(db.text(
            "ALTER TABLE commands ALTER COLUMN command_type TYPE VARCHAR(30)"))
        db.session.commit()
    except Exception as _mig_err5:
        db.session.rollback()
        print(f"Migration warning (commands.command_type widen): {_mig_err5}")
    print("Migration: commands.payload + widened command_type ensured")

    # 2FA + password reset timestamp columns on users
    for _col in ("totp_secret VARCHAR(64)",
                 "totp_enabled BOOLEAN DEFAULT FALSE",
                 "totp_recovery_codes TEXT",
                 "password_reset_at TIMESTAMP"):
        try:
            db.session.execute(db.text(
                f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {_col}"))
            db.session.commit()
        except Exception as _mig_err6:
            db.session.rollback()
            print(f"Migration warning (users {_col}): {_mig_err6}")
    print("Migration: users 2FA + password_reset columns ensured")


@app.route('/api/device/self-register', methods=['POST'])
def self_register():
    data = request.get_json()
    if not data or 'device_name' not in data:
        return jsonify({'error': 'Device name required'}), 400
    # Find first user or use a default
    user = User.query.first()
    if not user:
        return jsonify({'error': 'No users found'}), 404
    device = Device(
        user_id=user.id,
        device_name=data['device_name'],
        beacon_id=str(uuid.uuid4()).replace('-',''),
        gsm_number=''
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({'device_id': device.id, 'message': 'Device registered'}), 201

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
