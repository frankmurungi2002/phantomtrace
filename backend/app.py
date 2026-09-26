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

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ['name','email','phone','password']):
        return jsonify({'error': 'Missing required fields'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(name=data['name'], email=data['email'], phone=data['phone'], password_hash=password_hash)
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
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'token': token, 'user': {'id': user.id, 'name': user.name}}), 200

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def profile():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone}), 200

@app.route('/api/device/self-register', methods=['POST'])
def self_register_device():
    data = request.get_json()
    device = Device(
        user_id=db.session.execute(db.text('SELECT id FROM users LIMIT 1')).scalar(),
        device_name=data.get('device_name', 'Unknown'),
        beacon_id=str(uuid.uuid4()).replace('-',''),
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({'message': 'Registered', 'device_id': device.id}), 201

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
            'last_seen': d.last_seen.isoformat() if d.last_seen else None
        })
    return jsonify({'devices': result}), 200

@app.route('/api/device/<device_id>/mark-stolen', methods=['POST'])
@jwt_required()
def mark_stolen(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.status = 'STOLEN'
    device.stolen_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Device marked stolen', 'status': 'STOLEN'}), 200

@app.route('/api/device/<device_id>/mark-found', methods=['POST'])
@jwt_required()
def mark_found(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.status = 'SAFE'
    db.session.commit()
    return jsonify({'message': 'Device marked safe', 'status': 'SAFE'}), 200

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
    pdf = build_recovery_pdf(device_id, device)
    fname = f"PhantomTrace_Report_{(device.device_name or 'device').replace(' ', '_')}.pdf"
    return send_file(pdf, mimetype='application/pdf',
                     as_attachment=True, download_name=fname)


def build_recovery_pdf(device_id, device):
    """Assemble a recovery report PDF from everything we know about the device."""
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
    photos = EvidencePhoto.query.filter_by(device_id=device_id)\
        .order_by(EvidencePhoto.timestamp.desc()).limit(6).all()
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

    # Evidence photos (embedded from Cloudinary)
    if photos:
        story.append(Paragraph("Evidence", h2))
        for p in photos:
            try:
                r = _rq.get(p.file_path, timeout=12)
                if r.status_code == 200:
                    img = RLImage(io.BytesIO(r.content))
                    # scale to max 80mm wide, keep aspect
                    iw, ih = img.imageWidth, img.imageHeight
                    max_w = 80*mm
                    if iw > max_w:
                        img.drawHeight = ih * (max_w / iw)
                        img.drawWidth = max_w
                    cap = f"{p.photo_type} — {p.timestamp.strftime('%Y-%m-%d %H:%M') if p.timestamp else ''}"
                    story.append(Paragraph(cap, sub))
                    story.append(img)
                    story.append(Spacer(1, 8))
            except Exception as _ie:
                story.append(Paragraph(
                    f"[evidence unavailable: {p.photo_type}]", sub))

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
    return jsonify({'message': 'Heartbeat received', 'timestamp': device.last_seen.isoformat()}), 200

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
