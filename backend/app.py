from flask import Flask, request, jsonify, send_file, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os, uuid, bcrypt
from datetime import datetime
load_dotenv()

# ── Firebase push notifications ────────────────────────────────────────────────
import firebase_admin
from firebase_admin import credentials, messaging

_cred_path = os.path.join(os.path.dirname(__file__), 'firebase-service-account.json')
_firebase_ready = False
if os.path.exists(_cred_path):
    firebase_admin.initialize_app(credentials.Certificate(_cred_path))
    _firebase_ready = True
    print("Firebase initialized")
else:
    print("WARNING: firebase-service-account.json not found – push notifications disabled")

def send_push(token, title, body, data=None):
    if not _firebase_ready:
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

# ── Cloudinary (optional – set CLOUDINARY_URL env var) ────────────────────────
_cloudinary_ready = False
if os.getenv('CLOUDINARY_URL'):
    try:
        import cloudinary
        import cloudinary.uploader
        # cloudinary.config_from_url reads CLOUDINARY_URL automatically
        cloudinary.config(cloudinary_url=os.getenv('CLOUDINARY_URL'))
        _cloudinary_ready = True
        print("Cloudinary initialized")
    except ImportError:
        print("WARNING: cloudinary package not installed – falling back to local storage")

# ── Flask app setup ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = __import__('datetime').timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Models ─────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name          = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    phone         = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    fcm_token     = db.Column(db.String(500), nullable=True)   # Firebase Cloud Messaging
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

class Device(db.Model):
    __tablename__ = 'devices'
    id            = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_name   = db.Column(db.String(100), nullable=False)
    beacon_id     = db.Column(db.String(64), unique=True, nullable=False)
    gsm_number    = db.Column(db.String(20))
    status        = db.Column(db.String(10), default='SAFE')
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    stolen_at     = db.Column(db.DateTime)
    last_seen     = db.Column(db.DateTime, default=datetime.utcnow)
    # Geofence: safe zone defined by owner
    fence_lat     = db.Column(db.Float, nullable=True)
    fence_lon     = db.Column(db.Float, nullable=True)
    fence_radius  = db.Column(db.Float, nullable=True)  # km

class Sighting(db.Model):
    __tablename__ = 'sightings'
    id        = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    latitude  = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy  = db.Column(db.Float)
    method    = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Command(db.Model):
    __tablename__ = 'commands'
    id           = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id    = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    command_type = db.Column(db.String(20), nullable=False)
    status       = db.Column(db.String(10), default='PENDING')
    issued_at    = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at  = db.Column(db.DateTime)

class EvidencePhoto(db.Model):
    __tablename__ = 'evidence_photos'
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id  = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    file_path  = db.Column(db.String(500), nullable=False)   # Cloudinary URL or local path
    photo_type = db.Column(db.String(20), default='SCREENSHOT')
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

class EvidenceAudio(db.Model):
    __tablename__ = 'evidence_audio'
    id        = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    duration  = db.Column(db.Integer, default=30)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class EvidenceKeylog(db.Model):
    __tablename__ = 'evidence_keylog'
    id          = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id   = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    keylog_text = db.Column(db.Text)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceLocation(db.Model):
    __tablename__ = 'device_location'
    device_id  = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    latitude   = db.Column(db.Float)
    longitude  = db.Column(db.Float)
    city       = db.Column(db.String(100))
    country    = db.Column(db.String(100))
    isp        = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    area       = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceSystemInfo(db.Model):
    __tablename__ = 'device_system_info'
    device_id  = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    hostname   = db.Column(db.String(100))
    username   = db.Column(db.String(100))
    os_name    = db.Column(db.String(100))
    os_version = db.Column(db.String(100))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceNetworkInfo(db.Model):
    __tablename__ = 'device_network_info'
    device_id   = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    hostname    = db.Column(db.String(100))
    ip_address  = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceDiskInfo(db.Model):
    __tablename__ = 'device_disk_info'
    device_id  = db.Column(db.String(36), db.ForeignKey('devices.id'), primary_key=True)
    total_gb   = db.Column(db.String(20))
    used_gb    = db.Column(db.String(20))
    free_gb    = db.Column(db.String(20))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceProcess(db.Model):
    __tablename__ = 'device_processes'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id    = db.Column(db.String(36), db.ForeignKey('devices.id'))
    process_name = db.Column(db.String(100))
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow)

class CommandHistory(db.Model):
    __tablename__ = 'command_history'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id    = db.Column(db.String(36), db.ForeignKey('devices.id'))
    command_type = db.Column(db.String(50))
    result       = db.Column(db.String(50))
    executed_at  = db.Column(db.DateTime, default=datetime.utcnow)

class ShutdownAlert(db.Model):
    __tablename__ = 'shutdown_alerts'
    id         = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id  = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    reason     = db.Column(db.String(50), default='SHUTDOWN_ATTEMPT')
    approved   = db.Column(db.Boolean, default=None, nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

# ── Helper: notify device owner via FCM ────────────────────────────────────────
def notify_device_owner(device_id, title, body, data=None):
    try:
        result = db.session.execute(
            db.text("SELECT u.fcm_token FROM users u JOIN devices d ON d.user_id = u.id WHERE d.id=:id"),
            {"id": device_id}
        ).first()
        if result and result[0]:
            send_push(result[0], title, body, data or {})
    except Exception as e:
        print(f"notify error: {e}")

# ── Helper: geofence distance check (Haversine) ────────────────────────────────
import math
def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = math.sin(d_lat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(d_lon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

# ── Helper: upload to Cloudinary or save locally ───────────────────────────────
VAULT = os.path.join(os.path.dirname(__file__), 'evidence_vault')
os.makedirs(VAULT, exist_ok=True)

def store_file(file_obj, device_id, prefix, resource_type='image'):
    """Upload to Cloudinary if configured, otherwise save locally. Returns URL/path."""
    if _cloudinary_ready:
        import cloudinary.uploader
        result = cloudinary.uploader.upload(
            file_obj,
            folder=f"phantomtrace/{device_id}",
            public_id=f"{prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            resource_type=resource_type
        )
        return result['secure_url']
    else:
        ext = 'wav' if resource_type == 'video' else 'jpg'
        filename = f"{device_id}_{prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{ext}"
        filepath = os.path.join(VAULT, filename)
        file_obj.save(filepath)
        return filepath

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not all(k in data for k in ['name', 'email', 'phone', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(name=data['name'], email=data['email'], phone=data['phone'], password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Account created', 'token': token, 'user': {'id': user.id, 'name': user.name, 'email': user.email}}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(k in data for k in ['email', 'password']):
        return jsonify({'error': 'Missing email or password'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'token': token, 'user': {'id': user.id, 'name': user.name, 'email': user.email}}), 200

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def profile():
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone}), 200

@app.route('/api/auth/fcm-token', methods=['POST'])
@jwt_required()
def save_fcm_token():
    user_id = get_jwt_identity()
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'error': 'No token'}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.fcm_token = token
    db.session.commit()
    return jsonify({'message': 'FCM token saved'}), 200

# ══════════════════════════════════════════════════════════════════════════════
#  DEVICE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/device/register', methods=['POST'])
@jwt_required()
def register_device():
    data = request.get_json()
    if not data or 'device_name' not in data:
        return jsonify({'error': 'Device name required'}), 400
    device = Device(
        user_id=get_jwt_identity(),
        device_name=data['device_name'],
        beacon_id=str(uuid.uuid4()).replace('-', ''),
        gsm_number=data.get('gsm_number', '')
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({
        'message': 'Device registered',
        'device': {
            'id': device.id,
            'device_name': device.device_name,
            'beacon_id': device.beacon_id,
            'status': device.status
        }
    }), 201

@app.route('/api/device/self-register', methods=['POST'])
def self_register():
    """Called by the laptop agent on first run (no JWT needed)."""
    data = request.get_json()
    if not data or 'device_name' not in data:
        return jsonify({'error': 'Device name required'}), 400
    # Attach to the account whose email matches, or fall back to first user
    email = data.get('owner_email')
    user = (User.query.filter_by(email=email).first() if email else None) or User.query.first()
    if not user:
        return jsonify({'error': 'No user account found. Register via the app first.'}), 404
    device = Device(
        user_id=user.id,
        device_name=data['device_name'],
        beacon_id=str(uuid.uuid4()).replace('-', ''),
        gsm_number=''
    )
    db.session.add(device)
    db.session.commit()
    return jsonify({
        'message': 'Device registered',
        'device_id': device.id,
        'beacon_id': device.beacon_id
    }), 201

@app.route('/api/device/list', methods=['GET'])
@jwt_required()
def list_devices():
    devices = Device.query.filter_by(user_id=get_jwt_identity()).all()
    result = []
    for d in devices:
        online = bool(d.last_seen and (datetime.utcnow() - d.last_seen).total_seconds() < 30)
        result.append({
            'id': d.id,
            'device_name': d.device_name,
            'beacon_id': d.beacon_id,
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
    # Auto-queue LOCK + ALARM on the stolen device
    for cmd_type in ['LOCK', 'ALARM']:
        db.session.add(Command(device_id=device_id, command_type=cmd_type))
    db.session.commit()
    # Notify the owner (confirmation push)
    notify_device_owner(device_id, '🚨 Device Marked Stolen',
        f'{device.device_name} has been marked stolen. LOCK and ALARM commands sent.',
        {'device_id': device_id, 'action': 'stolen'})
    return jsonify({'message': 'Device marked stolen', 'status': 'STOLEN'}), 200

@app.route('/api/device/<device_id>/mark-found', methods=['POST'])
@jwt_required()
def mark_found(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    device.status = 'SAFE'
    db.session.commit()
    # Stop alarm
    db.session.add(Command(device_id=device_id, command_type='STOP_ALARM'))
    db.session.commit()
    return jsonify({'message': 'Device marked safe', 'status': 'SAFE'}), 200

@app.route('/api/device/<device_id>/geofence', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
def geofence(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    if request.method == 'GET':
        if device.fence_lat is None:
            return jsonify({'geofence': None}), 200
        return jsonify({'geofence': {'latitude': device.fence_lat, 'longitude': device.fence_lon, 'radius_km': device.fence_radius}}), 200
    if request.method == 'DELETE':
        device.fence_lat = device.fence_lon = device.fence_radius = None
        db.session.commit()
        return jsonify({'message': 'Geofence removed'}), 200
    # POST – set geofence
    data = request.get_json()
    if not all(k in data for k in ['latitude', 'longitude', 'radius_km']):
        return jsonify({'error': 'Need latitude, longitude, radius_km'}), 400
    device.fence_lat = data['latitude']
    device.fence_lon = data['longitude']
    device.fence_radius = data['radius_km']
    db.session.commit()
    return jsonify({'message': f'Geofence set: {data["radius_km"]}km around ({data["latitude"]}, {data["longitude"]})'}), 200

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
        notify_device_owner(device.id, '🟢 Device Online',
            f'{device.device_name} is now online.', {'device_id': device.id})
    return jsonify({'message': 'Heartbeat received', 'timestamp': device.last_seen.isoformat()}), 200

@app.route('/api/device/shutdown-alert', methods=['POST'])
def shutdown_alert():
    """Called by agent when the laptop is about to be shut down or restarted."""
    data = request.get_json()
    device_id = data.get('device_id')
    reason = data.get('reason', 'SHUTDOWN_ATTEMPT')
    if not device_id:
        return jsonify({'error': 'Missing device_id'}), 400
    device = Device.query.filter_by(id=device_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    alert = ShutdownAlert(device_id=device_id, reason=reason)
    db.session.add(alert)
    db.session.commit()
    # Notify owner immediately
    notify_device_owner(device_id, '⚠️ Shutdown Attempt',
        f'{device.device_name} is being shut down or restarted.',
        {'device_id': device_id, 'alert_id': alert.id, 'reason': reason})
    # Return whether device is stolen (agent uses this to decide whether to resist)
    return jsonify({
        'alert_id': alert.id,
        'device_status': device.status,
        'resist': device.status == 'STOLEN'   # agent should try to block if STOLEN
    }), 200

@app.route('/api/device/shutdown-alerts/<device_id>', methods=['GET'])
@jwt_required()
def get_shutdown_alerts(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    alerts = ShutdownAlert.query.filter_by(device_id=device_id).order_by(ShutdownAlert.timestamp.desc()).limit(20).all()
    return jsonify({'alerts': [{'id': a.id, 'reason': a.reason, 'timestamp': a.timestamp.isoformat()} for a in alerts]}), 200

@app.route('/api/device/systeminfo', methods=['POST'])
def device_systeminfo():
    data = request.get_json()
    sql = """
    INSERT INTO device_system_info (device_id, hostname, username, os_name, os_version, updated_at)
    VALUES (:device_id, :hostname, :username, :os_name, :os_version, NOW())
    ON CONFLICT (device_id) DO UPDATE SET
        hostname=EXCLUDED.hostname, username=EXCLUDED.username,
        os_name=EXCLUDED.os_name, os_version=EXCLUDED.os_version, updated_at=NOW()
    """
    db.session.execute(db.text(sql), {
        'device_id': data.get('device_id'), 'hostname': data.get('hostname'),
        'username': data.get('user'), 'os_name': data.get('os'), 'os_version': data.get('version')
    })
    db.session.commit()
    return jsonify({'message': 'System info saved'}), 200

@app.route('/api/device/networkinfo', methods=['POST'])
def device_networkinfo():
    data = request.get_json()
    sql = """
    INSERT INTO device_network_info (device_id, hostname, ip_address, mac_address, updated_at)
    VALUES (:device_id, :hostname, :ip_address, :mac_address, NOW())
    ON CONFLICT (device_id) DO UPDATE SET
        hostname=EXCLUDED.hostname, ip_address=EXCLUDED.ip_address,
        mac_address=EXCLUDED.mac_address, updated_at=NOW()
    """
    db.session.execute(db.text(sql), data)
    db.session.commit()
    return jsonify({'message': 'Network info saved'}), 200

@app.route('/api/device/diskinfo', methods=['POST'])
def device_diskinfo():
    data = request.get_json()
    sql = """
    INSERT INTO device_disk_info (device_id, total_gb, used_gb, free_gb, updated_at)
    VALUES (:device_id, :total_gb, :used_gb, :free_gb, NOW())
    ON CONFLICT (device_id) DO UPDATE SET
        total_gb=EXCLUDED.total_gb, used_gb=EXCLUDED.used_gb,
        free_gb=EXCLUDED.free_gb, updated_at=NOW()
    """
    db.session.execute(db.text(sql), data)
    db.session.commit()
    return jsonify({'message': 'Disk info saved'}), 200

@app.route('/api/device/processes', methods=['POST'])
def device_processes():
    data = request.get_json()
    device_id = data.get('device_id')
    processes = data.get('processes', [])
    db.session.execute(db.text("DELETE FROM device_processes WHERE device_id=:id"), {"id": device_id})
    for proc in processes:
        db.session.execute(
            db.text("INSERT INTO device_processes(device_id, process_name) VALUES(:device_id, :process_name)"),
            {"device_id": device_id, "process_name": proc}
        )
    db.session.commit()
    return jsonify({'message': 'Processes saved'}), 200

@app.route('/api/device/location', methods=['POST'])
def device_location():
    data = request.get_json()
    device_id = data.get('device_id')
    lat = data.get('latitude')
    lon = data.get('longitude')
    existing = db.session.execute(
        db.text("SELECT device_id FROM device_location WHERE device_id=:id"), {"id": device_id}
    ).first()
    if existing:
        db.session.execute(
            db.text("UPDATE device_location SET latitude=:lat, longitude=:lon, city=:city, country=:country, isp=:isp, ip_address=:ip, area=:area, updated_at=NOW() WHERE device_id=:device_id"),
            {"lat": lat, "lon": lon, "city": data.get("city"), "country": data.get("country"),
             "isp": data.get("isp"), "ip": data.get("ip_address"), "area": data.get("area", ""), "device_id": device_id}
        )
    else:
        db.session.execute(
            db.text("INSERT INTO device_location (device_id, latitude, longitude, city, country, isp, ip_address, area, updated_at) VALUES(:device_id,:lat,:lon,:city,:country,:isp,:ip,:area,NOW())"),
            {"device_id": device_id, "lat": lat, "lon": lon, "city": data.get("city"),
             "country": data.get("country"), "isp": data.get("isp"), "ip": data.get("ip_address"), "area": data.get("area", "")}
        )
    db.session.commit()
    # Geofence check
    device = Device.query.filter_by(id=device_id).first()
    if device and device.fence_lat and lat and lon:
        dist = haversine_km(device.fence_lat, device.fence_lon, lat, lon)
        if dist > device.fence_radius:
            notify_device_owner(device_id, '📍 Device Left Safe Zone',
                f'{device.device_name} is {dist:.1f}km from its safe zone.',
                {'device_id': device_id, 'lat': str(lat), 'lon': str(lon)})
    return jsonify({'message': 'Location saved'}), 200

@app.route('/api/device/overview/<device_id>', methods=['GET'])
def device_overview(device_id):
    system_info  = db.session.execute(db.text("SELECT * FROM device_system_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    network_info = db.session.execute(db.text("SELECT * FROM device_network_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    disk_info    = db.session.execute(db.text("SELECT * FROM device_disk_info WHERE device_id=:id"), {"id": device_id}).mappings().first()
    location_info= db.session.execute(db.text("SELECT * FROM device_location WHERE device_id=:id"), {"id": device_id}).mappings().first()
    process_count= db.session.execute(db.text("SELECT COUNT(*) FROM device_processes WHERE device_id=:id"), {"id": device_id}).scalar()
    cmd_count    = db.session.execute(db.text("SELECT COUNT(*) FROM command_history WHERE device_id=:id"), {"id": device_id}).scalar()
    device = Device.query.filter_by(id=device_id).first()
    online = bool(device and device.last_seen and (datetime.utcnow() - device.last_seen).total_seconds() < 30)
    return jsonify({
        "online":        online,
        "last_seen":     device.last_seen.isoformat() if device and device.last_seen else None,
        "system_info":   dict(system_info)   if system_info  else None,
        "network_info":  dict(network_info)  if network_info else None,
        "disk_info":     dict(disk_info)     if disk_info    else None,
        "location_info": dict(location_info) if location_info else None,
        "process_count": process_count,
        "command_count": cmd_count,
    }), 200

# ══════════════════════════════════════════════════════════════════════════════
#  COMMAND ROUTES
# ══════════════════════════════════════════════════════════════════════════════

VALID_COMMANDS = [
    'LOCK', 'PHOTO', 'ALARM', 'STOP_ALARM', 'AUDIO',
    'WIPE', 'PING', 'SYSTEM_INFO', 'GET_NETWORK',
    'GET_DISKS', 'GET_PROCESSES', 'SCREENSHOT', 'GET_LOCATION'
]

@app.route('/api/command/send', methods=['POST'])
@jwt_required()
def send_command():
    data = request.get_json()
    if not data or not all(k in data for k in ['device_id', 'command_type']):
        return jsonify({'error': 'Missing fields'}), 400
    if data['command_type'] not in VALID_COMMANDS:
        return jsonify({'error': f'Invalid command. Valid: {VALID_COMMANDS}'}), 400
    # WIPE requires explicit confirmation flag
    if data['command_type'] == 'WIPE' and not data.get('confirmed'):
        return jsonify({'error': 'WIPE requires confirmed=true in request body'}), 400
    device = Device.query.filter_by(id=data['device_id'], user_id=get_jwt_identity()).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    command = Command(device_id=data['device_id'], command_type=data['command_type'])
    db.session.add(command)
    db.session.commit()
    return jsonify({'message': 'Command queued', 'command_id': command.id}), 201

@app.route('/api/command/pending/<device_id>', methods=['GET'])
def get_pending(device_id):
    commands = Command.query.filter_by(device_id=device_id, status='PENDING').all()
    return jsonify({'commands': [{'id': c.id, 'command_type': c.command_type} for c in commands]}), 200

@app.route('/api/command/acknowledge/<command_id>', methods=['POST'])
def acknowledge(command_id):
    command = Command.query.get(command_id)
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    command.status = 'DONE'
    command.executed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Acknowledged'}), 200

@app.route('/api/command/result', methods=['POST'])
def command_result():
    data = request.get_json()
    db.session.execute(
        db.text("INSERT INTO command_history (device_id, command_type, result) VALUES(:device_id,:command_type,:result)"),
        data
    )
    db.session.commit()
    return jsonify({'message': 'Result saved'}), 200

@app.route('/api/command/history/<device_id>', methods=['GET'])
@jwt_required()
def command_history(device_id):
    rows = db.session.execute(
        db.text("SELECT command_type, result, executed_at FROM command_history WHERE device_id=:id ORDER BY executed_at DESC LIMIT 50"),
        {"id": device_id}
    ).mappings().all()
    return jsonify({'results': [{'command_type': r['command_type'], 'result': r['result'],
        'executed_at': r['executed_at'].isoformat() if r['executed_at'] else None} for r in rows]}), 200

# ══════════════════════════════════════════════════════════════════════════════
#  SIGHTING ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/sighting/bluetooth', methods=['POST'])
def bluetooth_sighting():
    data = request.get_json()
    if not data or not all(k in data for k in ['beacon_id', 'latitude', 'longitude']):
        return jsonify({'error': 'Missing fields'}), 400
    device = Device.query.filter_by(beacon_id=data['beacon_id']).first()
    if not device:
        return jsonify({'status': 'unknown'}), 200
    if device.status != 'STOLEN':
        return jsonify({'status': 'safe'}), 200
    sighting = Sighting(
        device_id=device.id,
        latitude=data['latitude'], longitude=data['longitude'],
        accuracy=data.get('accuracy', 0), method='BLE'
    )
    db.session.add(sighting)
    db.session.commit()
    socketio.emit(f'sighting_{device.id}', {
        'latitude': data['latitude'], 'longitude': data['longitude'],
        'method': 'BLE', 'timestamp': sighting.timestamp.isoformat()
    })
    # Push notification to owner
    notify_device_owner(device.id,
        '📡 Stolen Device Spotted!',
        f'{device.device_name} was detected nearby via Bluetooth.',
        {'device_id': device.id, 'lat': str(data['latitude']), 'lon': str(data['longitude']), 'method': 'BLE'}
    )
    return jsonify({'status': 'reported', 'device_status': 'STOLEN'}), 200

@app.route('/api/sighting/gsm', methods=['POST'])
def gsm_sighting():
    data = request.get_json()
    if not data or not all(k in data for k in ['device_id', 'latitude', 'longitude']):
        return jsonify({'error': 'Missing fields'}), 400
    device = Device.query.filter_by(id=data['device_id']).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    sighting = Sighting(
        device_id=data['device_id'],
        latitude=data['latitude'], longitude=data['longitude'],
        accuracy=data.get('accuracy', 0), method='GSM'
    )
    db.session.add(sighting)
    db.session.commit()
    socketio.emit(f'sighting_{data["device_id"]}', {
        'latitude': data['latitude'], 'longitude': data['longitude'],
        'method': 'GSM', 'timestamp': sighting.timestamp.isoformat()
    })
    if device.status == 'STOLEN':
        notify_device_owner(data['device_id'],
            '📡 Stolen Device Located!',
            f'{device.device_name} sent its GPS location.',
            {'device_id': data['device_id'], 'lat': str(data['latitude']), 'lon': str(data['longitude']), 'method': 'GSM'}
        )
    return jsonify({'status': 'reported'}), 200

@app.route('/api/sighting/trail/<device_id>', methods=['GET'])
@jwt_required()
def get_trail(device_id):
    sightings = Sighting.query.filter_by(device_id=device_id).order_by(Sighting.timestamp.asc()).all()
    return jsonify({'trail': [{'latitude': s.latitude, 'longitude': s.longitude,
        'method': s.method, 'timestamp': s.timestamp.isoformat()} for s in sightings]}), 200

# ══════════════════════════════════════════════════════════════════════════════
#  EVIDENCE ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/evidence/photo', methods=['POST'])
def upload_photo():
    device_id  = request.form.get('device_id')
    photo_type = request.form.get('photo_type', 'SCREENSHOT')
    if not device_id or 'photo' not in request.files:
        return jsonify({'error': 'Missing device_id or photo'}), 400
    file = request.files['photo']
    file_url = store_file(file, device_id, photo_type, resource_type='image')
    photo = EvidencePhoto(device_id=device_id, file_path=file_url, photo_type=photo_type)
    db.session.add(photo)
    db.session.commit()
    # Notify owner that evidence arrived
    notify_device_owner(device_id, f'📸 Evidence Captured',
        f'New {photo_type.lower()} from your stolen device.',
        {'device_id': device_id, 'photo_id': photo.id, 'type': photo_type})
    return jsonify({'message': 'Photo saved', 'id': photo.id, 'photo_type': photo_type,
        'url': file_url if file_url.startswith('http') else None}), 201

@app.route('/api/evidence/audio', methods=['POST'])
def upload_audio():
    device_id = request.form.get('device_id')
    if not device_id or 'audio' not in request.files:
        return jsonify({'error': 'Missing device_id or audio'}), 400
    file = request.files['audio']
    file_url = store_file(file, device_id, 'AUDIO', resource_type='video')  # Cloudinary uses 'video' for audio
    audio = EvidenceAudio(device_id=device_id, file_path=file_url)
    db.session.add(audio)
    db.session.commit()
    notify_device_owner(device_id, '🎙️ Audio Recorded',
        'Your stolen device captured audio from its microphone.',
        {'device_id': device_id, 'audio_id': audio.id})
    return jsonify({'message': 'Audio saved', 'id': audio.id,
        'url': file_url if file_url.startswith('http') else None}), 201

@app.route('/api/evidence/photos/<device_id>', methods=['GET'])
@jwt_required()
def get_photos(device_id):
    photos = EvidencePhoto.query.filter_by(device_id=device_id).order_by(EvidencePhoto.timestamp.desc()).all()
    return jsonify({'photos': [{'id': p.id, 'timestamp': p.timestamp.isoformat(),
        'photo_type': p.photo_type,
        'url': p.file_path if p.file_path.startswith('http') else f'/api/evidence/photo/{p.id}'
        } for p in photos]}), 200

@app.route('/api/evidence/photo/<photo_id>', methods=['GET', 'DELETE'])
@jwt_required()
def get_photo(photo_id):
    photo = EvidencePhoto.query.filter_by(id=photo_id).first()
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404
    if request.method == 'DELETE':
        if photo.file_path.startswith('http') and _cloudinary_ready:
            try:
                import cloudinary.uploader
                # Extract public_id from Cloudinary URL
                parts = photo.file_path.split('/')
                public_id = '/'.join(parts[-3:]).rsplit('.', 1)[0]  # folder/subfolder/name
                cloudinary.uploader.destroy(public_id)
            except Exception as e:
                print(f"Cloudinary delete error: {e}")
        elif os.path.exists(photo.file_path):
            try:
                os.remove(photo.file_path)
            except Exception:
                pass
        db.session.delete(photo)
        db.session.commit()
        return jsonify({'message': 'Deleted'}), 200
    # GET
    if photo.file_path.startswith('http'):
        return redirect(photo.file_path)
    if not os.path.exists(photo.file_path):
        return jsonify({'error': 'File not found on server (may have been lost on restart – enable Cloudinary)'}), 404
    return send_file(photo.file_path)

@app.route('/api/evidence/keylog', methods=['POST'])
def upload_keylog():
    data = request.get_json()
    if not data or not all(k in data for k in ['device_id', 'keylog_text']):
        return jsonify({'error': 'Missing fields'}), 400
    keylog = EvidenceKeylog(device_id=data['device_id'], keylog_text=data['keylog_text'])
    db.session.add(keylog)
    db.session.commit()
    return jsonify({'message': 'Keylog saved'}), 201

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP: create tables + migrate existing schemas
# ══════════════════════════════════════════════════════════════════════════════

with app.app_context():
    db.create_all()
    # Add columns that may not exist in older DB instances
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token VARCHAR(500)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS fence_lat FLOAT",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS fence_lon FLOAT",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS fence_radius FLOAT",
        "ALTER TABLE evidence_photos ALTER COLUMN file_path TYPE VARCHAR(500)",
    ]
    for sql in migrations:
        try:
            db.session.execute(db.text(sql))
        except Exception as e:
            print(f"Migration skipped ({sql[:50]}...): {e}")
    db.session.commit()
    print("✅ Database ready")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
