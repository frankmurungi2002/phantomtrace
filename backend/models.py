from app import db
from datetime import datetime
import uuid

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    devices = db.relationship('Device', backref='owner', lazy=True)

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
    sightings = db.relationship('Sighting', backref='device', lazy=True)
    commands = db.relationship('Command', backref='device', lazy=True)

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
    command_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10), default='PENDING')
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed_at = db.Column(db.DateTime)

class EvidencePhoto(db.Model):
    __tablename__ = 'evidence_photos'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class EvidenceKeylog(db.Model):
    __tablename__ = 'evidence_keylog'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=False)
    keylog_text = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
