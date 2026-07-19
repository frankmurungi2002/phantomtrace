from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from models import Device
import uuid
from datetime import datetime

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/register', methods=['POST'])
@jwt_required()
def register_device():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'device_name' not in data:
        return jsonify({'error': 'Device name required'}), 400
    
    device = Device(
        user_id=user_id,
        device_name=data['device_name'],
        beacon_id=str(uuid.uuid4()).replace('-', ''),
        gsm_number=data.get('gsm_number', '')
    )
    
    db.session.add(device)
    db.session.commit()
    
    return jsonify({
        'message': 'Device registered successfully',
        'device': {
            'id': device.id,
            'device_name': device.device_name,
            'beacon_id': device.beacon_id,
            'status': device.status
        }
    }), 201

@devices_bp.route('/list', methods=['GET'])
@jwt_required()
def list_devices():
    user_id = get_jwt_identity()
    devices = Device.query.filter_by(user_id=user_id).all()
    
    return jsonify({
        'devices': [{
            'id': d.id,
            'device_name': d.device_name,
            'status': d.status,
            'registered_at': d.registered_at.isoformat()
        } for d in devices]
    }), 200

@devices_bp.route('/<device_id>/mark-stolen', methods=['POST'])
@jwt_required()
def mark_stolen(device_id):
    user_id = get_jwt_identity()
    device = Device.query.filter_by(id=device_id, user_id=user_id).first()
    
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    device.status = 'STOLEN'
    device.stolen_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Device marked as stolen', 'status': 'STOLEN'}), 200

@devices_bp.route('/<device_id>/mark-found', methods=['POST'])
@jwt_required()
def mark_found(device_id):
    user_id = get_jwt_identity()
    device = Device.query.filter_by(id=device_id, user_id=user_id).first()
    
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    device.status = 'SAFE'
    db.session.commit()
    
    return jsonify({'message': 'Device marked as found', 'status': 'SAFE'}), 200
