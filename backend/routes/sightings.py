from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db, socketio
from models import Device, Sighting

sightings_bp = Blueprint('sightings', __name__)

@sightings_bp.route('/bluetooth', methods=['POST'])
def bluetooth_sighting():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['beacon_id', 'latitude', 'longitude']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    device = Device.query.filter_by(beacon_id=data['beacon_id']).first()
    
    if not device:
        return jsonify({'status': 'unknown'}), 200
    
    if device.status != 'STOLEN':
        return jsonify({'status': 'safe'}), 200
    
    sighting = Sighting(
        device_id=device.id,
        latitude=data['latitude'],
        longitude=data['longitude'],
        accuracy=data.get('accuracy', 0),
        method='BLE'
    )
    
    db.session.add(sighting)
    db.session.commit()
    
    socketio.emit(f'sighting_{device.id}', {
        'latitude': data['latitude'],
        'longitude': data['longitude'],
        'method': 'BLE',
        'timestamp': sighting.timestamp.isoformat()
    })
    
    return jsonify({'status': 'reported', 'device_status': 'STOLEN'}), 200

@sightings_bp.route('/gsm', methods=['POST'])
def gsm_sighting():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['device_id', 'latitude', 'longitude']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    device = Device.query.get(data['device_id'])
    
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    sighting = Sighting(
        device_id=device.id,
        latitude=data['latitude'],
        longitude=data['longitude'],
        accuracy=data.get('accuracy', 0),
        method='GSM'
    )
    
    db.session.add(sighting)
    db.session.commit()
    
    socketio.emit(f'sighting_{device.id}', {
        'latitude': data['latitude'],
        'longitude': data['longitude'],
        'method': 'GSM',
        'timestamp': sighting.timestamp.isoformat()
    })
    
    return jsonify({'status': 'reported'}), 200

@sightings_bp.route('/trail/<device_id>', methods=['GET'])
@jwt_required()
def get_trail(device_id):
    sightings = Sighting.query.filter_by(device_id=device_id).order_by(Sighting.timestamp.asc()).all()
    
    return jsonify({
        'trail': [{
            'latitude': s.latitude,
            'longitude': s.longitude,
            'method': s.method,
            'timestamp': s.timestamp.isoformat()
        } for s in sightings]
    }), 200
