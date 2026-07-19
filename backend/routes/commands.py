from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from models import Device, Command
from datetime import datetime

commands_bp = Blueprint('commands', __name__)

@commands_bp.route('/send', methods=['POST'])
@jwt_required()
def send_command():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not all(k in data for k in ['device_id', 'command_type']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    valid_commands = ['LOCK', 'PHOTO', 'ALARM', 'AUDIO', 'WIPE', 'PING']
    if data['command_type'] not in valid_commands:
        return jsonify({'error': 'Invalid command type'}), 400
    
    device = Device.query.filter_by(id=data['device_id'], user_id=user_id).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    
    command = Command(
        device_id=data['device_id'],
        command_type=data['command_type']
    )
    
    db.session.add(command)
    db.session.commit()
    
    return jsonify({
        'message': 'Command queued successfully',
        'command_id': command.id,
        'status': 'PENDING'
    }), 201

@commands_bp.route('/pending/<device_id>', methods=['GET'])
def get_pending(device_id):
    commands = Command.query.filter_by(device_id=device_id, status='PENDING').all()
    
    return jsonify({
        'commands': [{
            'id': c.id,
            'command_type': c.command_type,
            'issued_at': c.issued_at.isoformat()
        } for c in commands]
    }), 200

@commands_bp.route('/acknowledge/<command_id>', methods=['POST'])
def acknowledge(command_id):
    command = Command.query.get(command_id)
    
    if not command:
        return jsonify({'error': 'Command not found'}), 404
    
    command.status = 'DONE'
    command.executed_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Command acknowledged'}), 200
