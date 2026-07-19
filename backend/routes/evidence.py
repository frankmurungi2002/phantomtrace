from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from models import Device, EvidencePhoto, EvidenceKeylog
import os
from datetime import datetime

evidence_bp = Blueprint('evidence', __name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'evidence_vault')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@evidence_bp.route('/photo', methods=['POST'])
def upload_photo():
    device_id = request.form.get('device_id')
    
    if not device_id or 'photo' not in request.files:
        return jsonify({'error': 'Missing device_id or photo'}), 400
    
    file = request.files['photo']
    filename = f"{device_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jpg"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    photo = EvidencePhoto(device_id=device_id, file_path=filepath)
    db.session.add(photo)
    db.session.commit()
    
    return jsonify({'message': 'Photo uploaded', 'id': photo.id}), 201

@evidence_bp.route('/keylog', methods=['POST'])
def upload_keylog():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['device_id', 'keylog_text']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    keylog = EvidenceKeylog(
        device_id=data['device_id'],
        keylog_text=data['keylog_text']
    )
    db.session.add(keylog)
    db.session.commit()
    
    return jsonify({'message': 'Keylog uploaded'}), 201

@evidence_bp.route('/photos/<device_id>', methods=['GET'])
@jwt_required()
def get_photos(device_id):
    photos = EvidencePhoto.query.filter_by(device_id=device_id).order_by(EvidencePhoto.timestamp.desc()).all()
    
    return jsonify({
        'photos': [{
            'id': p.id,
            'timestamp': p.timestamp.isoformat()
        } for p in photos]
    }), 200
