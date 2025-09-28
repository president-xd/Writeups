#!/usr/local/bin/python3
from flask import Flask, send_from_directory, request, jsonify
import os

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
BLOCKED_EXTENSIONS = {'exe', 'jar', 'py', 'pyc', 'php', 'js', 'sh', 'bat', 'cmd', 'com', 'scr', 'vbs', 'pl', 'rb', 'go', 'rs', 'c', 'cpp', 'h'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

PUBLIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public')

def allowed_file(filename):
    if '.' not in filename:
        return False
    basename = os.path.basename(filename)
    if '.' not in basename:
        return False
    extension = basename.rsplit('.', 1)[1].lower()
    if extension in BLOCKED_EXTENSIONS:
        return False
    return extension in ALLOWED_EXTENSIONS

def is_blocked_extension(filename):
    if '.' not in filename:
        return False
    basename = os.path.basename(filename)
    if '.' not in basename:
        return False
    extension = basename.rsplit('.', 1)[1].lower()
    return extension in BLOCKED_EXTENSIONS

# Remove all files in uploads to prevent malicious files from spreading
def wipe_upload_directory():
    if os.path.exists(UPLOAD_FOLDER):
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                pass

def get_file_size_mb(file_path):
    return round(os.path.getsize(file_path) / (1024 * 1024), 2)

@app.route('/')
def home():
    return send_from_directory(PUBLIC_DIR, 'index.html')

@app.route('/logo.png')
def logo():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'logo.png')

@app.route('/logo-sm.png')
def logo_small():
    # A smaller images looks better on mobile so I just resize it and serve that
    logo_sm_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
    if not os.path.exists(logo_sm_path):
        os.system("magick/bin/convert logo.png -resize 10% " + os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], 'logo-sm.png')

@app.route('/upload', methods=['POST'])
def upload_file():
    # Can't upload nothing, right?
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected! Please choose a magical image to upload.'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected! Please choose a magical image to upload.'}), 400
    
    # Prevent uploading dangerous files
    if '.' not in file.filename:
        wipe_upload_directory()
        return jsonify({'success': False, 'message': '🚨 ATTACK DETECTED! Suspicious file without extension detected on the union network. All gallery files have been wiped for security. The Sorcerer\'s Council has been notified.'}), 403
    
    if is_blocked_extension(file.filename):
        wipe_upload_directory()
        return jsonify({'success': False, 'message': '🚨 ATTACK DETECTED! Malicious executable detected on the union network. All gallery files have been wiped for security. The Sorcerer\'s Council has been notified.'}), 403
    
    if file and allowed_file(file.filename):
        original_filename = file.filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        
        file.save(file_path)
        
        file_size = get_file_size_mb(file_path)
        
        return jsonify({
            'success': True, 
            'message': f'🎉 Spell cast successfully! "{original_filename}" has been added to the gallery ({file_size} MB)',
            'redirect': '/gallery'
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid file type! Only magical images (PNG, JPG, JPEG, GIF, BMP, WEBP) are allowed.'}), 400

@app.route('/gallery')
def gallery():
    return send_from_directory(PUBLIC_DIR, 'gallery.html')

@app.route('/api/gallery')
def api_gallery():
    uploaded_files = []
    
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            # Don't want to show logo-sm.png on the gallery
            if filename == 'logo-sm.png':
                continue
            if allowed_file(filename):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_size = get_file_size_mb(file_path)
                
                uploaded_files.append({
                    'filename': filename,
                    'original_name': filename,
                    'size_mb': file_size,
                    'extension': filename.rsplit('.', 1)[1].lower() if '.' in filename else 'unknown'
                })
    
    return jsonify(uploaded_files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Make sure to handle the case where the file is logo-sm.png (not part of the vault)
    if filename == 'logo-sm.png':
        return "File not found", 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Serve all files from public to /
@app.route('/<path:filename>')
def serve_files(filename):
    try:
        return send_from_directory(PUBLIC_DIR, filename)
    except:
        return "File not found", 404

if __name__ == '__main__':
    # Make upload directory
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    app.run(debug=True, host='0.0.0.0', port=5000)