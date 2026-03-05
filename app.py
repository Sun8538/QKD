"""
Quantum Cryptography for IoT Networks - Main Application
Flask-based web application with QKD, Pub/Sub messaging, AI assistant, and secure file sharing
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import hashlib
import hmac as _hmac
import secrets
import uuid
import os
import json
import socket
from datetime import datetime, timedelta
import threading
import time

# ── Local-IP helper (used for IoT sensor URL generation) ─────────────────────
def get_local_ip():
    """Return the machine's LAN IP so phones on the same WiFi can reach Flask."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))   # no data is actually sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

# Import custom modules
from config import Config
from database import get_db, init_db
from qkd_protocol import BB84Protocol, QKDKeyManager
from qkd_encryption import QKDEncryption, QuantumSecureChannel, FileEncryptionService
from ai_assistant import AIKeyManagementAssistant, KeyRotationScheduler
from email_service import EmailService, create_email_service

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Support reverse proxies (VS Code Dev Tunnels, ngrok, etc.)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialize services
qkd_manager = QKDKeyManager()
ai_assistant = AIKeyManagementAssistant(
    azure_endpoint=Config.AZURE_OPENAI_ENDPOINT,
    azure_key=Config.AZURE_OPENAI_KEY,
    deployment=Config.AZURE_OPENAI_DEPLOYMENT
)
key_scheduler = KeyRotationScheduler(ai_assistant)

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Create upload directories
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(Config.QR_FOLDER, exist_ok=True)
CHAT_FILES_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'chat_files')
os.makedirs(CHAT_FILES_FOLDER, exist_ok=True)


def create_notification(user_id, notif_type, title, message, link=None):
    """Helper to create a notification for a user"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        cursor.execute('''
            INSERT INTO notifications (user_id, type, title, message, link, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, notif_type, title, message, link, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error creating notification: {e}")

def generate_visualization_from_key(key_data):
    """Generate visualization steps from stored key data"""
    alice_bits = key_data.get('alice_bits', '')[:20] or ''
    alice_bases = key_data.get('alice_bases', '')[:20] or ''
    bob_bases = key_data.get('bob_bases', '')[:20] or ''
    sifted_key = key_data.get('sifted_key', '')[:20] or ''
    final_key = key_data.get('final_key', '') or ''
    
    # Ensure error_rate is a float
    try:
        error_rate = float(key_data.get('error_rate', 0) or 0)
    except (TypeError, ValueError):
        error_rate = 0.0
    
    visualization = [
        {
            'step': 1,
            'name': 'Alice Generates Random Bits',
            'description': 'Alice creates a sequence of random classical bits (0s and 1s)',
            'data': {
                'bits': list(alice_bits),
                'total': len(key_data.get('alice_bits', ''))
            }
        },
        {
            'step': 2,
            'name': 'Alice Chooses Random Bases',
            'description': 'Alice randomly selects Rectilinear (+) or Diagonal (×) basis for each bit',
            'data': {
                'bases': list(alice_bases),
                'total': len(key_data.get('alice_bases', ''))
            }
        },
        {
            'step': 3,
            'name': 'Alice Encodes Qubits',
            'description': 'Alice prepares photons in quantum states based on her bits and bases',
            'data': {
                'qubits': [
                    {'state': '|0⟩' if b == '0' else '|1⟩', 'polarization': '↔' if b == '0' else '↕'} 
                    if alice_bases[i:i+1] == '+' else {'state': '|+⟩' if b == '0' else '|-⟩', 'polarization': '⤢' if b == '0' else '⤡'}
                    for i, b in enumerate(alice_bits[:10])
                ]
            }
        },
        {
            'step': 4,
            'name': 'Bob Chooses Random Bases',
            'description': 'Bob independently selects random measurement bases',
            'data': {'bases': list(bob_bases)}
        },
        {
            'step': 5,
            'name': 'Bob Measures Qubits',
            'description': 'Bob measures received photons using his chosen bases',
            'data': {
                'measurements': [
                    {'basis_match': alice_bases[i:i+1] == bob_bases[i:i+1]} 
                    for i in range(min(len(alice_bases), len(bob_bases), 10))
                ]
            }
        },
        {
            'step': 6,
            'name': 'Basis Reconciliation',
            'description': 'Alice and Bob publicly compare their bases (not the bits!)',
            'data': {
                'matching_count': sum(1 for i in range(min(len(alice_bases), len(bob_bases))) if alice_bases[i:i+1] == bob_bases[i:i+1]),
                'total': len(alice_bases),
                'match_rate': f"{sum(1 for i in range(min(len(alice_bases), len(bob_bases))) if alice_bases[i:i+1] == bob_bases[i:i+1]) / max(len(alice_bases), 1) * 100:.1f}%"
            }
        },
        {
            'step': 7,
            'name': 'Key Sifting',
            'description': 'Keep only bits where both used the same basis',
            'data': {
                'sifted_length': len(sifted_key),
                'alice_sifted': list(sifted_key[:20]),
                'bob_sifted': list(sifted_key[:20])
            }
        },
        {
            'step': 8,
            'name': 'Error Rate Estimation',
            'description': 'Check for eavesdropping by comparing a sample of bits',
            'data': {
                'error_rate': error_rate,
                'error_rate_percent': f"{error_rate * 100:.2f}%",
                'threshold': '11%',
                'secure': error_rate < 0.11
            }
        },
        {
            'step': 9,
            'name': 'Privacy Amplification',
            'description': 'Hash function applied to remove any leaked information',
            'data': {
                'input_length': len(sifted_key),
                'output_length': len(final_key) * 4 if final_key else 256,
                'key_preview': (final_key[:16] + '...') if final_key else 'N/A'
            }
        },
        {
            'step': 10,
            'name': 'Key Generation Complete',
            'description': 'Secure quantum key successfully generated!',
            'data': {
                'key_length_bits': len(final_key) * 4 if final_key else 256,
                'key_hash': key_data.get('key_hash', 'N/A'),
                'error_rate': error_rate,
                'error_rate_percent': f"{error_rate * 100:.2f}%",
                'secure': True
            }
        }
    ]
    return visualization

# Initialize database on first request
@app.before_request
def before_request():
    if not hasattr(app, 'db_initialized'):
        init_db()
        app.db_initialized = True

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# Authentication Routes
# ============================================

@app.route('/')
def index():
    """Home page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index_new.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password') or request.form.get('Con_Password')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        
        # Hash password
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if email exists
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('Email already registered.', 'danger')
            conn.close()
            return render_template('auth/register.html')
        
        # Check if username exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already taken.', 'danger')
            conn.close()
            return render_template('auth/register.html')
        
        # Insert new user
        cursor.execute('''
            INSERT INTO users (username, email, password, phone, address, is_verified, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        ''', (username, email, password_hash, phone, address, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password_hash))
        user = cursor.fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['is_admin'] = bool(user['is_admin'])
            
            # Update last login
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                          (datetime.now().isoformat(), user['id']))
            conn.commit()
            conn.close()
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        
        conn.close()
        flash('Invalid email or password.', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ============================================
# Dashboard and Main Routes
# ============================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user stats
    cursor.execute('SELECT COUNT(*) FROM files WHERE uploaded_by = ?', (session['user_id'],))
    file_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM channels WHERE created_by = ?', (session['user_id'],))
    channel_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM messages WHERE sender_id = ?', (session['user_id'],))
    message_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM quantum_keys WHERE created_by = ? AND is_active = 1', 
                  (session['user_id'],))
    active_keys = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM iot_devices WHERE owner_id = ? AND is_active = 1',
                  (session['user_id'],))
    device_count = cursor.fetchone()[0]
    
    # Get recent activities
    cursor.execute('''
        SELECT 'file' as type, original_filename as name, uploaded_at as time 
        FROM files WHERE uploaded_by = ?
        UNION ALL
        SELECT 'channel' as type, name, created_at as time 
        FROM channels WHERE created_by = ?
        ORDER BY time DESC LIMIT 10
    ''', (session['user_id'], session['user_id']))
    recent_activities = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                          file_count=file_count,
                          channel_count=channel_count,
                          message_count=message_count,
                          active_keys=active_keys,
                          device_count=device_count,
                          recent_activities=recent_activities)

# ============================================
# QKD Key Generation and Visualization
# ============================================

@app.route('/qkd')
@login_required
def qkd_home():
    """QKD home page"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM quantum_keys WHERE created_by = ? ORDER BY created_at DESC LIMIT 10
    ''', (session['user_id'],))
    keys_raw = cursor.fetchall()
    conn.close()
    
    # Convert error_rate to float for safe template operations
    keys = []
    for key in keys_raw:
        key_dict = dict(key)
        try:
            key_dict['error_rate'] = float(key_dict.get('error_rate', 0) or 0)
        except (ValueError, TypeError):
            key_dict['error_rate'] = 0.0
        keys.append(key_dict)
    
    return render_template('qkd/qkd_home.html', keys=keys)

@app.route('/qkd/generate', methods=['GET', 'POST'])
@login_required
def qkd_generate():
    """Generate new QKD key with visualization"""
    if request.method == 'POST':
        key_length = int(request.form.get('key_length', 256))
        
        # Generate QKD key using BB84 protocol
        protocol = BB84Protocol(key_length)
        result = protocol.generate_key()
        
        if result['success']:
            # Store key in database
            key_id = str(uuid.uuid4())
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quantum_keys 
                (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
                 key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'session')
            ''', (
                key_id,
                result['alice_bits'],
                result['alice_bases'],
                result['bob_bases'],
                result['sifted_key'],
                result['final_key'],
                result['key_hash'],
                result['error_rate'],
                session['user_id'],
                datetime.now().isoformat(),
                (datetime.now() + timedelta(hours=1)).isoformat()
            ))
            
            # Log visualization data with key_id for proper retrieval
            cursor.execute('''
                INSERT INTO qkd_logs (session_id, step_name, step_data, visualization_data, created_at)
                VALUES (?, 'full_generation', ?, ?, ?)
            ''', (
                key_id,  # Use key_id instead of session_id for proper lookup
                json.dumps(result),
                json.dumps(result['visualization']),
                datetime.now().isoformat()
            ))
            
            # Create key refresh schedule
            cursor.execute('''
                INSERT INTO key_refresh_schedule 
                (quantum_key_id, refresh_interval, last_refresh, next_refresh, is_active)
                VALUES (?, ?, ?, ?, 1)
            ''', (
                cursor.lastrowid,
                Config.KEY_REFRESH_INTERVAL,
                datetime.now().isoformat(),
                (datetime.now() + timedelta(seconds=Config.KEY_REFRESH_INTERVAL)).isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            result['key_id'] = key_id
            flash('Quantum key generated successfully!', 'success')
            return render_template('qkd/qkd_visualization.html', 
                                 key_id=key_id,
                                 key_hash=result['key_hash'],
                                 error_rate=result['error_rate'],
                                 is_active=1,
                                 key_data=result,
                                 visualization_steps=result['visualization'])
        else:
            flash(f'Key generation failed: {result.get("error", "Unknown error")}', 'danger')
            return redirect(url_for('qkd_generate'))
    
    return render_template('qkd/qkd_generate.html')

@app.route('/qkd/visualize/<key_id>')
@login_required
def qkd_visualize(key_id):
    """Visualize existing QKD key generation process"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM quantum_keys WHERE key_id = ?', (key_id,))
    key_data = cursor.fetchone()
    
    if not key_data:
        flash('Key not found.', 'danger')
        return redirect(url_for('qkd_home'))
    
    cursor.execute('SELECT * FROM qkd_logs WHERE session_id = ?', (key_id,))
    log_data = cursor.fetchone()
    
    conn.close()
    
    key_dict = dict(key_data)
    # Convert error_rate to float
    try:
        key_dict['error_rate'] = float(key_dict.get('error_rate', 0) or 0)
    except (ValueError, TypeError):
        key_dict['error_rate'] = 0.0
    
    # Get visualization from logs or generate a reconstructed one
    if log_data and log_data['visualization_data']:
        visualization = json.loads(log_data['visualization_data'])
    else:
        # Reconstruct visualization from stored key data
        visualization = generate_visualization_from_key(key_dict)
    
    return render_template('qkd/qkd_visualization.html', 
                          key_data=key_dict,
                          key_id=key_id,
                          key_hash=key_dict.get('key_hash', 'N/A'),
                          error_rate=key_dict.get('error_rate', 0.0),
                          is_active=key_dict.get('is_active', 0),
                          visualization_steps=visualization)

@app.route('/api/qkd/generate', methods=['POST'])
@login_required
def api_qkd_generate():
    """API endpoint for QKD key generation"""
    data = request.get_json() or {}
    key_length = data.get('key_length', 256)
    
    protocol = BB84Protocol(key_length)
    result = protocol.generate_key()
    
    if result['success']:
        key_id = str(uuid.uuid4())
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO quantum_keys 
            (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
             key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'session')
        ''', (
            key_id,
            result['alice_bits'],
            result['alice_bases'],
            result['bob_bases'],
            result['sifted_key'],
            result['final_key'],
            result['key_hash'],
            result['error_rate'],
            session['user_id'],
            datetime.now().isoformat(),
            (datetime.now() + timedelta(hours=1)).isoformat()
        ))
        conn.commit()
        conn.close()
        
        result['key_id'] = key_id
    
    return jsonify(result)

# ============================================
# Pub/Sub Messaging System
# ============================================

@app.route('/channels')
@login_required
def channels_list():
    """List all channels"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get channels user has access to (only channels they own or are approved members of)
    cursor.execute('''
        SELECT c.*, u.username as creator_name,
               (SELECT COUNT(*) FROM channel_members WHERE channel_id = c.id AND status = 'approved') as member_count,
               (SELECT COUNT(*) FROM messages WHERE channel_id = c.id) as message_count
        FROM channels c
        JOIN users u ON c.created_by = u.id
        WHERE c.is_active = 1
          AND (
              c.created_by = ?
              OR EXISTS (
                  SELECT 1 FROM channel_members
                  WHERE channel_id = c.id AND user_id = ? AND status = 'approved'
              )
          )
        ORDER BY c.created_at DESC
    ''', (session['user_id'], session['user_id']))
    channels = cursor.fetchall()
    
    # Get user's channel memberships
    cursor.execute('''
        SELECT channel_id FROM channel_members WHERE user_id = ? AND status = 'approved'
    ''', (session['user_id'],))
    my_channels = [row['channel_id'] for row in cursor.fetchall()]
    
    # Get user's pending join requests
    cursor.execute('''
        SELECT jr.*, c.name as channel_name
        FROM join_requests jr
        JOIN channels c ON jr.channel_id = c.id
        WHERE jr.requester_id = ? AND jr.status = 'pending'
        ORDER BY jr.requested_at DESC
    ''', (session['user_id'],))
    pending_requests = cursor.fetchall()
    
    # Get user's private chats (excluding ones the user has deleted on their side)
    cursor.execute('''
        SELECT pc.*, 
               CASE WHEN pc.user1_id = ? THEN u2.username ELSE u1.username END as other_user_name,
               (SELECT content FROM messages WHERE receiver_id IN (pc.user1_id, pc.user2_id) AND sender_id IN (pc.user1_id, pc.user2_id) AND channel_id IS NULL ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages WHERE receiver_id IN (pc.user1_id, pc.user2_id) AND sender_id IN (pc.user1_id, pc.user2_id) AND channel_id IS NULL ORDER BY created_at DESC LIMIT 1) as last_message_at
        FROM private_chats pc
        JOIN users u1 ON pc.user1_id = u1.id
        JOIN users u2 ON pc.user2_id = u2.id
        WHERE pc.is_active = 1
          AND (
              (pc.user1_id = ? AND pc.deleted_by_user1 = 0)
              OR (pc.user2_id = ? AND pc.deleted_by_user2 = 0)
          )
        ORDER BY last_message_at DESC
        LIMIT 3
    ''', (session['user_id'], session['user_id'], session['user_id']))
    private_chats = cursor.fetchall()
    
    # Get discoverable channels (active channels the user is NOT owner/member of)
    cursor.execute('''
        SELECT c.id, c.channel_id, c.name, c.description, c.created_at,
               u.username as creator_name,
               (SELECT COUNT(*) FROM channel_members WHERE channel_id = c.id AND status = 'approved') as member_count
        FROM channels c
        JOIN users u ON c.created_by = u.id
        WHERE c.is_active = 1
          AND c.created_by != ?
          AND NOT EXISTS (
              SELECT 1 FROM channel_members
              WHERE channel_id = c.id AND user_id = ?
          )
        ORDER BY c.created_at DESC
    ''', (session['user_id'], session['user_id']))
    discoverable_channels = cursor.fetchall()

    conn.close()
    
    return render_template('messaging/channels.html', channels=channels, my_channels=my_channels, private_chats=private_chats, pending_requests=pending_requests, discoverable_channels=discoverable_channels)

@app.route('/channels/create', methods=['GET', 'POST'])
@login_required
def create_channel():
    """Create a new channel with QKD key"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        channel_type = request.form.get('channel_type', 'group')
        
        # Generate QKD key for the channel
        protocol = BB84Protocol(256)
        key_result = protocol.generate_key()
        
        if not key_result['success']:
            flash('Failed to generate quantum key for channel.', 'danger')
            return redirect(url_for('create_channel'))
        
        channel_id = str(uuid.uuid4())
        key_id = str(uuid.uuid4())
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Store the quantum key
        cursor.execute('''
            INSERT INTO quantum_keys 
            (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
             key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'channel')
        ''', (
            key_id,
            key_result['alice_bits'],
            key_result['alice_bases'],
            key_result['bob_bases'],
            key_result['sifted_key'],
            key_result['final_key'],
            key_result['key_hash'],
            key_result['error_rate'],
            session['user_id'],
            datetime.now().isoformat(),
            (datetime.now() + timedelta(hours=24)).isoformat()
        ))
        
        qk_row_id = cursor.lastrowid
        
        # Create channel
        cursor.execute('''
            INSERT INTO channels (channel_id, name, description, channel_type, quantum_key_id, 
                                 created_by, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (channel_id, name, description, channel_type, qk_row_id, 
              session['user_id'], datetime.now().isoformat()))
        
        channel_row_id = cursor.lastrowid
        
        # Add creator as admin member
        cursor.execute('''
            INSERT INTO channel_members (channel_id, user_id, role, quantum_key_verified, 
                                        joined_at, status, approved_by)
            VALUES (?, ?, 'admin', 1, ?, 'approved', ?)
        ''', (channel_row_id, session['user_id'], datetime.now().isoformat(), session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash(f'Channel "{name}" created successfully! Share the quantum key with members.', 'success')
        return redirect(url_for('view_channel', channel_id=channel_id))
    
    return render_template('messaging/create_channel.html')

@app.route('/channels/<channel_id>')
@login_required
def view_channel(channel_id):
    """View channel and messages"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get channel info with owner name
    cursor.execute('''
        SELECT c.*, u.username as owner_name 
        FROM channels c
        JOIN users u ON c.created_by = u.id
        WHERE c.channel_id = ?
    ''', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        flash('Channel not found.', 'danger')
        return redirect(url_for('channels_list'))
    
    # Check if user is a member
    cursor.execute('''
        SELECT * FROM channel_members 
        WHERE channel_id = ? AND user_id = ? AND status = 'approved'
    ''', (channel['id'], session['user_id']))
    membership = cursor.fetchone()

    # --- Access control: block non-members from seeing any channel data ---
    if not membership and channel['created_by'] != session['user_id']:
        conn.close()
        flash('You must be an approved member to view this channel. Request access below.', 'warning')
        return redirect(url_for('join_channel', channel_id=channel_id))

    # Get channel's quantum key
    cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (channel['quantum_key_id'],))
    quantum_key = cursor.fetchone()
    
    # Get messages (newest at bottom for chat flow)
    cursor.execute('''
        SELECT m.*, u.username as sender_name, m.created_at as sent_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.channel_id = ? AND m.is_deleted = 0
        ORDER BY m.created_at ASC LIMIT 50
    ''', (channel['id'],))
    messages = cursor.fetchall()
    
    # Get members
    cursor.execute('''
        SELECT cm.*, u.username, u.email
        FROM channel_members cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.channel_id = ?
    ''', (channel['id'],))
    members = [dict(row) for row in cursor.fetchall()]
    
    # Get pending join requests
    cursor.execute('''
        SELECT jr.*, u.username, u.email
        FROM join_requests jr
        JOIN users u ON jr.requester_id = u.id
        WHERE jr.channel_id = ? AND jr.status = 'pending'
    ''', (channel['id'],))
    pending_requests = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    is_admin = membership and membership['role'] == 'admin'
    is_creator = channel['created_by'] == session['user_id']
    
    return render_template('messaging/view_channel.html',
                          channel=channel,
                          membership=membership,
                          quantum_key=quantum_key,
                          messages=messages,
                          members=members,
                          pending_requests=pending_requests,
                          is_admin=is_admin or is_creator)

@app.route('/channels/<channel_id>/join', methods=['GET', 'POST'])
@login_required
def join_channel(channel_id):
    """Request to join a channel with key verification"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get channel with creator name and member count
    cursor.execute('''
        SELECT c.*, u.username as creator_name,
               (SELECT COUNT(*) FROM channel_members WHERE channel_id = c.id AND status = 'approved') as member_count
        FROM channels c
        JOIN users u ON c.created_by = u.id
        WHERE c.channel_id = ?
    ''', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        flash('Channel not found.', 'danger')
        return redirect(url_for('channels_list'))
    
    # Check if already a member
    cursor.execute('''
        SELECT * FROM channel_members WHERE channel_id = ? AND user_id = ?
    ''', (channel['id'], session['user_id']))
    existing = cursor.fetchone()
    
    if existing:
        if existing['status'] == 'approved':
            flash('You are already a member of this channel.', 'info')
            return redirect(url_for('view_channel', channel_id=channel_id))
        elif existing['status'] == 'pending':
            flash('Your join request is pending approval.', 'info')
            return redirect(url_for('channels_list'))
    
    if request.method == 'POST':
        provided_key = request.form.get('quantum_key')
        
        # Get channel's quantum key
        cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (channel['quantum_key_id'],))
        channel_key = cursor.fetchone()
        
        # Verify key match (timing-safe)
        provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()[:16]
        key_matches = _hmac.compare_digest(provided_hash, channel_key['key_hash'])
        
        request_id = str(uuid.uuid4())
        
        if key_matches:
            # Key verified - create pending membership for admin approval
            cursor.execute('''
                INSERT INTO join_requests (request_id, channel_id, requester_id, 
                                          provided_key_hash, status, verified, requested_at)
                VALUES (?, ?, ?, ?, 'pending', 1, ?)
            ''', (request_id, channel['id'], session['user_id'], provided_hash, 
                  datetime.now().isoformat()))
            
            conn.commit()
            
            # Notify channel owner about the join request
            create_notification(
                channel['created_by'],
                'join_request',
                'New Join Request',
                f'{session["username"]} requested to join channel "{channel["name"]}"',
                url_for('view_channel', channel_id=channel_id)
            )
            
            flash('Key verified! Your request is pending admin approval.', 'success')
        else:
            # Key mismatch - reject
            cursor.execute('''
                INSERT INTO join_requests (request_id, channel_id, requester_id, 
                                          provided_key_hash, status, verified, requested_at)
                VALUES (?, ?, ?, ?, 'rejected', 0, ?)
            ''', (request_id, channel['id'], session['user_id'], provided_hash,
                  datetime.now().isoformat()))
            
            conn.commit()
            flash('Quantum key mismatch! Access denied.', 'danger')
        
        conn.close()
        return redirect(url_for('channels_list'))
    
    conn.close()
    return render_template('messaging/join_channel.html', channel=channel)

@app.route('/channels/<channel_id>/approve/<request_id>')
@login_required
def approve_join_request(channel_id, request_id):
    """Approve a join request"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify user is admin of channel
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('channels_list'))
    
    # Get join request
    cursor.execute('SELECT * FROM join_requests WHERE request_id = ?', (request_id,))
    join_request = cursor.fetchone()
    
    if not join_request or join_request['status'] != 'pending':
        flash('Invalid request.', 'danger')
        return redirect(url_for('view_channel', channel_id=channel_id))
    
    # Update join request
    cursor.execute('''
        UPDATE join_requests SET status = 'approved', processed_at = ?, processed_by = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), session['user_id'], request_id))
    
    # Add as channel member
    cursor.execute('''
        INSERT INTO channel_members (channel_id, user_id, role, quantum_key_verified, 
                                    joined_at, status, approved_by, approved_at)
        VALUES (?, ?, 'member', 1, ?, 'approved', ?, ?)
    ''', (channel['id'], join_request['requester_id'], datetime.now().isoformat(),
          session['user_id'], datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    # Notify the requester that they were approved
    create_notification(
        join_request['requester_id'],
        'join_approved',
        'Join Request Approved',
        f'Your request to join channel "{channel["name"] if "name" in channel.keys() else "Unknown"}" was approved!',
        url_for('view_channel', channel_id=channel_id)
    )
    
    flash('Join request approved!', 'success')
    return redirect(url_for('view_channel', channel_id=channel_id))

@app.route('/channels/<channel_id>/reject/<request_id>')
@login_required
def reject_join_request(channel_id, request_id):
    """Reject a join request"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('channels_list'))
    
    # Get the join request to know who to notify
    cursor.execute('SELECT * FROM join_requests WHERE request_id = ?', (request_id,))
    join_request = cursor.fetchone()
    
    cursor.execute('''
        UPDATE join_requests SET status = 'rejected', processed_at = ?, processed_by = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), session['user_id'], request_id))
    
    conn.commit()
    conn.close()
    
    # Notify the requester that they were rejected
    if join_request:
        create_notification(
            join_request['requester_id'],
            'join_rejected',
            'Join Request Rejected',
            f'Your request to join channel "{channel["name"] if "name" in channel.keys() else "Unknown"}" was rejected.',
            url_for('channels_list')
        )
    
    flash('Join request rejected.', 'info')
    return redirect(url_for('view_channel', channel_id=channel_id))


@app.route('/api/join-requests/<request_id>/approve', methods=['POST'])
@login_required
def api_approve_join_request(request_id):
    """API endpoint to approve a join request"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get join request
    cursor.execute('SELECT * FROM join_requests WHERE request_id = ?', (request_id,))
    join_request = cursor.fetchone()
    
    if not join_request or join_request['status'] != 'pending':
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid request'})
    
    # Get channel and verify user is admin
    cursor.execute('SELECT * FROM channels WHERE id = ?', (join_request['channel_id'],))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Update join request
    cursor.execute('''
        UPDATE join_requests SET status = 'approved', processed_at = ?, processed_by = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), session['user_id'], request_id))
    
    # Add as channel member
    cursor.execute('''
        INSERT INTO channel_members (channel_id, user_id, role, quantum_key_verified, 
                                    joined_at, status, approved_by, approved_at)
        VALUES (?, ?, 'member', 1, ?, 'approved', ?, ?)
    ''', (channel['id'], join_request['requester_id'], datetime.now().isoformat(),
          session['user_id'], datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    # Notify requester
    create_notification(
        join_request['requester_id'],
        'join_approved',
        'Join Request Approved',
        f'Your request to join a channel was approved!',
        url_for('channels_list')
    )
    
    return jsonify({'success': True, 'message': 'Join request approved'})


@app.route('/api/join-requests/<request_id>/reject', methods=['POST'])
@login_required
def api_reject_join_request(request_id):
    """API endpoint to reject a join request"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get join request
    cursor.execute('SELECT * FROM join_requests WHERE request_id = ?', (request_id,))
    join_request = cursor.fetchone()
    
    if not join_request or join_request['status'] != 'pending':
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid request'})
    
    # Get channel and verify user is admin
    cursor.execute('SELECT * FROM channels WHERE id = ?', (join_request['channel_id'],))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    cursor.execute('''
        UPDATE join_requests SET status = 'rejected', processed_at = ?, processed_by = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), session['user_id'], request_id))
    
    conn.commit()
    conn.close()
    
    # Notify requester
    create_notification(
        join_request['requester_id'],
        'join_rejected',
        'Join Request Rejected',
        f'Your channel join request was rejected.',
        url_for('channels_list')
    )
    
    return jsonify({'success': True, 'message': 'Join request rejected'})


@app.route('/api/channels/<channel_id>/send', methods=['POST'])
@login_required
def send_channel_message(channel_id):
    """Send a message to a channel"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        return jsonify({'success': False, 'error': 'Channel not found'})
    
    # Check membership
    cursor.execute('''
        SELECT * FROM channel_members 
        WHERE channel_id = ? AND user_id = ? AND status = 'approved'
    ''', (channel['id'], session['user_id']))
    
    if not cursor.fetchone():
        return jsonify({'success': False, 'error': 'Not a member of this channel'})
    
    data = request.get_json()
    message_content = data.get('message', '')
    
    if not message_content:
        return jsonify({'success': False, 'error': 'Empty message'})
    
    # Get channel's quantum key
    cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (channel['quantum_key_id'],))
    quantum_key = cursor.fetchone()
    
    # Encrypt message
    encryptor = QKDEncryption(quantum_key['final_key'])
    encrypted_content = encryptor.encrypt_message(message_content)
    
    message_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT INTO messages (message_id, channel_id, sender_id, content, encrypted_content,
                             quantum_key_id, message_type, is_encrypted, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'text', 1, ?)
    ''', (message_id, channel['id'], session['user_id'], message_content, encrypted_content,
          quantum_key['id'], datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message_id': message_id,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/channels/<channel_id>/messages', methods=['GET', 'POST'])
@login_required
def channel_messages(channel_id):
    """Get or send messages to a channel"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        conn.close()
        return jsonify({'success': False, 'error': 'Channel not found'})
    
    if request.method == 'POST':
        # Send a message
        # Check membership
        cursor.execute('''
            SELECT * FROM channel_members 
            WHERE channel_id = ? AND user_id = ? AND status = 'approved'
        ''', (channel['id'], session['user_id']))
        
        if not cursor.fetchone() and channel['created_by'] != session['user_id']:
            conn.close()
            return jsonify({'success': False, 'error': 'Not a member of this channel'})
        
        data = request.get_json()
        message_content = data.get('content', '') or data.get('message', '')
        
        if not message_content:
            conn.close()
            return jsonify({'success': False, 'error': 'Empty message'})
        
        # Get channel's quantum key
        cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (channel['quantum_key_id'],))
        quantum_key = cursor.fetchone()
        
        # Encrypt message
        encryptor = QKDEncryption(quantum_key['final_key'])
        encrypted_content = encryptor.encrypt_message(message_content)
        
        message_id = str(uuid.uuid4())
        
        cursor.execute('''
            INSERT INTO messages (message_id, channel_id, sender_id, content, encrypted_content,
                                 quantum_key_id, message_type, is_encrypted, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'text', 1, ?)
        ''', (message_id, channel['id'], session['user_id'], message_content, encrypted_content,
              quantum_key['id'], datetime.now().isoformat()))
        
        db_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message_id': message_id,
            'db_id': db_id,
            'timestamp': datetime.now().isoformat()
        })
    
    # GET - retrieve messages (newest at bottom)
    # Enforce membership check — non-members must not read channel messages via API
    cursor.execute('''
        SELECT 1 FROM channel_members WHERE channel_id = ? AND user_id = ? AND status = 'approved'
    ''', (channel['id'], session['user_id']))
    if not cursor.fetchone() and channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Not authorized to view this channel'}), 403

    cursor.execute('''
        SELECT m.*, u.username as sender_name, m.sender_id, m.created_at as sent_at
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.channel_id = ? AND m.is_deleted = 0
        ORDER BY m.created_at ASC LIMIT 50
    ''', (channel['id'],))
    
    messages = []
    for row in cursor.fetchall():
        msg_data = {
            'id': row['id'],
            'message_id': row['message_id'],
            'sender_id': row['sender_id'],
            'sender_name': row['sender_name'],
            'content': row['content'],
            'message_type': row['message_type'] or 'text',
            'sent_at': row['sent_at'],
            'is_mine': row['sender_id'] == session['user_id'],
            'timestamp': row['created_at']
        }
        try:
            msg_data['file_name'] = row['file_name']
            msg_data['file_path'] = row['file_path']
            msg_data['file_size'] = row['file_size']
        except (IndexError, KeyError):
            msg_data['file_name'] = None
            msg_data['file_path'] = None
            msg_data['file_size'] = None
        messages.append(msg_data)
    
    conn.close()
    
    return jsonify({'success': True, 'messages': messages})


@app.route('/api/channels/<channel_id>', methods=['PUT'])
@login_required
def api_update_channel(channel_id):
    """Update channel settings"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    data = request.get_json()
    name = data.get('name', channel['name'])
    description = data.get('description', channel['description'])
    
    cursor.execute('''
        UPDATE channels SET name = ?, description = ? WHERE id = ?
    ''', (name, description, channel['id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Channel updated'})


@app.route('/api/channels/<channel_id>/refresh-key', methods=['POST'])
@login_required
def api_refresh_channel_key(channel_id):
    """Refresh the quantum key for a channel"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Generate new QKD key
    protocol = BB84Protocol(256)
    key_result = protocol.generate_key()
    
    if not key_result['success']:
        conn.close()
        return jsonify({'success': False, 'error': 'Failed to generate new quantum key'})
    
    new_key_id = str(uuid.uuid4())
    
    # Mark old key as inactive
    cursor.execute('UPDATE quantum_keys SET is_active = 0 WHERE id = ?', (channel['quantum_key_id'],))
    
    # Store new key
    cursor.execute('''
        INSERT INTO quantum_keys 
        (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
         key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'channel')
    ''', (
        new_key_id,
        key_result['alice_bits'],
        key_result['alice_bases'],
        key_result['bob_bases'],
        key_result['sifted_key'],
        key_result['final_key'],
        key_result['key_hash'],
        key_result['error_rate'],
        session['user_id'],
        datetime.now().isoformat(),
        (datetime.now() + timedelta(hours=24)).isoformat()
    ))
    
    new_key_row_id = cursor.lastrowid
    
    # Update channel to use new key
    cursor.execute('UPDATE channels SET quantum_key_id = ? WHERE id = ?', 
                  (new_key_row_id, channel['id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True, 
        'new_key_hash': key_result['key_hash'],
        'message': 'Quantum key refreshed'
    })


@app.route('/api/channels/<channel_id>', methods=['DELETE'])
@login_required
def api_delete_channel(channel_id):
    """Delete a channel"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel or channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Delete channel members
    cursor.execute('DELETE FROM channel_members WHERE channel_id = ?', (channel['id'],))
    
    # Delete messages
    cursor.execute('DELETE FROM messages WHERE channel_id = ?', (channel['id'],))
    
    # Delete join requests
    cursor.execute('DELETE FROM join_requests WHERE channel_id = ?', (channel['id'],))
    
    # Delete channel
    cursor.execute('DELETE FROM channels WHERE id = ?', (channel['id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Channel deleted'})


@app.route('/api/channels/<channel_id>/clear', methods=['POST'])
@login_required
def api_clear_channel_chat(channel_id):
    """Clear all messages in a channel (admin/owner only)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        conn.close()
        return jsonify({'success': False, 'error': 'Channel not found'})
    
    # Check if user is admin/owner
    if channel['created_by'] != session['user_id']:
        cursor.execute('''
            SELECT * FROM channel_members 
            WHERE channel_id = ? AND user_id = ? AND role = 'admin'
        ''', (channel['id'], session['user_id']))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Only admins can clear chat'})
    
    # Soft delete all messages
    cursor.execute('''
        UPDATE messages SET is_deleted = 1 WHERE channel_id = ?
    ''', (channel['id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Chat cleared successfully'})


@app.route('/api/channels/<channel_id>/block-user', methods=['POST'])
@login_required
def api_block_channel_user(channel_id):
    """Block/remove a user from a channel (admin/owner only)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        conn.close()
        return jsonify({'success': False, 'error': 'Channel not found'})
    
    # Check if user is admin/owner
    if channel['created_by'] != session['user_id']:
        cursor.execute('''
            SELECT * FROM channel_members 
            WHERE channel_id = ? AND user_id = ? AND role = 'admin'
        ''', (channel['id'], session['user_id']))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Only admins can block users'})
    
    data = request.get_json()
    user_id_to_block = data.get('user_id')
    
    if not user_id_to_block:
        conn.close()
        return jsonify({'success': False, 'error': 'User ID required'})
    
    # Cannot block the owner
    if user_id_to_block == channel['created_by']:
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot block the channel owner'})
    
    # Remove user from channel
    cursor.execute('''
        DELETE FROM channel_members 
        WHERE channel_id = ? AND user_id = ?
    ''', (channel['id'], user_id_to_block))
    
    # Get username for response
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id_to_block,))
    user = cursor.fetchone()
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True, 
        'message': f'User {user["username"] if user else "Unknown"} has been removed from the channel'
    })


@app.route('/api/channels/<channel_id>/upload-file', methods=['POST'])
@login_required
def upload_channel_file(channel_id):
    """Upload a file to a channel"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
    channel = cursor.fetchone()
    
    if not channel:
        conn.close()
        return jsonify({'success': False, 'error': 'Channel not found'})
    
    # Check membership
    cursor.execute('''
        SELECT * FROM channel_members 
        WHERE channel_id = ? AND user_id = ? AND status = 'approved'
    ''', (channel['id'], session['user_id']))
    
    if not cursor.fetchone() and channel['created_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Not a member of this channel'})
    
    if 'file' not in request.files:
        conn.close()
        return jsonify({'success': False, 'error': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        conn.close()
        return jsonify({'success': False, 'error': 'No file selected'})
    
    # Save file
    filename = secure_filename(file.filename)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(CHAT_FILES_FOLDER, f"{file_id}_{filename}")
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    
    # Get channel's quantum key
    cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (channel['quantum_key_id'],))
    quantum_key = cursor.fetchone()
    
    message_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT INTO messages (message_id, channel_id, sender_id, content, encrypted_content,
                             quantum_key_id, message_type, is_encrypted, created_at,
                             file_path, file_name, file_size)
        VALUES (?, ?, ?, ?, ?, ?, 'file', 1, ?, ?, ?, ?)
    ''', (message_id, channel['id'], session['user_id'], filename, '',
          quantum_key['id'] if quantum_key else None, datetime.now().isoformat(),
          file_path, filename, file_size))
    
    db_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message_id': db_id,
        'uuid': message_id,
        'file_name': filename,
        'file_size': file_size,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/chat/<chat_id>/upload-file', methods=['POST'])
@login_required  
def upload_private_chat_file(chat_id):
    """Upload a file to a private chat"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.*, qk.final_key
        FROM private_chats pc
        JOIN quantum_keys qk ON pc.quantum_key_id = qk.id
        WHERE pc.chat_id = ?
    ''', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        conn.close()
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    if 'file' not in request.files:
        conn.close()
        return jsonify({'success': False, 'error': 'No file provided'})
    
    file = request.files['file']
    if file.filename == '':
        conn.close()
        return jsonify({'success': False, 'error': 'No file selected'})
    
    # Save file
    filename = secure_filename(file.filename)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(CHAT_FILES_FOLDER, f"{file_id}_{filename}")
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    
    receiver_id = chat['user2_id'] if chat['user1_id'] == session['user_id'] else chat['user1_id']
    
    message_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT INTO messages (message_id, sender_id, receiver_id, content, encrypted_content,
                             quantum_key_id, message_type, is_encrypted, created_at,
                             file_path, file_name, file_size)
        VALUES (?, ?, ?, ?, ?, ?, 'file', 1, ?, ?, ?, ?)
    ''', (message_id, session['user_id'], receiver_id, filename, '',
          chat['quantum_key_id'], datetime.now().isoformat(),
          file_path, filename, file_size))
    
    db_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Notify receiver
    create_notification(
        receiver_id,
        'private_message_file',
        'File Received',
        f'{session["username"]} sent you a file: {filename}',
        url_for('view_private_chat', chat_id=chat_id)
    )
    
    return jsonify({
        'success': True,
        'message_id': db_id,
        'uuid': message_id,
        'file_name': filename,
        'file_size': file_size,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/chat-file/<int:message_id>')
@login_required
def download_chat_file(message_id):
    """Download a file from a channel or private chat message"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM messages WHERE id = ? AND message_type = ?', (message_id, 'file'))
    message = cursor.fetchone()
    
    if not message:
        conn.close()
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    # Check access - user must be sender, receiver, or member of channel
    has_access = False
    if message['sender_id'] == session['user_id']:
        has_access = True
    elif message['receiver_id'] and message['receiver_id'] == session['user_id']:
        has_access = True
    elif message['channel_id']:
        cursor.execute('''
            SELECT * FROM channel_members 
            WHERE channel_id = ? AND user_id = ? AND status = 'approved'
        ''', (message['channel_id'], session['user_id']))
        if cursor.fetchone():
            has_access = True
        # Also check if user is channel creator
        cursor.execute('SELECT created_by FROM channels WHERE id = ?', (message['channel_id'],))
        ch = cursor.fetchone()
        if ch and ch['created_by'] == session['user_id']:
            has_access = True
    
    conn.close()
    
    if not has_access:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    file_path = message['file_path']
    file_name = message['file_name'] or message['content']
    
    if file_path and os.path.exists(file_path):
        return send_file(file_path, as_attachment=True, download_name=file_name)
    else:
        return jsonify({'success': False, 'error': 'File not found on server'}), 404


@app.route('/api/chat/<chat_id>/clear', methods=['POST'])
@login_required
def clear_private_chat(chat_id):
    """Clear all messages in a private chat (soft delete)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM private_chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        conn.close()
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})

    # Soft-delete messages only for the requesting user so the other
    # participant's view is unaffected
    if session['user_id'] == chat['user1_id']:
        cursor.execute('''
            UPDATE messages SET deleted_by_user1 = 1
            WHERE channel_id IS NULL
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
    else:
        cursor.execute('''
            UPDATE messages SET deleted_by_user2 = 1
            WHERE channel_id IS NULL
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))

    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Chat cleared successfully'})


@app.route('/api/chat/<chat_id>/delete', methods=['POST'])
@login_required
def delete_private_chat(chat_id):
    """Delete a private chat"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM private_chats WHERE chat_id = ?', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        conn.close()
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'})

    is_user1 = (session['user_id'] == chat['user1_id'])

    # Soft-delete messages for the requesting user's view only
    if is_user1:
        cursor.execute('''
            UPDATE messages SET deleted_by_user1 = 1
            WHERE channel_id IS NULL
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
        cursor.execute(
            'UPDATE private_chats SET deleted_by_user1 = 1 WHERE chat_id = ?', (chat_id,)
        )
    else:
        cursor.execute('''
            UPDATE messages SET deleted_by_user2 = 1
            WHERE channel_id IS NULL
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
        cursor.execute(
            'UPDATE private_chats SET deleted_by_user2 = 1 WHERE chat_id = ?', (chat_id,)
        )

    # Only permanently remove the chat and its messages once both sides have deleted
    cursor.execute(
        'SELECT deleted_by_user1, deleted_by_user2 FROM private_chats WHERE chat_id = ?',
        (chat_id,)
    )
    status = cursor.fetchone()
    if status and status['deleted_by_user1'] and status['deleted_by_user2']:
        # Both users deleted — clean up physical files then remove DB records
        cursor.execute('''
            SELECT file_path FROM messages
            WHERE channel_id IS NULL AND message_type = 'file'
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
        for row in cursor.fetchall():
            if row['file_path'] and os.path.exists(row['file_path']):
                try:
                    os.remove(row['file_path'])
                except Exception:
                    pass
        cursor.execute('''
            DELETE FROM messages
            WHERE channel_id IS NULL
              AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
        cursor.execute('DELETE FROM private_chats WHERE chat_id = ?', (chat_id,))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Chat deleted successfully'})


# ============================================
# Private Chat
# ============================================

@app.route('/chat')
@login_required
def private_chat_list():
    """List private chats"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.*,
               CASE WHEN pc.user1_id = ? THEN u2.username ELSE u1.username END as other_user,
               CASE WHEN pc.user1_id = ? THEN u2.id ELSE u1.id END as other_user_id
        FROM private_chats pc
        JOIN users u1 ON pc.user1_id = u1.id
        JOIN users u2 ON pc.user2_id = u2.id
        WHERE pc.is_active = 1
          AND (
              (pc.user1_id = ? AND pc.deleted_by_user1 = 0)
              OR (pc.user2_id = ? AND pc.deleted_by_user2 = 0)
          )
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    chats = cursor.fetchall()
    
    # Get list of users for starting new chat
    cursor.execute('SELECT id, username, email FROM users WHERE id != ?', (session['user_id'],))
    users = cursor.fetchall()
    
    conn.close()
    
    return render_template('messaging/private_chats.html', chats=chats, users=users)

@app.route('/chat/start/<int:user_id>')
@login_required
def start_private_chat(user_id):
    """Start a new private chat"""
    if user_id == session['user_id']:
        flash('Cannot start chat with yourself.', 'warning')
        return redirect(url_for('private_chat_list'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if chat already exists
    cursor.execute('''
        SELECT * FROM private_chats 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    ''', (session['user_id'], user_id, user_id, session['user_id']))
    existing = cursor.fetchone()

    if existing:
        # If this user had previously "deleted" their side, restore it
        is_user1 = (existing['user1_id'] == session['user_id'])
        if is_user1 and existing['deleted_by_user1']:
            cursor.execute(
                'UPDATE private_chats SET deleted_by_user1 = 0 WHERE chat_id = ?',
                (existing['chat_id'],)
            )
            conn.commit()
        elif not is_user1 and existing['deleted_by_user2']:
            cursor.execute(
                'UPDATE private_chats SET deleted_by_user2 = 0 WHERE chat_id = ?',
                (existing['chat_id'],)
            )
            conn.commit()
        conn.close()
        return redirect(url_for('view_private_chat', chat_id=existing['chat_id']))
    
    # Generate QKD key for the chat
    protocol = BB84Protocol(256)
    key_result = protocol.generate_key()
    
    if not key_result['success']:
        flash('Failed to generate quantum key.', 'danger')
        conn.close()
        return redirect(url_for('private_chat_list'))
    
    chat_id = str(uuid.uuid4())
    key_id = str(uuid.uuid4())
    
    # Store quantum key
    cursor.execute('''
        INSERT INTO quantum_keys 
        (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
         key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'private_chat')
    ''', (
        key_id,
        key_result['alice_bits'],
        key_result['alice_bases'],
        key_result['bob_bases'],
        key_result['sifted_key'],
        key_result['final_key'],
        key_result['key_hash'],
        key_result['error_rate'],
        session['user_id'],
        datetime.now().isoformat(),
        (datetime.now() + timedelta(hours=24)).isoformat()
    ))
    
    qk_row_id = cursor.lastrowid
    
    # Create private chat
    cursor.execute('''
        INSERT INTO private_chats (chat_id, user1_id, user2_id, quantum_key_id, created_at, is_active)
        VALUES (?, ?, ?, ?, ?, 1)
    ''', (chat_id, session['user_id'], user_id, qk_row_id, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    flash('Private chat started with quantum encryption!', 'success')
    return redirect(url_for('view_private_chat', chat_id=chat_id))

@app.route('/chat/<chat_id>')
@login_required
def view_private_chat(chat_id):
    """View private chat"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.*, 
               u1.username as user1_name, u2.username as user2_name,
               qk.final_key, qk.key_hash, qk.expires_at
        FROM private_chats pc
        JOIN users u1 ON pc.user1_id = u1.id
        JOIN users u2 ON pc.user2_id = u2.id
        JOIN quantum_keys qk ON pc.quantum_key_id = qk.id
        WHERE pc.chat_id = ?
    ''', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        flash('Chat not found.', 'danger')
        return redirect(url_for('private_chat_list'))
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('private_chat_list'))
    
    other_user = chat['user2_name'] if chat['user1_id'] == session['user_id'] else chat['user1_name']

    # Determine which per-user delete flag to honour for the current viewer
    is_user1 = (chat['user1_id'] == session['user_id'])
    delete_col = 'm.deleted_by_user1 = 0' if is_user1 else 'm.deleted_by_user2 = 0'

    # Get messages visible to this user only
    cursor.execute(f'''
        SELECT m.*, u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.channel_id IS NULL AND m.is_deleted = 0
          AND {delete_col}
          AND ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
        ORDER BY m.created_at DESC LIMIT 50
    ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))
    messages = cursor.fetchall()

    conn.close()

    return render_template('messaging/private_chat.html',
                          chat=chat,
                          other_user=other_user,
                          messages=messages[::-1])

@app.route('/api/chat/<chat_id>/messages')
@login_required
def get_private_chat_messages(chat_id):
    """Get messages for a private chat, optionally only after a certain message ID"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.user1_id, pc.user2_id
        FROM private_chats pc
        WHERE pc.chat_id = ?
    ''', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    # Determine per-user delete filter so each user only sees their own view
    is_user1 = (chat['user1_id'] == session['user_id'])
    delete_col = 'm.deleted_by_user1 = 0' if is_user1 else 'm.deleted_by_user2 = 0'

    # Check for 'after' parameter for incremental updates
    after_id = request.args.get('after', 0, type=int)

    if after_id > 0:
        # Only fetch messages newer than the specified ID
        cursor.execute(f'''
            SELECT m.*, u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.channel_id IS NULL AND m.is_deleted = 0
              AND {delete_col}
              AND ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
              AND m.id > ?
            ORDER BY m.created_at ASC
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id'], after_id))
    else:
        # Fetch recent messages
        cursor.execute(f'''
            SELECT m.*, u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.channel_id IS NULL AND m.is_deleted = 0
              AND {delete_col}
              AND ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
            ORDER BY m.created_at DESC LIMIT 50
        ''', (chat['user1_id'], chat['user2_id'], chat['user2_id'], chat['user1_id']))

    messages = [dict(row) for row in cursor.fetchall()]

    conn.close()

    # Reverse only if fetching without 'after' parameter
    if after_id == 0:
        messages = messages[::-1]

    return jsonify({'success': True, 'messages': messages})

@app.route('/api/chat/<chat_id>/send', methods=['POST'])
@login_required
def send_private_message(chat_id):
    """Send private message"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT pc.*, qk.final_key
        FROM private_chats pc
        JOIN quantum_keys qk ON pc.quantum_key_id = qk.id
        WHERE pc.chat_id = ?
    ''', (chat_id,))
    chat = cursor.fetchone()
    
    if not chat:
        return jsonify({'success': False, 'error': 'Chat not found'})
    
    if chat['user1_id'] != session['user_id'] and chat['user2_id'] != session['user_id']:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    data = request.get_json()
    message_content = data.get('message', '')
    
    if not message_content:
        return jsonify({'success': False, 'error': 'Empty message'})
    
    receiver_id = chat['user2_id'] if chat['user1_id'] == session['user_id'] else chat['user1_id']
    
    # Encrypt message
    encryptor = QKDEncryption(chat['final_key'])
    encrypted_content = encryptor.encrypt_message(message_content)
    
    message_id = str(uuid.uuid4())
    
    cursor.execute('''
        INSERT INTO messages (message_id, sender_id, receiver_id, content, encrypted_content,
                             quantum_key_id, message_type, is_encrypted, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'text', 1, ?)
    ''', (message_id, session['user_id'], receiver_id, message_content, encrypted_content,
          chat['quantum_key_id'], datetime.now().isoformat()))
    
    db_message_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message_id': db_message_id,  # Return the database ID for incremental polling
        'uuid': message_id,
        'timestamp': datetime.now().isoformat()
    })

# ============================================
# File Encryption with QR Code
# ============================================

@app.route('/files')
@login_required
def files_list():
    """List user's files"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.*, qk.key_hash, qk.error_rate, 
               (SELECT COUNT(*) FROM file_requests WHERE file_id = f.id) as request_count,
               (SELECT COUNT(*) FROM file_requests WHERE file_id = f.id AND status = 'pending') as pending_count
        FROM files f
        LEFT JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE f.uploaded_by = ? AND f.is_active = 1
        ORDER BY f.uploaded_at DESC
    ''', (session['user_id'],))
    my_files = cursor.fetchall()
    
    # Get incoming file requests
    cursor.execute('''
        SELECT fr.*, f.original_filename, u.username as requester_name, u.email as requester_email
        FROM file_requests fr
        JOIN files f ON fr.file_id = f.id
        JOIN users u ON fr.requester_id = u.id
        WHERE fr.owner_id = ? AND fr.status = 'pending'
    ''', (session['user_id'],))
    incoming_requests = cursor.fetchall()
    
    # Get my file requests
    cursor.execute('''
        SELECT fr.*, f.original_filename, u.username as owner_name
        FROM file_requests fr
        JOIN files f ON fr.file_id = f.id
        JOIN users u ON fr.owner_id = u.id
        WHERE fr.requester_id = ?
        ORDER BY fr.requested_at DESC
    ''', (session['user_id'],))
    my_requests = cursor.fetchall()
    
    conn.close()
    
    return render_template('files/files_list.html', 
                          files=my_files,
                          pending_requests=incoming_requests,
                          my_requests=my_requests)

@app.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Upload and encrypt a file"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_file'))
        
        keywords = request.form.get('keywords', '')
        description = request.form.get('description', '')
        
        # Save original file temporarily
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        temp_path = os.path.join(Config.UPLOAD_FOLDER, f"temp_{file_id}_{filename}")
        file.save(temp_path)
        
        # Generate QKD key for file encryption
        protocol = BB84Protocol(256)
        key_result = protocol.generate_key()
        
        if not key_result['success']:
            os.remove(temp_path)
            flash('Failed to generate quantum key.', 'danger')
            return redirect(url_for('upload_file'))
        
        key_id = str(uuid.uuid4())
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Store quantum key
        cursor.execute('''
            INSERT INTO quantum_keys 
            (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
             key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'file')
        ''', (
            key_id,
            key_result['alice_bits'],
            key_result['alice_bases'],
            key_result['bob_bases'],
            key_result['sifted_key'],
            key_result['final_key'],
            key_result['key_hash'],
            key_result['error_rate'],
            session['user_id'],
            datetime.now().isoformat(),
            (datetime.now() + timedelta(days=30)).isoformat()
        ))
        
        qk_row_id = cursor.lastrowid
        
        # Encrypt file
        file_service = FileEncryptionService(
            Config.UPLOAD_FOLDER,
            Config.ENCRYPTED_FOLDER,
            Config.QR_FOLDER
        )
        
        encryption_result = file_service.encrypt_uploaded_file(
            temp_path, 
            key_result['final_key'],
            file_id
        )
        
        # Remove temp file
        os.remove(temp_path)
        
        # Store file record
        cursor.execute('''
            INSERT INTO files (file_id, original_filename, encrypted_filename, file_path,
                             file_size, file_type, keywords, description, quantum_key_id,
                             encryption_key, qr_code_path, uploaded_by, uploaded_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            file_id,
            filename,
            encryption_result['encrypted_name'],
            encryption_result['encrypted_path'],
            os.path.getsize(encryption_result['encrypted_path']),
            filename.rsplit('.', 1)[-1] if '.' in filename else 'unknown',
            keywords,
            description,
            qk_row_id,
            key_result['final_key'],
            encryption_result['qr_code_path'],
            session['user_id'],
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        # Check if AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json or request.accept_mimetypes.accept_json:
            return jsonify({
                'success': True,
                'file_id': file_id,
                'key_hash': key_result['key_hash'],
                'qr_code_path': f"qr_codes/{file_id}_qr.png",
                'message': 'File uploaded and encrypted successfully!'
            })
        
        flash('File uploaded and encrypted successfully!', 'success')
        return redirect(url_for('view_file', file_id=file_id))
    
    # Get available keys for dropdown
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT key_id, key_hash, key_type FROM quantum_keys 
        WHERE created_by = ? AND is_active = 1 
        ORDER BY created_at DESC LIMIT 10
    ''', (session['user_id'],))
    available_keys = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('files/upload_file.html', available_keys=available_keys)

@app.route('/files/scan-qr')
@login_required
def scan_qr_code():
    """QR Code Scanner page"""
    return render_template('files/qr_scanner.html')

@app.route('/files/<file_id>')
@login_required
def view_file(file_id):
    """View file details with QR code"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.*, qk.key_hash, qk.error_rate, qk.expires_at as key_expires,
               u.username as owner_name
        FROM files f
        JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        JOIN users u ON f.uploaded_by = u.id
        WHERE f.file_id = ?
    ''', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        flash('File not found.', 'danger')
        conn.close()
        return redirect(url_for('files_list'))
    
    # Convert to dict and ensure error_rate is float
    file_dict = dict(file_data)
    try:
        file_dict['error_rate'] = float(file_dict.get('error_rate', 0) or 0)
    except (ValueError, TypeError):
        file_dict['error_rate'] = 0.0
    
    if not file_dict:
        flash('File not found.', 'danger')
        conn.close()
        return redirect(url_for('files_list'))
    
    # Get QR code relative path - extract just the filename
    qr_path = file_dict['qr_code_path']
    if qr_path:
        # Extract just the filename from the path
        qr_filename = os.path.basename(qr_path)
        qr_relative = f"qr_codes/{qr_filename}"
    else:
        qr_relative = None
    
    conn.close()
    
    is_owner = file_dict['uploaded_by'] == session['user_id']
    
    return render_template('files/view_file.html', 
                          file=file_dict,
                          qr_path=qr_relative,
                          is_owner=is_owner)


@app.route('/files/download/<file_id>')
@login_required
def download_file(file_id):
    """Download a file (encrypted or decrypted based on access)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.*, u.username as owner_name
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        WHERE f.file_id = ?
    ''', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        flash('File not found.', 'danger')
        return redirect(url_for('files_list'))
    
    # Check access - owner or approved request
    is_owner = file_data['uploaded_by'] == session['user_id']
    
    if not is_owner:
        cursor.execute('''
            SELECT * FROM file_requests 
            WHERE file_id = ? AND requester_id = ? AND status = 'approved'
        ''', (file_data['id'], session['user_id']))
        access = cursor.fetchone()
        
        if not access:
            flash('You do not have permission to download this file.', 'danger')
            conn.close()
            return redirect(url_for('files_list'))
    
    conn.close()
    
    # Get file path
    file_path = file_data['file_path']
    
    if file_path and os.path.exists(file_path):
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_data['encrypted_filename'] or file_data['original_filename']
        )
    else:
        flash('File not found on server.', 'danger')
        return redirect(url_for('view_file', file_id=file_id))


@app.route('/files/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file (owner only)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        flash('File not found.', 'danger')
        return redirect(url_for('files_list'))
    
    # Check ownership
    if file_data['uploaded_by'] != session['user_id']:
        flash('You do not have permission to delete this file.', 'danger')
        return redirect(url_for('files_list'))
    
    try:
        # Delete physical files
        if file_data['file_path'] and os.path.exists(file_data['file_path']):
            os.remove(file_data['file_path'])
        
        if file_data['qr_code_path'] and os.path.exists(file_data['qr_code_path']):
            os.remove(file_data['qr_code_path'])
        
        # Delete related requests
        cursor.execute('DELETE FROM file_requests WHERE file_id = ?', (file_data['id'],))
        
        # Delete file record
        cursor.execute('DELETE FROM files WHERE id = ?', (file_data['id'],))
        
        conn.commit()
        flash('File deleted successfully.', 'success')
        
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')
    
    conn.close()
    return redirect(url_for('files_list'))


@app.route('/api/files/<file_id>', methods=['DELETE'])
@login_required
def api_delete_file(file_id):
    """API endpoint to delete a file (owner only)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM files WHERE file_id = ?', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        conn.close()
        return jsonify({'success': False, 'error': 'File not found'})
    
    # Check ownership
    if file_data['uploaded_by'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'You do not have permission to delete this file'})
    
    try:
        # Delete physical files
        if file_data['file_path'] and os.path.exists(file_data['file_path']):
            os.remove(file_data['file_path'])
        
        if file_data['qr_code_path'] and os.path.exists(file_data['qr_code_path']):
            os.remove(file_data['qr_code_path'])
        
        # Delete related requests
        cursor.execute('DELETE FROM file_requests WHERE file_id = ?', (file_data['id'],))
        
        # Delete file record
        cursor.execute('DELETE FROM files WHERE id = ?', (file_data['id'],))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/files/request/<file_id>', methods=['POST'])
@login_required
def request_file_access(file_id):
    """Request access to a file"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.*, u.email as owner_email, u.username as owner_name 
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        WHERE f.file_id = ?
    ''', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        flash('File not found.', 'danger')
        return redirect(url_for('files_list'))
    
    if file_data['uploaded_by'] == session['user_id']:
        flash('You already own this file.', 'info')
        return redirect(url_for('view_file', file_id=file_id))
    
    # Check for existing pending request
    cursor.execute('''
        SELECT * FROM file_requests 
        WHERE file_id = ? AND requester_id = ? AND status = 'pending'
    ''', (file_data['id'], session['user_id']))
    
    if cursor.fetchone():
        flash('You already have a pending request for this file.', 'info')
        return redirect(url_for('files_list'))
    
    request_id = str(uuid.uuid4())
    approval_token = str(uuid.uuid4())  # Token for email approval
    
    # Get requester info
    cursor.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],))
    requester = cursor.fetchone()
    
    cursor.execute('''
        INSERT INTO file_requests (request_id, file_id, requester_id, owner_id, 
                                  status, requested_at, approval_token)
        VALUES (?, ?, ?, ?, 'pending', ?, ?)
    ''', (request_id, file_data['id'], session['user_id'], file_data['uploaded_by'],
          datetime.now().isoformat(), approval_token))
    
    conn.commit()
    conn.close()
    
    # Notify file owner about the access request
    create_notification(
        file_data['uploaded_by'],
        'file_request',
        'File Access Request',
        f'{requester["username"]} requested access to "{file_data["original_filename"]}"',
        url_for('files_list')
    )
    
    # Send notification email to file owner with approval/reject links
    try:
        email_service = create_email_service()
        approve_url = url_for('approve_via_email', token=approval_token, _external=True)
        
        subject = f"🔐 File Access Request - {file_data['original_filename']}"
        
        body = f"""
Dear {file_data['owner_name']},

{requester['username']} ({requester['email']}) has requested access to your file:

📁 File: {file_data['original_filename']}
👤 Requester: {requester['username']}
📧 Email: {requester['email']}
⏰ Requested at: {datetime.now().strftime('%Y-%m-%d %H:%M')}

Click the link below to approve this request:
{approve_url}

Or log in to your account to approve/reject from the portal.

Best regards,
Quantum IoT Security System
"""
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .info-box {{ background: #f8f9fa; border: 2px solid #667eea; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .info-item {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }}
        .info-item:last-child {{ border-bottom: none; }}
        .approve-btn {{ display: inline-block; background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 15px 30px; border-radius: 8px; text-decoration: none; font-weight: bold; margin: 10px 5px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 File Access Request</h1>
        </div>
        <div class="content">
            <p>Dear {file_data['owner_name']},</p>
            <p><strong>{requester['username']}</strong> has requested access to your file.</p>
            
            <div class="info-box">
                <div class="info-item">
                    <span>📁 File:</span>
                    <span><strong>{file_data['original_filename']}</strong></span>
                </div>
                <div class="info-item">
                    <span>👤 Requester:</span>
                    <span>{requester['username']}</span>
                </div>
                <div class="info-item">
                    <span>📧 Email:</span>
                    <span>{requester['email']}</span>
                </div>
                <div class="info-item">
                    <span>⏰ Requested:</span>
                    <span>{datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                </div>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{approve_url}" class="approve-btn">✅ Approve Request</a>
            </div>
            
            <p style="color: #666; font-size: 14px;">
                You can also log in to your account to manage this request from the portal.
            </p>
        </div>
        <div class="footer">
            <p>Quantum IoT Security System</p>
        </div>
    </div>
</body>
</html>
"""
        
        email_service.send_email(file_data['owner_email'], subject, body, html_body)
    except Exception as e:
        print(f"Failed to send notification email: {e}")
    
    flash('Access request sent! The file owner will be notified via email.', 'success')
    return redirect(url_for('files_list'))

@app.route('/files/approve/<request_id>')
@login_required
def approve_file_request(request_id):
    """Approve file access request and send key via email"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT fr.*, f.original_filename, f.encryption_key, f.file_id,
               u.email as requester_email, u.username as requester_name,
               qk.final_key, qk.key_hash, qk.error_rate, qk.expires_at
        FROM file_requests fr
        JOIN files f ON fr.file_id = f.id
        JOIN users u ON fr.requester_id = u.id
        JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE fr.request_id = ?
    ''', (request_id,))
    request_data = cursor.fetchone()
    
    if not request_data:
        flash('Request not found.', 'danger')
        return redirect(url_for('files_list'))
    
    if request_data['owner_id'] != session['user_id']:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('files_list'))
    
    # Generate access key
    access_key = str(uuid.uuid4())[:8]
    
    # Update request
    cursor.execute('''
        UPDATE file_requests 
        SET status = 'approved', quantum_key_sent = 1, key_sent_at = ?, 
            responded_at = ?, access_key = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), datetime.now().isoformat(), access_key, request_id))
    
    conn.commit()
    conn.close()
    
    # Send email with quantum key
    try:
        email_service = create_email_service()
        key_data = {
            'key_id': request_data['file_id'],
            'final_key': request_data['final_key'],
            'key_hash': request_data['key_hash'],
            'error_rate': request_data['error_rate'],
            'expires_at': request_data['expires_at']
        }
        file_info = {
            'file_id': request_data['file_id'],
            'filename': request_data['original_filename']
        }
        
        result = email_service.send_quantum_key(
            request_data['requester_email'],
            key_data,
            file_info
        )
        
        if result['success']:
            flash('Request approved and quantum key sent via email!', 'success')
        else:
            flash(f'Request approved but email failed: {result.get("error", "Unknown error")}', 'warning')
    except Exception as e:
        flash(f'Request approved but email failed: {str(e)}', 'warning')
    
    # Notify requester about approval
    create_notification(
        request_data['requester_id'],
        'file_approved',
        'File Access Approved',
        f'Your request to access "{request_data["original_filename"]}" was approved! Check your email for the key.',
        url_for('decrypt_file')
    )
    
    return redirect(url_for('files_list'))

@app.route('/files/reject/<request_id>')
@login_required
def reject_file_request(request_id):
    """Reject file access request"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM file_requests WHERE request_id = ?', (request_id,))
    request_data = cursor.fetchone()
    
    if not request_data or request_data['owner_id'] != session['user_id']:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('files_list'))
    
    cursor.execute('''
        UPDATE file_requests SET status = 'rejected', responded_at = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), request_id))
    
    conn.commit()
    conn.close()
    
    # Notify requester about rejection
    if request_data:
        create_notification(
            request_data['requester_id'],
            'file_rejected',
            'File Access Rejected',
            'Your file access request was rejected.',
            url_for('files_list')
        )
    
    flash('Request rejected.', 'info')
    return redirect(url_for('files_list'))


# ============= API ENDPOINTS FOR FILE REQUESTS =============

@app.route('/api/file-requests/<request_id>/approve', methods=['POST'])
@login_required
def api_approve_file_request(request_id):
    """API endpoint to approve file access request and send key via email"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT fr.*, f.original_filename, f.encryption_key, f.file_id as file_uuid,
               u.email as requester_email, u.username as requester_name,
               qk.final_key, qk.key_hash, qk.error_rate, qk.expires_at,
               owner.email as owner_email
        FROM file_requests fr
        JOIN files f ON fr.file_id = f.id
        JOIN users u ON fr.requester_id = u.id
        JOIN users owner ON fr.owner_id = owner.id
        LEFT JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE fr.request_id = ?
    ''', (request_id,))
    request_data = cursor.fetchone()
    
    if not request_data:
        conn.close()
        return jsonify({'success': False, 'error': 'Request not found'})
    
    if request_data['owner_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized action'})
    
    if request_data['status'] != 'pending':
        conn.close()
        return jsonify({'success': False, 'error': f'Request already {request_data["status"]}'})
    
    # Generate access key
    access_key = str(uuid.uuid4())[:8]
    
    # Update request status
    cursor.execute('''
        UPDATE file_requests 
        SET status = 'approved', quantum_key_sent = 1, key_sent_at = ?, 
            responded_at = ?, access_key = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), datetime.now().isoformat(), access_key, request_id))
    
    conn.commit()
    conn.close()
    
    # Send email with quantum key
    email_sent = False
    email_error = None
    try:
        email_service = create_email_service()
        key_data = {
            'key_id': request_data['file_uuid'],
            'final_key': request_data['final_key'] or 'Key not available',
            'key_hash': request_data['key_hash'] or 'N/A',
            'error_rate': request_data['error_rate'] or 0,
            'expires_at': request_data['expires_at'] or 'No expiration'
        }
        file_info = {
            'file_id': request_data['file_uuid'],
            'filename': request_data['original_filename']
        }
        
        result = email_service.send_quantum_key(
            request_data['requester_email'],
            key_data,
            file_info
        )
        
        email_sent = result['success']
        if not result['success']:
            email_error = result.get('error', 'Unknown error')
    except Exception as e:
        email_error = str(e)
    
    response = {
        'success': True,
        'message': 'Request approved',
        'email_sent': email_sent,
        'requester_email': request_data['requester_email']
    }
    
    if email_error:
        response['email_error'] = email_error
        response['message'] = f'Request approved but email failed: {email_error}'
    
    # Notify requester about approval
    create_notification(
        request_data['requester_id'],
        'file_approved',
        'File Access Approved',
        f'Your request to access "{request_data["original_filename"]}" was approved!',
        url_for('decrypt_file')
    )
    
    return jsonify(response)


@app.route('/api/file-requests/<request_id>/reject', methods=['POST'])
@login_required
def api_reject_file_request(request_id):
    """API endpoint to reject file access request"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT fr.*, u.email as requester_email, u.username as requester_name
        FROM file_requests fr
        JOIN users u ON fr.requester_id = u.id
        WHERE fr.request_id = ?
    ''', (request_id,))
    request_data = cursor.fetchone()
    
    if not request_data:
        conn.close()
        return jsonify({'success': False, 'error': 'Request not found'})
    
    if request_data['owner_id'] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized action'})
    
    if request_data['status'] != 'pending':
        conn.close()
        return jsonify({'success': False, 'error': f'Request already {request_data["status"]}'})
    
    cursor.execute('''
        UPDATE file_requests SET status = 'rejected', responded_at = ?
        WHERE request_id = ?
    ''', (datetime.now().isoformat(), request_id))
    
    conn.commit()
    conn.close()
    
    # Notify requester about rejection
    create_notification(
        request_data['requester_id'],
        'file_rejected',
        'File Access Rejected',
        f'Your request to access a file was rejected.',
        url_for('files_list')
    )
    
    return jsonify({'success': True, 'message': 'Request rejected'})


@app.route('/files/approve-via-email/<token>')
def approve_via_email(token):
    """Approve file access request via email link (no login required)"""
    import hashlib
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Find request by approval token
    cursor.execute('''
        SELECT fr.*, f.original_filename, f.file_id as file_uuid,
               u.email as requester_email, u.username as requester_name,
               qk.final_key, qk.key_hash, qk.error_rate, qk.expires_at,
               owner.username as owner_name
        FROM file_requests fr
        JOIN files f ON fr.file_id = f.id
        JOIN users u ON fr.requester_id = u.id
        JOIN users owner ON fr.owner_id = owner.id
        LEFT JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE fr.approval_token = ?
    ''', (token,))
    request_data = cursor.fetchone()
    
    if not request_data:
        conn.close()
        return render_template('error.html', 
            title='Invalid Link', 
            message='This approval link is invalid or has expired.')
    
    if request_data['status'] != 'pending':
        conn.close()
        return render_template('error.html', 
            title='Already Processed', 
            message=f'This request has already been {request_data["status"]}.')
    
    # Approve the request
    access_key = str(uuid.uuid4())[:8]
    cursor.execute('''
        UPDATE file_requests 
        SET status = 'approved', quantum_key_sent = 1, key_sent_at = ?, 
            responded_at = ?, access_key = ?
        WHERE approval_token = ?
    ''', (datetime.now().isoformat(), datetime.now().isoformat(), access_key, token))
    
    conn.commit()
    conn.close()
    
    # Send email with quantum key
    try:
        email_service = create_email_service()
        key_data = {
            'key_id': request_data['file_uuid'],
            'final_key': request_data['final_key'] or 'Key not available',
            'key_hash': request_data['key_hash'] or 'N/A',
            'error_rate': request_data['error_rate'] or 0,
            'expires_at': request_data['expires_at'] or 'No expiration'
        }
        file_info = {
            'file_id': request_data['file_uuid'],
            'filename': request_data['original_filename']
        }
        
        email_service.send_quantum_key(
            request_data['requester_email'],
            key_data,
            file_info
        )
    except Exception as e:
        print(f"Email error: {e}")
    
    return render_template('email_approval_success.html',
        requester_name=request_data['requester_name'],
        filename=request_data['original_filename'])


@app.route('/files/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    """Decrypt a file with quantum key - supports both file upload and file_id entry"""
    if request.method == 'POST':
        # Check if user provided file_id or uploaded file
        file_id = request.form.get('file_id', '').strip()
        quantum_key = request.form.get('quantum_key', '').strip() or request.form.get('decryption_key', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        
        if file_id and quantum_key:
            # Method 1: Decrypt by file_id and quantum key (from email)
            cursor.execute('''
                SELECT f.*, qk.final_key, qk.key_hash
                FROM files f
                JOIN quantum_keys qk ON f.quantum_key_id = qk.id
                WHERE f.file_id = ? AND f.is_active = 1
            ''', (file_id,))
            file_data = cursor.fetchone()
            
            if not file_data:
                flash('File not found or has been deleted.', 'danger')
                conn.close()
                return redirect(url_for('decrypt_file'))
            
            # Verify key (timing-safe comparison)
            provided_hash = hashlib.sha256(quantum_key.encode()).hexdigest()[:16]
            
            if not _hmac.compare_digest(provided_hash, file_data['key_hash']):
                flash('Invalid quantum key. Access denied.', 'danger')
                conn.close()
                return redirect(url_for('decrypt_file'))
            
            # Check if user has permission (owner or approved request)
            if file_data['uploaded_by'] != session['user_id']:
                cursor.execute('''
                    SELECT * FROM file_requests 
                    WHERE file_id = (SELECT id FROM files WHERE file_id = ?) 
                    AND requester_id = ? AND status = 'approved'
                ''', (file_id, session['user_id']))
                access_request = cursor.fetchone()
                
                if not access_request:
                    flash('You do not have permission to decrypt this file.', 'danger')
                    conn.close()
                    return redirect(url_for('decrypt_file'))
            
            # Decrypt and serve file
            try:
                encryptor = QKDEncryption(file_data['final_key'])
                
                # Read encrypted file
                with open(file_data['file_path'], 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = encryptor.decrypt_data(encrypted_data)
                
                # Update download count
                cursor.execute('UPDATE files SET download_count = download_count + 1 WHERE file_id = ?',
                              (file_id,))
                conn.commit()
                conn.close()
                
                # Return decrypted file
                from io import BytesIO
                return send_file(
                    BytesIO(decrypted_data),
                    download_name=file_data['original_filename'],
                    as_attachment=True
                )
            except Exception as e:
                conn.close()
                flash(f'Decryption failed: {str(e)}', 'danger')
                return redirect(url_for('decrypt_file'))
        
        elif 'encrypted_file' in request.files:
            # Method 2: Upload encrypted file and provide key (legacy method)
            file = request.files['encrypted_file']
            if file.filename == '':
                flash('No file selected.', 'danger')
                conn.close()
                return redirect(url_for('decrypt_file'))
            
            if not quantum_key:
                flash('Quantum key is required.', 'danger')
                conn.close()
                return redirect(url_for('decrypt_file'))
            
            # Save uploaded file temporarily
            temp_path = os.path.join(Config.UPLOAD_FOLDER, f"temp_decrypt_{uuid.uuid4()}_{file.filename}")
            file.save(temp_path)
            
            try:
                encryptor = QKDEncryption(quantum_key)
                
                with open(temp_path, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = encryptor.decrypt_data(encrypted_data)
                
                os.remove(temp_path)
                conn.close()
                
                from io import BytesIO
                return send_file(
                    BytesIO(decrypted_data),
                    download_name=file.filename.replace('_encrypted', '').replace('.qkd_encrypted', ''),
                    as_attachment=True
                )
            except Exception as e:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                conn.close()
                flash(f'Decryption failed: {str(e)}', 'danger')
                return redirect(url_for('decrypt_file'))
        else:
            conn.close()
            flash('Please provide either File ID + Quantum Key, or upload an encrypted file.', 'warning')
            return redirect(url_for('decrypt_file'))
    
    return render_template('files/decrypt_file.html')

@app.route('/files/browse')
@login_required
def browse_files():
    """Browse all available files"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT f.*, u.username as owner_name, qk.key_hash
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE f.is_active = 1
        ORDER BY f.uploaded_at DESC
    ''')
    files = cursor.fetchall()
    
    conn.close()
    
    return render_template('files/browse_files.html', files=files)

# ============================================
# AI Assistant
# ============================================

@app.route('/ai-assistant')
@login_required
def ai_assistant_page():
    """AI Assistant page"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recent AI logs
    cursor.execute('''
        SELECT * FROM ai_assistant_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT 20
    ''', (session['user_id'],))
    logs = cursor.fetchall()
    
    # Get user's active keys for analysis
    cursor.execute('''
        SELECT * FROM quantum_keys 
        WHERE created_by = ? AND is_active = 1
        ORDER BY created_at DESC
    ''', (session['user_id'],))
    active_keys = cursor.fetchall()
    
    conn.close()
    
    return render_template('ai/ai_assistant.html', logs=logs, active_keys=active_keys)

@app.route('/api/ai/analyze-key/<key_id>')
@login_required
def api_analyze_key(key_id):
    """Analyze a quantum key's health"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM quantum_keys WHERE key_id = ?', (key_id,))
    key_data = cursor.fetchone()
    
    if not key_data:
        return jsonify({'success': False, 'error': 'Key not found'})
    
    # Convert to dict and add age
    key_dict = dict(key_data)
    created = datetime.fromisoformat(key_dict['created_at'])
    key_dict['age_minutes'] = (datetime.now() - created).total_seconds() / 60
    
    # Get AI analysis
    analysis = ai_assistant.analyze_key_health(key_dict)
    
    # Log the analysis
    cursor.execute('''
        INSERT INTO ai_assistant_logs (user_id, query, response, action_taken, 
                                       recommendation_type, created_at)
        VALUES (?, ?, ?, ?, 'key_analysis', ?)
    ''', (session['user_id'], f'Analyze key {key_id}', json.dumps(analysis),
          'Provided health analysis', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'analysis': analysis})

@app.route('/api/ai/recommendation', methods=['POST'])
@login_required
def api_ai_recommendation():
    """Get AI recommendation for key rotation"""
    data = request.get_json()
    
    conn = get_db()
    cursor = conn.cursor()
    
    key_id = data.get('key_id')
    channel_id = data.get('channel_id')
    
    # Get key data
    cursor.execute('SELECT * FROM quantum_keys WHERE key_id = ?', (key_id,))
    key_data = cursor.fetchone()
    
    if not key_data:
        return jsonify({'success': False, 'error': 'Key not found'})
    
    key_dict = dict(key_data)
    created = datetime.fromisoformat(key_dict['created_at'])
    key_dict['age_minutes'] = (datetime.now() - created).total_seconds() / 60
    
    # Get channel data if provided
    channel_dict = {}
    if channel_id:
        cursor.execute('SELECT * FROM channels WHERE channel_id = ?', (channel_id,))
        channel = cursor.fetchone()
        if channel:
            channel_dict = dict(channel)
            cursor.execute('SELECT COUNT(*) FROM channel_members WHERE channel_id = ?', 
                          (channel['id'],))
            channel_dict['member_count'] = cursor.fetchone()[0]
    
    # Get AI recommendation
    recommendation = ai_assistant.get_rotation_recommendation(channel_dict, key_dict)
    
    # Log
    cursor.execute('''
        INSERT INTO ai_assistant_logs (user_id, query, response, action_taken, 
                                       recommendation_type, created_at)
        VALUES (?, ?, ?, ?, 'rotation_recommendation', ?)
    ''', (session['user_id'], f'Get rotation recommendation for key {key_id}',
          json.dumps(recommendation), 'Provided recommendation', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'recommendation': recommendation})

@app.route('/api/ai/health-status')
@login_required
def api_ai_health_status():
    """Get AI assistant health status with comprehensive metrics"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's key statistics
    cursor.execute('''
        SELECT COUNT(*) as total_keys,
               SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_keys,
               AVG(error_rate) as avg_error_rate,
               MIN(created_at) as oldest_key,
               MAX(created_at) as newest_key
        FROM quantum_keys WHERE created_by = ?
    ''', (session['user_id'],))
    key_stats = cursor.fetchone()
    
    # Get last rotation time
    cursor.execute('''
        SELECT last_refresh FROM key_refresh_schedule 
        WHERE quantum_key_id IN (SELECT id FROM quantum_keys WHERE created_by = ?)
        ORDER BY last_refresh DESC LIMIT 1
    ''', (session['user_id'],))
    last_rotation_row = cursor.fetchone()
    
    # Get channel activity
    cursor.execute('''
        SELECT COUNT(*) as channel_count FROM channels WHERE created_by = ?
    ''', (session['user_id'],))
    channel_stats = cursor.fetchone()
    
    conn.close()
    
    # Calculate health score
    health_score = 100
    warnings = []
    
    # Check error rate
    avg_error = key_stats['avg_error_rate'] or 0
    if avg_error > 0.11:
        health_score -= 40
        warnings.append('Critical: Error rate too high!')
    elif avg_error > 0.05:
        health_score -= 20
        warnings.append('Warning: Elevated error rate')
    
    # Check key age
    key_age_status = 'good'
    avg_key_age = 'N/A'
    if key_stats['newest_key']:
        try:
            newest = datetime.fromisoformat(key_stats['newest_key'].replace('T', ' ').split('.')[0])
            age_minutes = (datetime.now() - newest).total_seconds() / 60
            avg_key_age = f"{int(age_minutes)} min"
            if age_minutes > 60:
                health_score -= 15
                key_age_status = 'warning'
                warnings.append('Keys are getting old')
            elif age_minutes > 30:
                health_score -= 5
                key_age_status = 'caution'
        except:
            pass
    
    # Format last rotation
    last_rotation = 'Never'
    if last_rotation_row and last_rotation_row['last_refresh']:
        try:
            last_rot_time = datetime.fromisoformat(last_rotation_row['last_refresh'].replace('T', ' ').split('.')[0])
            minutes_ago = (datetime.now() - last_rot_time).total_seconds() / 60
            if minutes_ago < 60:
                last_rotation = f"{int(minutes_ago)} min ago"
            else:
                hours_ago = minutes_ago / 60
                last_rotation = f"{int(hours_ago)} hours ago"
        except:
            pass
    
    # Determine error rate status
    error_rate_status = 'good'
    error_rate_display = 'N/A'
    if avg_error is not None:
        error_rate_display = f"{avg_error*100:.2f}%"
        if avg_error > 0.11:
            error_rate_status = 'critical'
        elif avg_error > 0.05:
            error_rate_status = 'warning'
    
    health_score = max(0, min(100, health_score))
    
    status = {
        'success': True,
        'health': {
            'score': health_score,
            'status': 'healthy' if health_score >= 80 else ('warning' if health_score >= 50 else 'critical'),
            'avg_key_age': avg_key_age,
            'key_age_status': key_age_status,
            'avg_error_rate': error_rate_display,
            'error_rate_status': error_rate_status,
            'active_keys': key_stats['active_keys'] or 0,
            'total_keys': key_stats['total_keys'] or 0,
            'last_rotation': last_rotation,
            'channels': channel_stats['channel_count'] or 0,
            'warnings': warnings
        },
        'ai_status': 'operational' if ai_assistant.client else 'fallback',
        'endpoint': ai_assistant.azure_endpoint[:50] + '...' if ai_assistant.azure_endpoint else 'Not configured',
        'model': ai_assistant.deployment
    }
    return jsonify(status)

@app.route('/api/ai/recommendations')
@login_required
def api_ai_recommendations():
    """Get general AI recommendations"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's key statistics
    cursor.execute('''
        SELECT COUNT(*) as total, 
               SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active,
               AVG(error_rate) as avg_error
        FROM quantum_keys WHERE created_by = ?
    ''', (session['user_id'],))
    stats = cursor.fetchone()
    
    conn.close()
    
    recommendations = {
        'success': True,
        'recommendations': [
            {
                'type': 'key_health',
                'priority': 'medium',
                'message': f'You have {stats["active"]} active keys with an average error rate of {stats["avg_error"]:.2%}' if stats['avg_error'] else 'Generate more keys to see statistics'
            },
            {
                'type': 'security',
                'priority': 'high',
                'message': 'Rotate keys every 5 minutes for high-security channels'
            },
            {
                'type': 'best_practice',
                'priority': 'low',
                'message': 'Monitor error rates - values above 11% indicate potential security issues'
            }
        ]
    }
    return jsonify(recommendations)

@app.route('/api/ai/export-report')
@login_required
def api_ai_export_report():
    """Export AI assistant conversation history as report"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's AI assistant logs
    cursor.execute('''
        SELECT query, response, recommendation_type, created_at
        FROM ai_assistant_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC LIMIT 50
    ''', (session['user_id'],))
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Get summary statistics
    cursor.execute('''
        SELECT COUNT(*) as total_queries,
               COUNT(DISTINCT recommendation_type) as recommendation_types
        FROM ai_assistant_logs WHERE user_id = ?
    ''', (session['user_id'],))
    stats = dict(cursor.fetchone())
    
    conn.close()
    
    report = {
        'success': True,
        'report': {
            'generated_at': datetime.now().isoformat(),
            'statistics': stats,
            'conversation_history': logs[:10],  # Last 10 interactions
            'download_url': '#'  # Could generate PDF/CSV here
        }
    }
    return jsonify(report)

@app.route('/api/ai/chat', methods=['POST'])
@login_required
def api_ai_chat():
    """Chat with AI assistant"""
    data = request.get_json()
    query = data.get('question', '') or data.get('query', '')
    
    if not query:
        return jsonify({'success': False, 'error': 'Empty query'})
    
    # Get context (user's keys and channels)
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM quantum_keys WHERE created_by = ? AND is_active = 1',
                  (session['user_id'],))
    active_keys = cursor.fetchone()[0]
    
    context = {
        'user_id': session['user_id'],
        'active_keys_count': active_keys
    }
    
    try:
        # Get AI response
        response = ai_assistant.get_security_advice(query, context)
        
        # Log
        cursor.execute('''
            INSERT INTO ai_assistant_logs (user_id, query, response, recommendation_type, created_at)
            VALUES (?, ?, ?, 'chat', ?)
        ''', (session['user_id'], query, response, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'answer': response, 'response': response})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ai/analyze-all', methods=['POST'])
@login_required
def api_ai_analyze_all():
    """Analyze all quantum keys for the current user"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all active keys for this user
        cursor.execute('''
            SELECT * FROM quantum_keys 
            WHERE created_by = ? AND is_active = 1
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        keys = cursor.fetchall()
        
        if not keys:
            return jsonify({
                'success': True,
                'summary': 'No active keys found. Generate some quantum keys to get started!',
                'analyzed': 0,
                'recommendations': []
            })
        
        # Analyze each key
        analyses = []
        total_health = 0
        warnings = []
        critical_keys = []
        
        for key in keys:
            key_dict = dict(key)
            created = datetime.fromisoformat(key_dict['created_at'])
            key_dict['age_minutes'] = (datetime.now() - created).total_seconds() / 60
            
            analysis = ai_assistant.analyze_key_health(key_dict)
            analyses.append({
                'key_id': key_dict['key_id'],
                'health_score': analysis['health_score'],
                'status': analysis['status'],
                'recommendations': analysis['recommendations']
            })
            
            total_health += analysis['health_score']
            
            if analysis['health_score'] < 50:
                critical_keys.append(key_dict['key_id'][:8])
            
            if analysis.get('warnings'):
                warnings.extend(analysis['warnings'])
        
        avg_health = total_health / len(keys) if keys else 0
        
        # Generate summary
        summary_parts = [
            f"Analyzed {len(keys)} active key(s).",
            f"Average health score: {avg_health:.0f}/100."
        ]
        
        if critical_keys:
            summary_parts.append(f"⚠️ {len(critical_keys)} key(s) need immediate attention.")
        else:
            summary_parts.append("✅ All keys are in good health.")
        
        if warnings:
            summary_parts.append(f"Found {len(set(warnings))} warning(s) to address.")
        
        summary = " ".join(summary_parts)
        
        # Log the analysis
        cursor.execute('''
            INSERT INTO ai_assistant_logs (user_id, query, response, action_taken, 
                                           recommendation_type, created_at)
            VALUES (?, ?, ?, ?, 'batch_analysis', ?)
        ''', (session['user_id'], 'Analyze all keys', json.dumps({'summary': summary}),
              f'Analyzed {len(keys)} keys', datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'summary': summary,
            'analyzed': len(keys),
            'average_health': avg_health,
            'critical_count': len(critical_keys),
            'analyses': analyses,
            'recommendations': list(set(warnings))[:5]  # Top 5 unique warnings
        })
        
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/ai/rotate-all', methods=['POST'])
@login_required
def api_ai_rotate_all():
    """Rotate all quantum keys for the current user"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Get all active keys for this user
        cursor.execute('''
            SELECT * FROM quantum_keys 
            WHERE created_by = ? AND is_active = 1
        ''', (session['user_id'],))
        keys = cursor.fetchall()
        
        if not keys:
            return jsonify({
                'success': True,
                'message': 'No active keys to rotate.',
                'rotated': 0
            })
        
        rotated_count = 0
        errors = []
        
        for key in keys:
            try:
                # Mark old key as inactive
                cursor.execute('UPDATE quantum_keys SET is_active = 0 WHERE id = ?', (key['id'],))
                
                # Generate new key
                protocol = BB84Protocol(256)
                result = protocol.generate_key()
                
                if result['success']:
                    new_key_id = str(uuid.uuid4())
                    
                    # Insert new key
                    cursor.execute('''
                        INSERT INTO quantum_keys 
                        (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
                         key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    ''', (
                        new_key_id,
                        result['alice_bits'],
                        result['alice_bases'],
                        result['bob_bases'],
                        result['sifted_key'],
                        result['final_key'],
                        result['key_hash'],
                        result['error_rate'],
                        session['user_id'],
                        datetime.now().isoformat(),
                        (datetime.now() + timedelta(hours=1)).isoformat(),
                        key['key_type'] or 'session'
                    ))
                    
                    rotated_count += 1
                else:
                    errors.append(f"Failed to generate new key for {key['key_id'][:8]}")
                    
            except Exception as e:
                errors.append(f"Error rotating key {key['key_id'][:8]}: {str(e)}")
        
        # Log the rotation
        cursor.execute('''
            INSERT INTO ai_assistant_logs (user_id, query, response, action_taken, 
                                           recommendation_type, created_at)
            VALUES (?, ?, ?, ?, 'batch_rotation', ?)
        ''', (session['user_id'], 'Rotate all keys', 
              json.dumps({'rotated': rotated_count, 'errors': errors}),
              f'Rotated {rotated_count} keys', datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Successfully rotated {rotated_count} of {len(keys)} keys.',
            'rotated': rotated_count,
            'total': len(keys),
            'errors': errors if errors else None
        })
        
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/keys/schedule-rotation', methods=['POST'])
@login_required
def api_schedule_rotation():
    """Schedule automatic key rotation"""
    data = request.get_json() or {}
    
    interval_minutes = data.get('interval', 60)  # Default 60 minutes
    key_id = data.get('key_id')  # Optional specific key
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        if key_id:
            # Schedule for specific key
            cursor.execute('''
                SELECT * FROM quantum_keys 
                WHERE key_id = ? AND created_by = ? AND is_active = 1
            ''', (key_id, session['user_id']))
            key = cursor.fetchone()
            
            if not key:
                return jsonify({'success': False, 'error': 'Key not found'})
            
            # Check if schedule exists
            cursor.execute('SELECT * FROM key_refresh_schedule WHERE quantum_key_id = ?', (key['id'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing schedule
                cursor.execute('''
                    UPDATE key_refresh_schedule 
                    SET refresh_interval = ?, next_refresh = ?, is_active = 1
                    WHERE quantum_key_id = ?
                ''', (interval_minutes * 60, 
                      (datetime.now() + timedelta(minutes=interval_minutes)).isoformat(),
                      key['id']))
            else:
                # Create new schedule
                cursor.execute('''
                    INSERT INTO key_refresh_schedule 
                    (quantum_key_id, refresh_interval, next_refresh, is_active)
                    VALUES (?, ?, ?, 1)
                ''', (key['id'], interval_minutes * 60,
                      (datetime.now() + timedelta(minutes=interval_minutes)).isoformat()))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': f'Key rotation scheduled every {interval_minutes} minutes.',
                'next_rotation': (datetime.now() + timedelta(minutes=interval_minutes)).isoformat()
            })
        else:
            # Schedule for all active keys
            cursor.execute('''
                SELECT * FROM quantum_keys 
                WHERE created_by = ? AND is_active = 1
            ''', (session['user_id'],))
            keys = cursor.fetchall()
            
            scheduled_count = 0
            for key in keys:
                # Check if schedule exists
                cursor.execute('SELECT * FROM key_refresh_schedule WHERE quantum_key_id = ?', (key['id'],))
                existing = cursor.fetchone()
                
                if existing:
                    cursor.execute('''
                        UPDATE key_refresh_schedule 
                        SET refresh_interval = ?, next_refresh = ?, is_active = 1
                        WHERE quantum_key_id = ?
                    ''', (interval_minutes * 60,
                          (datetime.now() + timedelta(minutes=interval_minutes)).isoformat(),
                          key['id']))
                else:
                    cursor.execute('''
                        INSERT INTO key_refresh_schedule 
                        (quantum_key_id, refresh_interval, next_refresh, is_active)
                        VALUES (?, ?, ?, 1)
                    ''', (key['id'], interval_minutes * 60,
                          (datetime.now() + timedelta(minutes=interval_minutes)).isoformat()))
                scheduled_count += 1
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': f'Scheduled rotation for {scheduled_count} keys every {interval_minutes} minutes.',
                'scheduled': scheduled_count,
                'interval_minutes': interval_minutes
            })
            
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

# ============================================
# Key Refresh (Dynamic Key Rotation)
# ============================================

@app.route('/api/keys/refresh/<key_id>', methods=['POST'])
@login_required
def api_refresh_key(key_id):
    """Manually refresh a quantum key"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM quantum_keys WHERE key_id = ? AND created_by = ?',
                  (key_id, session['user_id']))
    old_key = cursor.fetchone()
    
    if not old_key:
        return jsonify({'success': False, 'error': 'Key not found'})
    
    # Generate new key
    protocol = BB84Protocol(256)
    result = protocol.generate_key()
    
    if not result['success']:
        return jsonify({'success': False, 'error': 'Failed to generate new key'})
    
    new_key_id = str(uuid.uuid4())
    
    # Mark old key as inactive
    cursor.execute('UPDATE quantum_keys SET is_active = 0 WHERE key_id = ?', (key_id,))
    
    # Insert new key
    cursor.execute('''
        INSERT INTO quantum_keys 
        (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
         key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    ''', (
        new_key_id,
        result['alice_bits'],
        result['alice_bases'],
        result['bob_bases'],
        result['sifted_key'],
        result['final_key'],
        result['key_hash'],
        result['error_rate'],
        session['user_id'],
        datetime.now().isoformat(),
        (datetime.now() + timedelta(hours=1)).isoformat(),
        old_key['key_type']
    ))
    
    # Update any channels using this key
    cursor.execute('''
        UPDATE channels SET quantum_key_id = ? WHERE quantum_key_id = ?
    ''', (cursor.lastrowid, old_key['id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'old_key_id': key_id,
        'new_key_id': new_key_id,
        'new_key': result['final_key'],
        'new_key_hash': result['key_hash']
    })

@app.route('/api/keys/send-email/<key_id>', methods=['POST'])
@login_required
def api_send_key_email(key_id):
    """Send quantum key via email"""
    data = request.get_json()
    recipient_email = data.get('email')
    
    if not recipient_email:
        return jsonify({'success': False, 'error': 'Email required'})
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM quantum_keys WHERE key_id = ? AND created_by = ?',
                  (key_id, session['user_id']))
    key_data = cursor.fetchone()
    
    if not key_data:
        return jsonify({'success': False, 'error': 'Key not found'})
    
    try:
        email_service = create_email_service()
        key_dict = {
            'key_id': key_data['key_id'],
            'final_key': key_data['final_key'],
            'key_hash': key_data['key_hash'],
            'error_rate': key_data['error_rate'],
            'expires_at': key_data['expires_at']
        }
        
        try:
            result = email_service.send_quantum_key(recipient_email, key_dict)
        except Exception as email_error:
            # Email sending failed (likely SMTP auth issues)
            result = {
                'success': False,
                'error': f'Email service unavailable. Please configure SMTP settings. Error: {str(email_error)}'
            }
        
        # Log email attempt
        cursor.execute('''
            INSERT INTO email_logs (recipient_email, subject, content_type, status, 
                                   sent_at, related_key_id)
            VALUES (?, 'Quantum Key', 'key_share', ?, ?, ?)
        ''', (recipient_email, 'sent' if result.get('success') else 'failed',
              datetime.now().isoformat(), key_data['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify(result)
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

# ============================================
# QR Code Scanning
# ============================================

@app.route('/file/access/<file_id>', methods=['GET', 'POST'])
def file_access_qr(file_id):
    """Handle QR code scan for file access - request access via email"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get file info
    cursor.execute('''
        SELECT f.*, u.username as owner_name, qk.key_hash
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        LEFT JOIN quantum_keys qk ON f.quantum_key_id = qk.id
        WHERE f.file_id = ?
    ''', (file_id,))
    file_data = cursor.fetchone()
    
    if not file_data:
        conn.close()
        return render_template('error.html', 
            title='File Not Found',
            message='The file you are trying to access does not exist.')
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return render_template('files/qr_access.html', file=file_data)
        
        # Check if user exists
        cursor.execute('SELECT id, username FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if not user:
            flash('No account found with this email. Please register first.', 'warning')
            conn.close()
            return render_template('files/qr_access.html', file=file_data, show_register=True)
        
        # Check if already owner
        if file_data['uploaded_by'] == user['id']:
            flash('You are the owner of this file. Please log in to access it.', 'info')
            conn.close()
            return redirect(url_for('login'))
        
        # Check existing request
        cursor.execute('''
            SELECT * FROM file_requests 
            WHERE file_id = ? AND requester_id = ?
        ''', (file_data['id'], user['id']))
        existing_request = cursor.fetchone()
        
        if existing_request:
            if existing_request['status'] == 'pending':
                flash('You already have a pending access request for this file.', 'info')
            elif existing_request['status'] == 'approved':
                # Send key to email
                try:
                    email_service = create_email_service()
                    cursor.execute('SELECT * FROM quantum_keys WHERE id = ?', (file_data['quantum_key_id'],))
                    qk = cursor.fetchone()
                    
                    key_data = {
                        'key_id': file_data['file_id'],
                        'final_key': qk['final_key'] if qk else 'N/A',
                        'key_hash': qk['key_hash'] if qk else 'N/A',
                        'error_rate': qk['error_rate'] if qk else 0,
                        'expires_at': qk['expires_at'] if qk else 'N/A'
                    }
                    file_info = {
                        'file_id': file_data['file_id'],
                        'filename': file_data['original_filename']
                    }
                    
                    result = email_service.send_quantum_key(email, key_data, file_info)
                    if result['success']:
                        flash('Your access was already approved! The decryption key has been sent to your email.', 'success')
                    else:
                        flash(f'Access approved but failed to send email: {result.get("error")}', 'warning')
                except Exception as e:
                    flash(f'Access approved but email failed: {str(e)}', 'warning')
            else:
                flash(f'Your previous request was {existing_request["status"]}. Contact the file owner.', 'info')
            conn.close()
            return render_template('files/qr_access.html', file=file_data)
        
        # Create new access request
        request_id = str(uuid.uuid4())
        approval_token = str(uuid.uuid4())
        
        cursor.execute('''
            INSERT INTO file_requests (request_id, file_id, requester_id, owner_id, 
                                      status, requested_at, approval_token)
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
        ''', (request_id, file_data['id'], user['id'], file_data['uploaded_by'],
              datetime.now().isoformat(), approval_token))
        
        conn.commit()
        
        # Send notification email to owner
        try:
            cursor.execute('SELECT email, username FROM users WHERE id = ?', (file_data['uploaded_by'],))
            owner = cursor.fetchone()
            
            email_service = create_email_service()
            approve_url = url_for('approve_via_email', token=approval_token, _external=True)
            
            subject = f"🔐 File Access Request - {file_data['original_filename']}"
            body = f"""
Dear {owner['username']},

{user['username']} ({email}) has requested access to your file via QR code scan.

📁 File: {file_data['original_filename']}
👤 Requester: {user['username']}
📧 Email: {email}

Click here to approve: {approve_url}

Quantum IoT Security System
"""
            html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .approve-btn {{ display: inline-block; background: #28a745; color: white; padding: 15px 30px; border-radius: 8px; text-decoration: none; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>🔐 File Access Request</h1></div>
        <div class="content">
            <p>Dear {owner['username']},</p>
            <p><strong>{user['username']}</strong> ({email}) has requested access to:</p>
            <p style="background: #f8f9fa; padding: 15px; border-radius: 8px;"><strong>{file_data['original_filename']}</strong></p>
            <p style="text-align: center;"><a href="{approve_url}" class="approve-btn">✅ Approve Request</a></p>
        </div>
    </div>
</body>
</html>
"""
            email_service.send_email(owner['email'], subject, body, html_body)
        except Exception as e:
            print(f"Failed to notify owner: {e}")
        
        flash('Access request sent! The file owner will be notified. Once approved, the decryption key will be sent to your email.', 'success')
        conn.close()
        return render_template('files/qr_access.html', file=file_data, request_sent=True)
    
    conn.close()
    return render_template('files/qr_access.html', file=file_data)


@app.route('/qr/<file_id>')
def serve_qr_code(file_id):
    """Serve QR code image"""
    qr_path = os.path.join(Config.QR_FOLDER, f"{file_id}_qr.png")
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/png')
    return "QR code not found", 404

# ============================================
# Notifications System
# ============================================

@app.route('/api/notifications')
@login_required
def api_get_notifications():
    """Get user notifications"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create notifications table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            link TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Get unread notifications
    cursor.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? AND is_read = 0 
        ORDER BY created_at DESC LIMIT 10
    ''', (session['user_id'],))
    notifications = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({'success': True, 'notifications': notifications, 'count': len(notifications)})

@app.route('/api/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark notification as read"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE notifications SET is_read = 1 
        WHERE id = ? AND user_id = ?
    ''', (notification_id, session['user_id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_notifications_read():
    """Mark all notifications as read"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE notifications SET is_read = 1 
        WHERE user_id = ?
    ''', (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ============================================
# Error Handlers
# ============================================

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error('Server error: %s', e)
    return render_template('errors/500.html'), 500

# ============================================
# Background Key Rotation Thread
# ============================================

def key_rotation_worker():
    """Background worker for automatic key rotation"""
    while True:
        try:
            time.sleep(60)  # Check every minute
            
            conn = get_db()
            cursor = conn.cursor()
            
            # Find keys due for rotation
            cursor.execute('''
                SELECT krs.*, qk.key_id, qk.created_by
                FROM key_refresh_schedule krs
                JOIN quantum_keys qk ON krs.quantum_key_id = qk.id
                WHERE krs.is_active = 1 AND krs.next_refresh <= ?
            ''', (datetime.now().isoformat(),))
            
            due_keys = cursor.fetchall()
            
            for key_schedule in due_keys:
                # Generate new key
                protocol = BB84Protocol(256)
                result = protocol.generate_key()
                
                if result['success']:
                    new_key_id = str(uuid.uuid4())
                    
                    # Mark old as inactive
                    cursor.execute('UPDATE quantum_keys SET is_active = 0 WHERE key_id = ?',
                                  (key_schedule['key_id'],))
                    
                    # Insert new key
                    cursor.execute('''
                        INSERT INTO quantum_keys 
                        (key_id, alice_bits, alice_bases, bob_bases, sifted_key, final_key, 
                         key_hash, error_rate, created_by, created_at, expires_at, is_active, key_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'session')
                    ''', (
                        new_key_id,
                        result['alice_bits'],
                        result['alice_bases'],
                        result['bob_bases'],
                        result['sifted_key'],
                        result['final_key'],
                        result['key_hash'],
                        result['error_rate'],
                        key_schedule['created_by'],
                        datetime.now().isoformat(),
                        (datetime.now() + timedelta(hours=1)).isoformat()
                    ))
                    
                    # Update schedule
                    cursor.execute('''
                        UPDATE key_refresh_schedule 
                        SET last_refresh = ?, next_refresh = ?, refresh_count = refresh_count + 1
                        WHERE id = ?
                    ''', (datetime.now().isoformat(),
                          (datetime.now() + timedelta(seconds=key_schedule['refresh_interval'])).isoformat(),
                          key_schedule['id']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Key rotation error: {e}")

# Start background thread (only in production)
# rotation_thread = threading.Thread(target=key_rotation_worker, daemon=True)
# rotation_thread.start()

# ============================================
# IoT Device Management
# ============================================

def _api_key_auth():
    """Authenticate request by X-API-Key header. Returns device row or None."""
    api_key = request.headers.get('X-API-Key', '')
    if not api_key:
        return None
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM iot_devices WHERE api_key_hash = ? AND is_active = 1',
        (key_hash,)
    )
    device = cursor.fetchone()
    conn.close()
    return device


@app.route('/iot/devices')
@login_required
def iot_device_dashboard():
    """IoT device management dashboard."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM iot_devices WHERE owner_id = ? ORDER BY registered_at DESC',
        (session['user_id'],)
    )
    devices = [dict(d) for d in cursor.fetchall()]

    # For each device, fetch the latest telemetry reading
    latest = {}
    for d in devices:
        cursor.execute(
            'SELECT * FROM iot_telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1',
            (d['id'],)
        )
        row = cursor.fetchone()
        latest[d['id']] = row

    conn.close()

    # Pop one-time API key from session (set after registration)
    new_api_key = session.pop('iot_new_key', None)
    new_device_name = session.pop('iot_new_device_name', None)
    new_device_uuid = session.pop('iot_new_device_uuid', None)   # UUID for sensor URL

    local_ip = get_local_ip()
    sensor_port = int(os.environ.get('HTTPS_PORT', 5001))
    # Build sensor base URL from current request so it also works via
    # VS Code Dev Tunnels / port forwarding.
    sensor_base = request.url_root.rstrip('/')

    return render_template('iot/device_dashboard.html', devices=devices, latest=latest,
                           new_api_key=new_api_key, new_device_name=new_device_name,
                           new_device_uuid=new_device_uuid,
                           local_ip=local_ip, sensor_port=sensor_port,
                           sensor_base=sensor_base)


@app.route('/iot/devices/register', methods=['POST'])
@login_required
def register_iot_device():
    """Register a new IoT / mobile device and return a one-time API key."""
    device_name = request.form.get('device_name', '').strip()
    device_type = request.form.get('device_type', 'mobile').strip()

    if not device_name:
        flash('Device name is required.', 'danger')
        return redirect(url_for('iot_device_dashboard'))

    raw_api_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()
    device_uuid = str(uuid.uuid4())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO iot_devices (device_id, device_name, device_type, api_key_hash, owner_id)
           VALUES (?, ?, ?, ?, ?)''',
        (device_uuid, device_name, device_type, key_hash, session['user_id'])
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Store API key in session for one-time display on the dashboard (never saved to DB)
    session['iot_new_key'] = raw_api_key
    session['iot_new_device_name'] = device_name
    session['iot_new_device_uuid'] = device_uuid   # UUID used in sensor URL
    return redirect(url_for('iot_device_dashboard'))


@app.route('/iot/devices/<int:device_db_id>/delete', methods=['POST'])
@login_required
def delete_iot_device(device_db_id):
    """Permanently delete an IoT device and its telemetry."""
    conn = get_db()
    cursor = conn.cursor()
    # Verify ownership
    cursor.execute(
        'SELECT id FROM iot_devices WHERE id = ? AND owner_id = ?',
        (device_db_id, session['user_id'])
    )
    if not cursor.fetchone():
        conn.close()
        flash('Device not found.', 'danger')
        return redirect(url_for('iot_device_dashboard'))
    # Delete telemetry first, then the device
    cursor.execute('DELETE FROM iot_telemetry WHERE device_id = ?', (device_db_id,))
    cursor.execute('DELETE FROM iot_devices WHERE id = ? AND owner_id = ?',
                   (device_db_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Device permanently deleted.', 'info')
    return redirect(url_for('iot_device_dashboard'))


@app.route('/iot/devices/<int:device_db_id>/toggle-active', methods=['POST'])
@login_required
def toggle_iot_device_active(device_db_id):
    """Toggle active/deactivated status of an IoT device."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, is_active FROM iot_devices WHERE id = ? AND owner_id = ?',
        (device_db_id, session['user_id'])
    )
    device = cursor.fetchone()
    if not device:
        conn.close()
        flash('Device not found.', 'danger')
        return redirect(url_for('iot_device_dashboard'))
    new_status = 0 if device['is_active'] else 1
    cursor.execute(
        'UPDATE iot_devices SET is_active = ? WHERE id = ? AND owner_id = ?',
        (new_status, device_db_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    label = 'activated' if new_status else 'deactivated'
    flash(f'Device {label}.', 'info')
    return redirect(url_for('iot_device_dashboard'))


@app.route('/iot/sensor/<device_id>')
def mobile_sensor_page(device_id):
    """Mobile-optimised sensor page. No login required — opened on the phone."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM iot_devices WHERE device_id = ? AND is_active = 1',
        (device_id,)
    )
    device = cursor.fetchone()
    conn.close()
    if not device:
        return render_template('errors/404.html'), 404
    has_qkd = bool(device['quantum_key'])
    return render_template('iot/mobile_sensor.html', device=device, device_uuid=device_id,
                           has_qkd=has_qkd)


# ---- Telemetry API ----

@app.route('/api/iot/telemetry', methods=['POST'])
def receive_telemetry():
    """Accept sensor data from a mobile device. Auth via X-API-Key header."""
    device = _api_key_auth()
    if device is None:
        return jsonify({'success': False, 'error': 'Invalid or missing API key'}), 403

    data = request.get_json(silent=True) or {}

    conn = get_db()
    cursor = conn.cursor()

    # Update last_seen timestamp
    cursor.execute(
        'UPDATE iot_devices SET last_seen = ? WHERE id = ?',
        (datetime.now().isoformat(), device['id'])
    )

    accel = data.get('accelerometer', {})
    gyro = data.get('gyroscope', {})
    orient = data.get('orientation', {})
    geo = data.get('geolocation', {})

    # Build raw JSON payload
    raw_payload = json.dumps({
        'accelerometer': accel, 'gyroscope': gyro,
        'orientation': orient, 'geolocation': geo,
        'battery': data.get('battery'), 'status': data.get('status', 'normal')
    })

    # QKD encrypt if device has a quantum key
    encrypted_payload = None
    qkd_active = False
    if device['quantum_key']:
        try:
            enc = QKDEncryption(device['quantum_key'])
            encrypted_payload = enc.encrypt_message(raw_payload)
            qkd_active = True
        except Exception:
            pass

    cursor.execute(
        '''INSERT INTO iot_telemetry
           (device_id, accel_x, accel_y, accel_z,
            gyro_x, gyro_y, gyro_z,
            orientation_alpha, orientation_beta, orientation_gamma,
            latitude, longitude, altitude, accuracy,
            battery_level, status, encrypted_payload, raw_payload)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (
            device['id'],
            accel.get('x'), accel.get('y'), accel.get('z'),
            gyro.get('alpha'), gyro.get('beta'), gyro.get('gamma'),
            orient.get('alpha'), orient.get('beta'), orient.get('gamma'),
            geo.get('latitude'), geo.get('longitude'),
            geo.get('altitude'), geo.get('accuracy'),
            data.get('battery'),
            data.get('status', 'normal'),
            encrypted_payload,
            raw_payload if not qkd_active else None
        )
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'qkd_active': qkd_active})


@app.route('/api/iot/devices/<int:device_db_id>/telemetry')
@login_required
def get_device_telemetry(device_db_id):
    """Return latest 50 telemetry readings for a device owned by the logged-in user."""
    conn = get_db()
    cursor = conn.cursor()
    # Verify ownership
    cursor.execute(
        'SELECT * FROM iot_devices WHERE id = ? AND owner_id = ? AND is_active = 1',
        (device_db_id, session['user_id'])
    )
    device = cursor.fetchone()
    if not device:
        conn.close()
        return jsonify({'success': False, 'error': 'Not found'}), 404

    cursor.execute(
        'SELECT * FROM iot_telemetry WHERE device_id = ? ORDER BY timestamp DESC LIMIT 50',
        (device_db_id,)
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Optionally decrypt encrypted_payload for display
    quantum_key = device['quantum_key']
    for row in rows:
        if row.get('encrypted_payload') and quantum_key:
            try:
                dec = QKDEncryption(quantum_key)
                row['decrypted_payload'] = dec.decrypt_message(row['encrypted_payload'])
            except Exception:
                row['decrypted_payload'] = None
        else:
            row['decrypted_payload'] = None

    return jsonify({'success': True, 'telemetry': rows, 'qkd_active': bool(quantum_key)})


@app.route('/iot/qkd-demo/<int:device_db_id>')
@login_required
def iot_qkd_demo(device_db_id):
    """QKD handshake demo visualization page for an IoT device."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM iot_devices WHERE id = ? AND owner_id = ? AND is_active = 1',
        (device_db_id, session['user_id'])
    )
    device = cursor.fetchone()
    conn.close()
    if not device:
        flash('Device not found.', 'danger')
        return redirect(url_for('iot_device_dashboard'))
    return render_template('iot/qkd_demo.html', device=device)


@app.route('/api/iot/qkd-handshake/<int:device_db_id>', methods=['POST'])
@login_required
def iot_qkd_handshake(device_db_id):
    """Run a real BB84 key exchange and store the resulting quantum key on the device."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM iot_devices WHERE id = ? AND owner_id = ? AND is_active = 1',
        (device_db_id, session['user_id'])
    )
    device = cursor.fetchone()
    if not device:
        conn.close()
        return jsonify({'success': False, 'error': 'Device not found'}), 404

    # Run BB84 with 32-qubit demo key (readable in visualization)
    protocol = BB84Protocol(32)
    result = protocol.generate_key()

    # Store the quantum key on success
    if result.get('success', True) and 'final_key' in result:
        cursor.execute(
            'UPDATE iot_devices SET quantum_key = ? WHERE id = ?',
            (result['final_key'], device_db_id)
        )
        conn.commit()

    conn.close()
    return jsonify(result)


if __name__ == '__main__':
    import sys
    from werkzeug.serving import make_server, generate_adhoc_ssl_context

    print("Initializing Quantum Cryptography for IoT Networks...")
    init_db()
    print("Database initialized.")

    # Start key rotation background worker
    rotation_thread = threading.Thread(target=key_rotation_worker, daemon=True)
    rotation_thread.start()
    print("Key rotation worker started (checks every 60s).")

    local_ip = get_local_ip()

    PORT       = int(os.environ.get('PORT', 5000))
    HTTPS_PORT = int(os.environ.get('HTTPS_PORT', 5001))

    print()
    print("=" * 65)
    print(f"  LAPTOP  ->  http://127.0.0.1:{PORT}   (no warnings)")
    print(f"  PHONE   ->  https://{local_ip}:{HTTPS_PORT}  (tap Advanced > Proceed)")
    print()
    print("  Port-forwarding tip: forward port {0} in VS Code Ports panel,".format(PORT))
    print("  set visibility to 'Public', and use the tunnel URL.")
    print("=" * 65)
    print()

    # ── HTTP server (port 5000) — for laptop / localhost ──────────
    def run_http():
        http = make_server('0.0.0.0', PORT, app)
        http.serve_forever()

    # ── HTTPS server (port 5001) — for phone on same WiFi ────────
    def run_https():
        try:
            ssl_ctx = generate_adhoc_ssl_context()
            https = make_server('0.0.0.0', HTTPS_PORT, app, ssl_context=ssl_ctx)
            https.serve_forever()
        except Exception as e:
            print(f"  [WARN] Could not start HTTPS on :{HTTPS_PORT} — {e}")
            print("         Phone access via HTTPS won't be available.")

    t_http  = threading.Thread(target=run_http,  daemon=True)
    t_https = threading.Thread(target=run_https, daemon=True)
    t_http.start()
    t_https.start()

    try:
        t_http.join()
    except KeyboardInterrupt:
        print("\nShutting down…")
