"""
SQLite Database Setup and Models for Quantum Cryptography IoT Network
"""
import sqlite3
import os
from datetime import datetime

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quantum_iot.db')

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with all required tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            role TEXT DEFAULT 'user',
            is_verified INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Quantum Keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quantum_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT UNIQUE NOT NULL,
            alice_bits TEXT NOT NULL,
            alice_bases TEXT NOT NULL,
            bob_bases TEXT NOT NULL,
            sifted_key TEXT NOT NULL,
            final_key TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            error_rate REAL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            last_used TIMESTAMP,
            key_type TEXT DEFAULT 'session',
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Channels/Groups table (for Pub/Sub)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            channel_type TEXT DEFAULT 'group',
            quantum_key_id INTEGER,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            max_members INTEGER DEFAULT 50,
            FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Channel Members table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS channel_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',
            quantum_key_verified INTEGER DEFAULT 0,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            approved_by INTEGER,
            approved_at TIMESTAMP,
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (approved_by) REFERENCES users(id),
            UNIQUE(channel_id, user_id)
        )
    ''')
    
    # Messages table (Pub/Sub messages)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE NOT NULL,
            channel_id INTEGER,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER,
            content TEXT NOT NULL,
            encrypted_content TEXT,
            quantum_key_id INTEGER,
            message_type TEXT DEFAULT 'text',
            is_encrypted INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            is_deleted INTEGER DEFAULT 0,
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id),
            FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id)
        )
    ''')
    
    # Files table (encrypted files with QR codes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT UNIQUE NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_type TEXT,
            keywords TEXT,
            description TEXT,
            quantum_key_id INTEGER,
            encryption_key TEXT NOT NULL,
            qr_code_path TEXT,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            download_count INTEGER DEFAULT 0,
            FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id),
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        )
    ''')
    
    # File Access Requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            file_id INTEGER NOT NULL,
            requester_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            quantum_key_sent INTEGER DEFAULT 0,
            key_sent_at TIMESTAMP,
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP,
            response_message TEXT,
            access_key TEXT,
            approval_token TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (requester_id) REFERENCES users(id),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # QKD Visualization Log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS qkd_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            step_name TEXT NOT NULL,
            step_data TEXT,
            visualization_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Key Refresh Schedule table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS key_refresh_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quantum_key_id INTEGER NOT NULL,
            refresh_interval INTEGER DEFAULT 300,
            last_refresh TIMESTAMP,
            next_refresh TIMESTAMP,
            refresh_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id)
        )
    ''')
    
    # AI Assistant Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_assistant_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT NOT NULL,
            response TEXT NOT NULL,
            action_taken TEXT,
            recommendation_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Email Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_email TEXT NOT NULL,
            subject TEXT NOT NULL,
            content_type TEXT,
            status TEXT DEFAULT 'sent',
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            related_key_id INTEGER,
            FOREIGN KEY (related_key_id) REFERENCES quantum_keys(id)
        )
    ''')
    
    # Join Requests (for third-party approval)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS join_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE NOT NULL,
            channel_id INTEGER NOT NULL,
            requester_id INTEGER NOT NULL,
            provided_key_hash TEXT,
            status TEXT DEFAULT 'pending',
            verified INTEGER DEFAULT 0,
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMP,
            processed_by INTEGER,
            FOREIGN KEY (channel_id) REFERENCES channels(id),
            FOREIGN KEY (requester_id) REFERENCES users(id),
            FOREIGN KEY (processed_by) REFERENCES users(id)
        )
    ''')
    
    # Private Chats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS private_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT UNIQUE NOT NULL,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            quantum_key_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user1_id) REFERENCES users(id),
            FOREIGN KEY (user2_id) REFERENCES users(id),
            FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id),
            UNIQUE(user1_id, user2_id)
        )
    ''')
    
    # Notifications table
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
    
    # Create default admin user
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, email, password, role, is_admin, is_verified)
        VALUES ('admin', 'admin@qkd-iot.com', 'e10adc3949ba59abbe56e057f20f883e', 'admin', 1, 1)
    ''')
    
    # Migrations for existing databases - add new columns if they don't exist
    try:
        cursor.execute('ALTER TABLE file_requests ADD COLUMN approval_token TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE messages ADD COLUMN file_path TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE messages ADD COLUMN file_name TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE messages ADD COLUMN file_size INTEGER')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # IoT Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT UNIQUE NOT NULL,
            device_name TEXT NOT NULL,
            device_type TEXT DEFAULT 'mobile',
            api_key_hash TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            quantum_key TEXT,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')

    # IoT Telemetry table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            accel_x REAL, accel_y REAL, accel_z REAL,
            gyro_x REAL, gyro_y REAL, gyro_z REAL,
            orientation_alpha REAL, orientation_beta REAL, orientation_gamma REAL,
            latitude REAL, longitude REAL, altitude REAL, accuracy REAL,
            battery_level REAL,
            status TEXT DEFAULT 'normal',
            encrypted_payload TEXT,
            raw_payload TEXT,
            FOREIGN KEY (device_id) REFERENCES iot_devices(id)
        )
    ''')

    # Migrations for existing IoT tables (add QKD columns safely)
    try:
        cursor.execute('ALTER TABLE iot_devices ADD COLUMN quantum_key TEXT')
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute('ALTER TABLE iot_telemetry ADD COLUMN encrypted_payload TEXT')
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute('ALTER TABLE iot_telemetry ADD COLUMN raw_payload TEXT')
    except sqlite3.OperationalError:
        pass

    # Per-user soft-delete for private chat messages (so one user clearing
    # chat does not affect the other user's view)
    try:
        cursor.execute('ALTER TABLE messages ADD COLUMN deleted_by_user1 INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        cursor.execute('ALTER TABLE messages ADD COLUMN deleted_by_user2 INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    # Per-user soft-delete flags on private_chats so one user can "delete"
    # the chat without it disappearing for the other user
    try:
        cursor.execute('ALTER TABLE private_chats ADD COLUMN deleted_by_user1 INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        cursor.execute('ALTER TABLE private_chats ADD COLUMN deleted_by_user2 INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass  # Column already exists

    conn.commit()
    conn.close()
    print("Database initialized successfully!")

def reset_db():
    """Reset the database (WARNING: deletes all data)"""
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    init_db()

if __name__ == '__main__':
    init_db()
    print(f"Database created at: {DATABASE_PATH}")
