"""
Configuration settings for Quantum Cryptography for IoT Networks
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
    
    # Application Base URL (for QR codes and external links)
    APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000')
    
    # Database
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quantum_iot.db')
    
    # Upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ENCRYPTED_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encrypted_files')
    QR_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'qr_codes')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
        'csv', 'json', 'xml', 'yaml', 'yml', 'md', 'rtf', 'log',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
        'mp3', 'wav', 'ogg', 'flac', 'aac', 'wma',
        'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm',
        'py', 'js', 'html', 'css', 'java', 'c', 'cpp', 'h', 'cs', 'go', 'rs', 'rb', 'php',
        'sql', 'sh', 'bat', 'ps1', 'ts', 'tsx', 'jsx',
        'apk', 'exe', 'msi', 'dmg', 'iso', 'bin',
        'pem', 'key', 'crt', 'cer', 'p12', 'pfx'
    }
    
    # Email settings (all from environment variables)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '')
    
    # QKD Settings
    QKD_KEY_LENGTH = int(os.environ.get('QKD_KEY_LENGTH', 256))  # bits
    KEY_REFRESH_INTERVAL = int(os.environ.get('KEY_REFRESH_INTERVAL', 300))  # seconds (5 minutes)
    KEY_EXPIRY_TIME = int(os.environ.get('KEY_EXPIRY_TIME', 3600))  # seconds (1 hour)
    
    # Azure OpenAI Settings (all from environment variables)
    AZURE_OPENAI_ENDPOINT = os.environ.get('AZURE_OPENAI_ENDPOINT', '')
    AZURE_OPENAI_KEY = os.environ.get('AZURE_OPENAI_KEY', '')
    AZURE_OPENAI_DEPLOYMENT = os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'gpt-4o')
    AZURE_OPENAI_API_VERSION = os.environ.get('AZURE_OPENAI_API_VERSION', '2024-12-01-preview')
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False

# Create necessary directories
for folder in [Config.UPLOAD_FOLDER, Config.ENCRYPTED_FOLDER, Config.QR_FOLDER]:
    os.makedirs(folder, exist_ok=True)
