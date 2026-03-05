"""
Encryption Module using QKD-generated keys
Provides secure file and message encryption
"""
import os
import hashlib
import base64
from typing import Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json

class QKDEncryption:
    """
    Encryption system using quantum-generated keys
    """
    
    def __init__(self, quantum_key: str = None):
        self.quantum_key = quantum_key
        self.fernet = None
        if quantum_key:
            self._derive_fernet_key()
    
    def _derive_fernet_key(self) -> bytes:
        """Derive a Fernet-compatible key from the quantum key"""
        if not self.quantum_key:
            raise ValueError("No quantum key set")
        
        # Use PBKDF2 to derive a proper key from the quantum key
        salt = b'qkd_salt_2024'  # In production, use random salt stored with ciphertext
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.quantum_key.encode()))
        self.fernet = Fernet(key)
        return key
    
    def set_key(self, quantum_key: str):
        """Set a new quantum key"""
        self.quantum_key = quantum_key
        self._derive_fernet_key()
    
    def encrypt_message(self, message: str) -> str:
        """Encrypt a message using the quantum-derived key"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        
        encrypted = self.fernet.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a message using the quantum-derived key"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """Encrypt a file using the quantum-derived key"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = self.fernet.encrypt(file_data)
        
        if output_path is None:
            output_path = file_path + '.qkd_encrypted'
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_path: str, output_path: str = None) -> str:
        """Decrypt a file using the quantum-derived key"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
        
        if output_path is None:
            output_path = encrypted_path.replace('.qkd_encrypted', '')
            if output_path == encrypted_path:
                output_path = encrypted_path + '.decrypted'
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt raw bytes"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        return self.fernet.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt raw bytes"""
        if not self.fernet:
            raise ValueError("No encryption key set")
        return self.fernet.decrypt(encrypted_data)
    
    @staticmethod
    def generate_file_hash(file_path: str) -> str:
        """Generate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def verify_key_match(key1: str, key2: str) -> bool:
        """Verify if two quantum keys match (for Pub/Sub verification)"""
        hash1 = hashlib.sha256(key1.encode()).hexdigest()[:16]
        hash2 = hashlib.sha256(key2.encode()).hexdigest()[:16]
        return hash1 == hash2


class QuantumSecureChannel:
    """
    Secure communication channel using QKD encryption
    For Pub/Sub messaging system
    """
    
    def __init__(self, channel_id: str, quantum_key: str):
        self.channel_id = channel_id
        self.quantum_key = quantum_key
        self.encryptor = QKDEncryption(quantum_key)
        self.key_hash = hashlib.sha256(quantum_key.encode()).hexdigest()[:16]
    
    def verify_participant(self, provided_key: str) -> bool:
        """Verify if a participant has the correct quantum key"""
        provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()[:16]
        return provided_hash == self.key_hash
    
    def encrypt_for_channel(self, message: str, sender_id: str) -> dict:
        """Encrypt a message for the channel"""
        # Add metadata
        payload = {
            'channel_id': self.channel_id,
            'sender_id': sender_id,
            'message': message,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }
        
        encrypted = self.encryptor.encrypt_message(json.dumps(payload))
        
        return {
            'channel_id': self.channel_id,
            'encrypted_content': encrypted,
            'sender_id': sender_id
        }
    
    def decrypt_from_channel(self, encrypted_content: str) -> dict:
        """Decrypt a message from the channel"""
        decrypted_json = self.encryptor.decrypt_message(encrypted_content)
        return json.loads(decrypted_json)
    
    def get_key_hash(self) -> str:
        """Get the key hash for verification purposes"""
        return self.key_hash


class FileEncryptionService:
    """
    Service for encrypting files with QKD keys and generating QR codes
    """
    
    def __init__(self, upload_folder: str, encrypted_folder: str, qr_folder: str):
        self.upload_folder = upload_folder
        self.encrypted_folder = encrypted_folder
        self.qr_folder = qr_folder
        
        # Create folders if they don't exist
        for folder in [upload_folder, encrypted_folder, qr_folder]:
            os.makedirs(folder, exist_ok=True)
    
    def encrypt_uploaded_file(self, file_path: str, quantum_key: str, 
                             file_id: str) -> dict:
        """
        Encrypt an uploaded file and generate QR code
        """
        import qrcode
        from io import BytesIO
        from config import Config
        
        # Create encryptor with quantum key
        encryptor = QKDEncryption(quantum_key)
        
        # Generate encrypted filename
        original_name = os.path.basename(file_path)
        encrypted_name = f"{file_id}_encrypted_{original_name}"
        encrypted_path = os.path.join(self.encrypted_folder, encrypted_name)
        
        # Encrypt the file
        encryptor.encrypt_file(file_path, encrypted_path)
        
        # Generate file hash
        file_hash = encryptor.generate_file_hash(encrypted_path)
        
        # Generate QR code with direct access URL (not JSON)
        # Get the base URL from Config which loads from .env
        base_url = Config.APP_BASE_URL
        access_url = f'{base_url}/file/access/{file_id}'
        
        qr_data_info = {
            'file_id': file_id,
            'file_hash': file_hash[:16],
            'access_url': access_url
        }
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        # Store the direct URL so scanning opens the browser directly
        qr.add_data(access_url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_path = os.path.join(self.qr_folder, f"{file_id}_qr.png")
        qr_img.save(qr_path)
        
        return {
            'file_id': file_id,
            'original_name': original_name,
            'encrypted_name': encrypted_name,
            'encrypted_path': encrypted_path,
            'file_hash': file_hash,
            'qr_code_path': qr_path,
            'qr_data': qr_data_info
        }
    
    def decrypt_file_for_user(self, encrypted_path: str, quantum_key: str,
                             output_folder: str) -> str:
        """Decrypt a file for authorized user"""
        encryptor = QKDEncryption(quantum_key)
        
        original_name = os.path.basename(encrypted_path)
        # Remove encryption prefix
        if '_encrypted_' in original_name:
            clean_name = original_name.split('_encrypted_', 1)[1]
        else:
            clean_name = original_name.replace('.qkd_encrypted', '')
        
        output_path = os.path.join(output_folder, f"decrypted_{clean_name}")
        encryptor.decrypt_file(encrypted_path, output_path)
        
        return output_path


def generate_encryption_key() -> str:
    """Generate a new Fernet encryption key"""
    return Fernet.generate_key().decode()


if __name__ == '__main__':
    # Test the encryption module
    print("Testing QKD Encryption Module...")
    
    # Test message encryption
    test_key = "a1b2c3d4e5f6789012345678901234567890abcdef"
    encryptor = QKDEncryption(test_key)
    
    original_message = "Hello, this is a secret message!"
    encrypted = encryptor.encrypt_message(original_message)
    decrypted = encryptor.decrypt_message(encrypted)
    
    print(f"\nOriginal: {original_message}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original_message == decrypted}")
    
    # Test secure channel
    print("\n--- Secure Channel Test ---")
    channel = QuantumSecureChannel("channel-001", test_key)
    
    # Verify participant
    print(f"Key verification (correct): {channel.verify_participant(test_key)}")
    print(f"Key verification (wrong): {channel.verify_participant('wrong-key')}")
    
    # Test channel message
    channel_msg = channel.encrypt_for_channel("Test channel message", "user-123")
    print(f"Channel message encrypted: {channel_msg['encrypted_content'][:50]}...")
    
    decrypted_msg = channel.decrypt_from_channel(channel_msg['encrypted_content'])
    print(f"Decrypted message: {decrypted_msg['message']}")
