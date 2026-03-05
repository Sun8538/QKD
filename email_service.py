"""
Email Service Module for Quantum Key Distribution
Handles sending quantum keys and session keys via email
"""
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import Dict, Optional
import sqlite3

class EmailService:
    """Service for sending quantum keys and notifications via email"""
    
    def __init__(self, smtp_server: str = 'smtp.gmail.com', smtp_port: int = 587,
                 username: str = None, password: str = None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username or os.environ.get('MAIL_USERNAME', '')
        self.password = password or os.environ.get('MAIL_PASSWORD', '')
        self.default_sender = os.environ.get('MAIL_DEFAULT_SENDER', self.username)
    
    def send_email(self, to_email: str, subject: str, body: str, 
                   html_body: str = None, attachments: list = None) -> Dict:
        """Send an email with optional HTML body and attachments"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = self.default_sender
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add plain text body
            msg.attach(MIMEText(body, 'plain'))
            
            # Add HTML body if provided
            if html_body:
                msg.attach(MIMEText(html_body, 'html'))
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    self._add_attachment(msg, attachment)
            
            # Send the email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.default_sender, to_email, msg.as_string())
            
            return {
                'success': True,
                'message': 'Email sent successfully',
                'recipient': to_email,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'recipient': to_email,
                'timestamp': datetime.now().isoformat()
            }
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add an attachment to the email"""
        try:
            with open(file_path, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            filename = os.path.basename(file_path)
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(part)
        except Exception as e:
            print(f"Failed to attach file {file_path}: {e}")
    
    def send_quantum_key(self, to_email: str, key_data: Dict, 
                         file_info: Dict = None) -> Dict:
        """Send a quantum key to user via email"""
        subject = "🔐 Your Quantum Key for Secure Access"
        
        key_preview = key_data.get('final_key', '')[:16] + '...' if key_data.get('final_key') else 'N/A'
        key_hash = key_data.get('key_hash', 'N/A')
        expires_at = key_data.get('expires_at', 'N/A')
        
        body = f"""
Dear User,

Your request has been approved! Here are your secure quantum key credentials:

🔑 Quantum Key Details:
━━━━━━━━━━━━━━━━━━━━━
Key ID: {key_data.get('key_id', 'N/A')}
Key Hash: {key_hash}
Full Key: {key_data.get('final_key', 'N/A')}
Expires: {expires_at}
Error Rate: {key_data.get('error_rate', 0)*100:.2f}%
━━━━━━━━━━━━━━━━━━━━━

"""
        if file_info:
            body += f"""
📁 File Access Information:
━━━━━━━━━━━━━━━━━━━━━
File ID: {file_info.get('file_id', 'N/A')}
Filename: {file_info.get('filename', 'N/A')}
━━━━━━━━━━━━━━━━━━━━━

"""
        
        body += """
⚠️ Security Notice:
- Keep this key confidential
- Do not share this email with others
- The key will expire as indicated above
- For security, delete this email after use

This key was generated using BB84 Quantum Key Distribution protocol,
providing quantum-level security against eavesdropping.

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
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .key-box {{ background: #f8f9fa; border: 2px solid #667eea; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .key-item {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }}
        .key-item:last-child {{ border-bottom: none; }}
        .key-label {{ color: #666; font-weight: 500; }}
        .key-value {{ color: #333; font-family: 'Courier New', monospace; word-break: break-all; }}
        .full-key {{ background: #1a1a2e; color: #00ff88; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; margin: 15px 0; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 0 5px 5px 0; }}
        .warning h4 {{ color: #856404; margin: 0 0 10px 0; }}
        .warning ul {{ margin: 0; padding-left: 20px; color: #856404; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
        .quantum-badge {{ display: inline-block; background: linear-gradient(135deg, #00ff88, #00b4d8); color: #1a1a2e; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Quantum Key Delivery</h1>
            <div class="quantum-badge">BB84 Protocol Secured</div>
        </div>
        <div class="content">
            <p>Dear User,</p>
            <p>Your access request has been <strong style="color: #28a745;">approved</strong>! Below are your quantum-secured credentials:</p>
            
            <div class="key-box">
                <h3 style="margin-top: 0; color: #667eea;">🔑 Key Details</h3>
                <div class="key-item">
                    <span class="key-label">Key ID:</span>
                    <span class="key-value">{key_data.get('key_id', 'N/A')}</span>
                </div>
                <div class="key-item">
                    <span class="key-label">Key Hash:</span>
                    <span class="key-value">{key_hash}</span>
                </div>
                <div class="key-item">
                    <span class="key-label">Error Rate:</span>
                    <span class="key-value">{key_data.get('error_rate', 0)*100:.2f}%</span>
                </div>
                <div class="key-item">
                    <span class="key-label">Expires:</span>
                    <span class="key-value">{expires_at}</span>
                </div>
            </div>
            
            <h4 style="color: #667eea;">🔓 Your Full Quantum Key:</h4>
            <div class="full-key">{key_data.get('final_key', 'N/A')}</div>
            """
        
        if file_info:
            html_body += f"""
            <div class="key-box">
                <h3 style="margin-top: 0; color: #667eea;">📁 File Information</h3>
                <div class="key-item">
                    <span class="key-label">File ID:</span>
                    <span class="key-value">{file_info.get('file_id', 'N/A')}</span>
                </div>
                <div class="key-item">
                    <span class="key-label">Filename:</span>
                    <span class="key-value">{file_info.get('filename', 'N/A')}</span>
                </div>
            </div>
            """
        
        html_body += """
            <div class="warning">
                <h4>⚠️ Security Notice</h4>
                <ul>
                    <li>Keep this key strictly confidential</li>
                    <li>Do not share this email with anyone</li>
                    <li>The key will expire as indicated</li>
                    <li>Delete this email after use for security</li>
                </ul>
            </div>
            
            <p>This key was generated using the <strong>BB84 Quantum Key Distribution</strong> protocol, 
            providing quantum-level security that is theoretically impossible to eavesdrop without detection.</p>
        </div>
        <div class="footer">
            <p>Quantum IoT Security System | Powered by Quantum Key Distribution</p>
            <p>© 2026 All Rights Reserved</p>
        </div>
    </div>
</body>
</html>
"""
        
        return self.send_email(to_email, subject, body, html_body)
    
    def send_channel_invite(self, to_email: str, channel_info: Dict, 
                           quantum_key: str) -> Dict:
        """Send channel/group invitation with quantum key"""
        subject = f"🔐 Invitation to Join: {channel_info.get('name', 'Secure Channel')}"
        
        body = f"""
Dear User,

You have been invited to join a secure quantum-encrypted channel!

📢 Channel Information:
━━━━━━━━━━━━━━━━━━━━━
Channel Name: {channel_info.get('name', 'N/A')}
Channel Type: {channel_info.get('channel_type', 'group')}
Description: {channel_info.get('description', 'N/A')}
━━━━━━━━━━━━━━━━━━━━━

🔑 Your Access Key:
{quantum_key}

To join the channel:
1. Log in to the Quantum IoT Portal
2. Navigate to "Join Channel"
3. Enter the channel name and your access key
4. Your key will be verified against the channel's quantum key

⚠️ Important:
- This key is unique to you
- The channel uses quantum key verification
- Mismatched keys will be rejected for security

Best regards,
Quantum IoT Security System
"""
        
        return self.send_email(to_email, subject, body)
    
    def send_key_rotation_notice(self, to_email: str, old_key_id: str, 
                                 new_key_data: Dict) -> Dict:
        """Notify user about key rotation"""
        subject = "🔄 Quantum Key Rotation Notice"
        
        body = f"""
Dear User,

Your quantum key has been automatically rotated for enhanced security.

Previous Key ID: {old_key_id}
New Key ID: {new_key_data.get('key_id', 'N/A')}
New Key: {new_key_data.get('final_key', 'N/A')}

This rotation was performed to:
- Maintain forward secrecy
- Prevent replay attacks
- Ensure optimal security

Your active sessions will automatically use the new key.

Best regards,
Quantum IoT Security System
"""
        
        return self.send_email(to_email, subject, body)
    
    def send_access_approval(self, to_email: str, request_info: Dict, 
                            key_data: Dict) -> Dict:
        """Send access approval notification with key"""
        subject = "✅ Access Request Approved"
        
        body = f"""
Dear User,

Great news! Your access request has been approved.

📋 Request Details:
━━━━━━━━━━━━━━━━━━━━━
Request ID: {request_info.get('request_id', 'N/A')}
File/Resource: {request_info.get('resource_name', 'N/A')}
Approved by: {request_info.get('approved_by', 'Admin')}
━━━━━━━━━━━━━━━━━━━━━

🔑 Your Access Credentials:
Key: {key_data.get('final_key', 'N/A')}
Valid Until: {key_data.get('expires_at', 'N/A')}

You can now access the requested resource using the provided key.

Best regards,
Quantum IoT Security System
"""
        
        return self.send_email(to_email, subject, body)
    
    def send_access_rejection(self, to_email: str, request_info: Dict, 
                             reason: str = None) -> Dict:
        """Send access rejection notification"""
        subject = "❌ Access Request Rejected"
        
        body = f"""
Dear User,

We regret to inform you that your access request has been rejected.

📋 Request Details:
━━━━━━━━━━━━━━━━━━━━━
Request ID: {request_info.get('request_id', 'N/A')}
File/Resource: {request_info.get('resource_name', 'N/A')}
━━━━━━━━━━━━━━━━━━━━━

Reason: {reason or 'Not specified'}

If you believe this is an error, please contact the resource owner.

Best regards,
Quantum IoT Security System
"""
        
        return self.send_email(to_email, subject, body)


def create_email_service():
    """Factory function to create email service with environment config"""
    # Try to import Config, fallback to env vars
    try:
        from config import Config
        return EmailService(
            smtp_server=Config.MAIL_SERVER,
            smtp_port=Config.MAIL_PORT,
            username=Config.MAIL_USERNAME,
            password=Config.MAIL_PASSWORD
        )
    except ImportError:
        return EmailService(
            smtp_server=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
            smtp_port=int(os.environ.get('MAIL_PORT', 587)),
            username=os.environ.get('MAIL_USERNAME', ''),
            password=os.environ.get('MAIL_PASSWORD', '')
        )


if __name__ == '__main__':
    # Test the email service (won't actually send without credentials)
    service = EmailService()
    
    test_key = {
        'key_id': 'test-key-123',
        'final_key': 'a1b2c3d4e5f6789012345678901234567890abcdef',
        'key_hash': 'abc123def456',
        'error_rate': 0.02,
        'expires_at': '2024-12-31T23:59:59'
    }
    
    print("Email Service Test")
    print("==================")
    print(f"SMTP Server: {service.smtp_server}")
    print(f"Username configured: {'Yes' if service.username else 'No'}")
