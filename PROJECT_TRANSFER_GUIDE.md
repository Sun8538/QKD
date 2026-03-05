# Quantum Cryptography for IoT Networks — Complete Transfer & Setup Guide

> **Generated**: March 2026  
> **Project**: QKD-Based Secure Communication Platform  
> **Stack**: Python 3.12 + Flask + SQLite + Azure OpenAI

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Complete Feature List](#2-complete-feature-list)
3. [Architecture & File Reference](#3-architecture--file-reference)
4. [Prerequisites](#4-prerequisites)
5. [Step-by-Step Installation](#5-step-by-step-installation)
6. [Environment Configuration (.env)](#6-environment-configuration-env)
7. [Running the Application](#7-running-the-application)
8. [All Routes & Endpoints](#8-all-routes--endpoints)
9. [Database Schema](#9-database-schema)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Project Overview

A Flask-based web application that implements **Quantum Key Distribution (BB84 protocol)** for securing IoT network communications. Features include encrypted messaging (pub/sub channels + private chats), encrypted file sharing with QR code access, an AI-powered key management assistant, and IoT device integration.

---

## 2. Complete Feature List

### 2.1 Quantum Key Distribution (QKD)
- **BB84 Protocol Simulation** with visual step-by-step walkthrough
- **Key Types**: session (1h), channel (24h), file (30d), private chat (24h)
- **QBER Monitoring** — eavesdropping detection at >11% error threshold
- **Key Rotation** — manual refresh per channel or scheduled via AI recommendations
- **Key Visualization** — replay Alice/Bob basis selection, sifting, error correction

### 2.2 User Authentication & Security
- User registration and login with password hashing
- Session management with 2-hour expiry
- Secure HTTP headers (X-Frame-Options, X-XSS-Protection, X-Content-Type-Options)
- HMAC timing-safe key comparisons

### 2.3 Encrypted Pub/Sub Messaging (Channels)
- Create named group channels with quantum key protection
- Join requests with admin approval workflow
- Encrypted message storage (Fernet encryption via QKD keys)
- File uploads within channels
- Channel key rotation, member blocking, message clearing

### 2.4 Encrypted Private Chat
- 1-to-1 direct messaging encrypted with per-chat QKD keys
- File sharing in chats
- Soft delete (messages hidden per-user, not destroyed)
- Real-time incremental message polling

### 2.5 Encrypted File Sharing + QR Codes
- Upload files → encrypted with QKD key → stored in `encrypted_files/`
- Each file gets a unique QR code (PNG) for scanning
- Multi-stage access control:
  - Requester scans QR or requests access
  - Owner approves via email link
  - Quantum key delivered to requester via email
  - Requester decrypts and downloads
- 60+ supported file types (docs, images, code, media, archives, executables, certificates)

### 2.6 AI Key Management Assistant
- Powered by **Azure OpenAI (GPT-4o)**
- Intelligent recommendations for key rotation, threat assessment, security posture
- 4000+ line fallback response system when API is unavailable
- Logs all AI interactions to database

### 2.7 Email Service
- Gmail SMTP integration for:
  - File access approval/rejection notifications
  - Quantum key delivery to approved requesters
  - Channel join request notifications
- Graceful fallback when email is not configured

### 2.8 IoT Device Integration
- Device registration dashboard
- Mobile sensor data collection (accelerometer, gyroscope, magnetometer via DeviceMotion API)
- Per-device quantum encryption keys
- QKD demo page for device-level key exchange visualization

---

## 3. Architecture & File Reference

### 3.1 Core Python Files (REQUIRED)

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application — all routes, middleware, request handlers (~4400 lines) |
| `config.py` | Configuration class reading from `.env` — paths, keys, email, Azure settings |
| `database.py` | SQLite database initialization, schema creation, connection helper |
| `qkd_protocol.py` | BB84 protocol simulation (Alice/Bob/Eve), key manager, error correction |
| `qkd_encryption.py` | QKDEncryption (Fernet), QuantumSecureChannel, FileEncryptionService |
| `ai_assistant.py` | Azure OpenAI integration, fallback responses, KeyRotationScheduler |
| `email_service.py` | Gmail SMTP service, HTML email templates, retry logic |
| `requirements.txt` | Python dependencies |
| `.env` | Environment variables (secrets — **never commit to git**) |

### 3.2 Template Directories (REQUIRED)

| Directory | Templates Used |
|-----------|---------------|
| `templates/` | `base.html`, `dashboard.html`, `index_new.html`, `error.html`, `email_approval_success.html` |
| `templates/auth/` | `login.html`, `register.html` |
| `templates/qkd/` | `qkd_home.html`, `qkd_generate.html`, `qkd_visualization.html` |
| `templates/messaging/` | `channels.html`, `create_channel.html`, `view_channel.html`, `join_channel.html`, `private_chats.html`, `private_chat.html` |
| `templates/files/` | `files_list.html`, `upload_file.html`, `view_file.html`, `qr_scanner.html`, `qr_access.html`, `decrypt_file.html`, `browse_files.html` |
| `templates/ai/` | `ai_assistant.html` |
| `templates/iot/` | `device_dashboard.html`, `mobile_sensor.html`, `qkd_demo.html` |
| `templates/errors/` | `404.html`, `500.html` |

### 3.3 Static Assets (REQUIRED)

| Path | Purpose |
|------|---------|
| `static/css/bootstrap.min.css` | Bootstrap 4 stylesheet (used by legacy templates + mobile_sensor) |
| `static/css/tooplate-style.css` | Custom theme CSS (used by index.html, userhome.html) |
| `static/css/magnific-popup.css` | Lightbox CSS (used by index.html, userhome.html) |
| `static/js/background.cycle.js` | Background image cycler JS |
| `static/js/jquery-1.11.0.min.js` | jQuery (legacy templates) |
| `static/js/jquery.magnific-popup.min.js` | Magnific Popup JS |
| `static/slick/` | Slick carousel (CSS + JS + fonts) |
| `static/qr_codes/` | Auto-generated QR code PNGs (re-created at runtime) |
| `static/files/wallpaper.png` | Background wallpaper |

### 3.4 Runtime Directories (created automatically, can be empty on transfer)

| Directory | Purpose |
|-----------|---------|
| `uploads/` | Uploaded plain files before encryption |
| `uploads/chat_files/` | Files shared in private chats |
| `uploads/decrypted_image/` | Temporarily decrypted images |
| `encrypted_files/` | Encrypted file storage |
| `static/qr_codes/` | Generated QR code images |

---

## 4. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.10+ (tested on 3.12) | [python.org/downloads](https://python.org/downloads) |
| **pip** | Latest | Comes with Python |
| **Git** | Optional | For version control |
| **Gmail Account** | — | With 2FA enabled + App Password for email features |
| **Azure OpenAI** | — | Optional — AI assistant falls back gracefully without it |

---

## 5. Step-by-Step Installation

### 5.1 Transfer the Project

Copy the entire `QKD/` folder to the new laptop. **Exclude** these (they'll be regenerated):
- `.venv/` (virtual environment — will be recreated)
- `__pycache__/` (compiled bytecode)
- `quantum_iot.db` (database — will be recreated on first run)
- `encrypted_files/*` contents (test data)
- `uploads/*` contents (test data)
- `static/qr_codes/*` contents (test data)
- `static/profiles/Thumbs.db` (Windows thumbnail cache)

### 5.2 Create Virtual Environment

```powershell
# Navigate to the project folder
cd C:\path\to\QKD

# Create virtual environment
python -m venv .venv

# Activate it (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# If you get an execution policy error, run this first:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**On macOS/Linux:**
```bash
cd /path/to/QKD
python3 -m venv .venv
source .venv/bin/activate
```

### 5.3 Install Dependencies

```powershell
pip install -r requirements.txt
```

This installs:
- Flask 2.3.3, Werkzeug 2.3.7
- pyopenssl (HTTPS support for mobile sensors)
- cryptography 41.0.4, pycryptodome 3.19.0
- qrcode 7.4.2, Pillow 10.0.1
- openai 1.3.5
- numpy 2.0.0
- python-dotenv 1.0.0
- flask-cors 4.0.0

### 5.4 Configure Environment Variables

Edit the `.env` file with your new credentials (see Section 6 below).

### 5.5 Initialize Database

The database (`quantum_iot.db`) is created **automatically** on first run. No manual setup needed.

### 5.6 Create Required Directories

These are created automatically by the app, but you can pre-create them:
```powershell
mkdir uploads, uploads\chat_files, uploads\decrypted_image, encrypted_files, static\qr_codes -Force
```

---

## 6. Environment Configuration (.env)

Create/edit the `.env` file in the project root with these values:

```env
# Flask Secret Key (generate a strong random string)
SECRET_KEY=your-strong-random-secret-key-here

# Application Base URL
# IMPORTANT: For QR codes to work from phones, use your LAN IP
# Find it with: ipconfig (Windows) or ifconfig (Mac/Linux)
APP_BASE_URL=http://YOUR_LOCAL_IP:5000

# ── Email (Gmail SMTP) ──
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# ── Azure OpenAI (Optional) ──
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_KEY=your-azure-openai-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-12-01-preview
```

### How to get Gmail App Password:
1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Enable **2-Step Verification** under Security
3. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
4. Generate a password for "Mail" → "Windows Computer"
5. Use the 16-character password as `MAIL_PASSWORD`

### How to find your LAN IP (for APP_BASE_URL):
```powershell
# Windows
ipconfig | Select-String "IPv4"

# macOS/Linux
ifconfig | grep "inet "
```

---

## 7. Running the Application

### Development Mode

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run the app
python app.py
```

The app starts on **https://0.0.0.0:5000** (HTTPS with self-signed cert via pyopenssl).

- **Local access**: https://localhost:5000 or https://127.0.0.1:5000
- **Network access** (phones/other devices): https://YOUR_LAN_IP:5000
- Your browser will show a security warning for the self-signed cert — click "Advanced" → "Proceed"

### Windows Firewall

If other devices can't connect, allow port 5000 through Windows Firewall:
```powershell
# Run as Administrator
netsh advfirewall firewall add rule name="Flask QKD" dir=in action=allow protocol=tcp localport=5000
```

---

## 8. All Routes & Endpoints

### Authentication
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Landing page |
| GET/POST | `/register` | User registration |
| GET/POST | `/login` | User login |
| GET | `/logout` | Logout |

### Dashboard
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/dashboard` | Main dashboard with stats |

### QKD (Quantum Key Distribution)
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/qkd` | List all quantum keys |
| GET/POST | `/qkd/generate` | Generate new QKD key with visualization |
| GET | `/qkd/visualize/<key_id>` | Replay QKD protocol steps |
| POST | `/api/qkd/generate` | API: Generate key (JSON) |

### Channels (Pub/Sub Messaging)
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/channels` | List all channels |
| GET/POST | `/channels/create` | Create new channel |
| GET | `/channels/<id>` | View channel + messages |
| GET/POST | `/channels/<id>/join` | Request to join channel |
| GET | `/channels/<id>/approve/<req_id>` | Approve join request |
| POST | `/api/channels/<id>/send` | Send channel message |
| GET/POST | `/api/channels/<id>/messages` | Get/send messages |
| PUT | `/api/channels/<id>` | Update channel settings |
| POST | `/api/channels/<id>/refresh-key` | Rotate channel QKD key |
| POST | `/api/channels/<id>/clear` | Clear channel messages |
| POST | `/api/channels/<id>/block-user` | Remove user from channel |
| POST | `/api/channels/<id>/upload-file` | Upload file to channel |

### Private Chat
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/chat` | List all private chats |
| GET | `/chat/start/<user_id>` | Start chat with user |
| GET | `/chat/<chat_id>` | View private chat |
| GET | `/api/chat/<chat_id>/messages` | Get messages (polling) |
| POST | `/api/chat/<chat_id>/send` | Send private message |
| POST | `/api/chat/<chat_id>/upload-file` | Upload file in chat |
| GET | `/api/chat-file/<msg_id>` | Download chat file |

### File Management
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/files` | List user's files |
| GET/POST | `/files/upload` | Upload & encrypt file |
| GET | `/files/<file_id>` | View file details + QR |
| GET | `/files/download/<file_id>` | Download encrypted file |
| POST | `/files/delete/<file_id>` | Delete file |
| POST | `/files/request/<file_id>` | Request file access |
| GET | `/files/approve/<req_id>` | Approve + send key via email |
| GET | `/files/reject/<req_id>` | Reject access request |
| GET | `/files/scan-qr` | QR scanner page |
| GET | `/files/browse` | Browse all accessible files |
| POST | `/files/decrypt` | Decrypt file with key |
| GET | `/qr/<file_id>` | QR code access page |

### AI Assistant
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/ai-assistant` | AI assistant page |
| POST | `/api/ai/recommend` | Get AI recommendation |

### IoT
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/iot/dashboard` | IoT device dashboard |
| POST | `/iot/register` | Register new IoT device |
| GET | `/iot/sensor/<device_id>` | Mobile sensor page |
| POST | `/api/iot/telemetry` | Submit sensor telemetry |
| GET | `/iot/qkd-demo/<device_id>` | QKD demo for device |
| POST | `/api/iot/qkd-exchange` | IoT QKD key exchange |

### Error Handlers
| Code | Route | Description |
|------|-------|-------------|
| 404 | `*` | Page not found |
| 500 | `*` | Internal server error |

---

## 9. Database Schema

SQLite database: `quantum_iot.db` (auto-created on first run)

### Tables

**users** — User accounts
```
id, username, email, password (MD5 hash), role, created_at, profile_image
```

**quantum_keys** — Generated QKD keys
```
id, key_id (UUID), key_type, alice_bits, alice_bases, bob_bases, bob_measurements,
matching_positions, sifted_key, error_rate, final_key, eavesdropper_detected,
protocol_steps (JSON), created_by, created_at, expires_at, is_active, associated_entity
```

**channels** — Group messaging channels
```
id, channel_id (UUID), name, description, created_by, quantum_key_id, created_at,
is_active, is_discoverable
```

**channel_members** — Channel membership
```
id, channel_id, user_id, role (admin/member), joined_at, is_approved
```

**messages** — Channel and chat messages
```
id, message_id (UUID), channel_id, sender_id, encrypted_content, message_type,
file_path, file_name, created_at, is_deleted
```

**files** — Encrypted files
```
id, file_id (UUID), original_filename, encrypted_filename, encrypted_path,
file_size, file_type, encryption_key, qr_code_path, uploaded_by, uploaded_at, is_active
```

**file_requests** — File access workflow
```
id, request_id (UUID), file_id, requester_id, requester_email, status,
requested_at, responded_at, quantum_key
```

**private_chats** — 1-to-1 conversations
```
id, chat_id (UUID), user1_id, user2_id, quantum_key_id, created_at,
is_active, deleted_by_user1, deleted_by_user2
```

**notifications** — User notifications
```
id, user_id, type, message, data (JSON), is_read, created_at
```

**qkd_logs** — QKD visualization history
```
id, key_id, user_id, protocol_data (JSON), created_at
```

**key_refresh_schedule** — Auto key rotation
```
id, entity_type, entity_id, current_key_id, refresh_interval, last_refreshed, next_refresh, is_active
```

**ai_assistant_logs** — AI interaction history
```
id, user_id, query_type, query_data (JSON), response (JSON), created_at
```

**iot_devices** — IoT device registry
```
id, device_id (UUID), name, device_type, owner_id, quantum_key, status, registered_at, last_seen
```

**join_requests** — Channel join tracking
```
id, request_id (UUID), channel_id, user_id, status, requested_at, responded_at
```

---

## 10. Troubleshooting

### "Module not found" error
```powershell
# Make sure venv is active
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### "Address already in use" (port 5000)
```powershell
# Find and kill the process using port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Emails not sending
- Verify Gmail 2FA is enabled
- Regenerate App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
- Check `.env` has correct `MAIL_USERNAME` and `MAIL_PASSWORD`

### QR codes not scannable from phone
- Set `APP_BASE_URL` in `.env` to your LAN IP (e.g., `http://192.168.1.100:5000`)
- Ensure phone and laptop are on the **same WiFi network**
- Allow port 5000 through Windows Firewall

### AI Assistant not responding
- Azure OpenAI credentials are optional — the app falls back to built-in responses
- To enable, fill in `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_KEY` in `.env`

### SSL/HTTPS certificate warning
- Expected behavior with self-signed certificates
- Click "Advanced" → "Proceed to localhost" in your browser
- Required for mobile sensor DeviceMotion API to work

### Database errors after code changes
```powershell
# Delete and recreate the database
Remove-Item quantum_iot.db
python app.py  # Database auto-recreates
```

---

## Quick Start Checklist

- [ ] Python 3.10+ installed
- [ ] Project folder copied (without `.venv/`, `__pycache__/`, `quantum_iot.db`)
- [ ] Virtual environment created and activated
- [ ] `pip install -r requirements.txt` completed
- [ ] `.env` file configured with your credentials
- [ ] `APP_BASE_URL` set to your LAN IP
- [ ] Run `python app.py`
- [ ] Open https://localhost:5000 in browser
- [ ] Register a new user account
- [ ] Test: Generate QKD key → Create channel → Upload file
