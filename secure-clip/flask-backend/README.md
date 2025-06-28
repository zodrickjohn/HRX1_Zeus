
# Flask Backend for SecureClip

## Quick Start

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the setup script:**
   ```bash
   python setup.py
   ```

3. **Start the Flask server:**
   ```bash
   python app.py
   ```

The server will start on `http://localhost:5000` with WebSocket support.

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

### Dashboard
- `GET /api/dashboard/stats` - Real-time dashboard statistics
- `GET /api/dashboard/activity` - Recent activity feed

### Team Management
- `GET /api/teams/members` - Get all team members
- `POST /api/teams/invite` - Invite new team member

### Security Policies
- `GET /api/policies` - Get security policies
- `POST /api/policies` - Create new policy

### Audit Logs
- `GET /api/audit/logs` - Get audit logs with pagination
- `POST /api/audit/logs` - Create new audit log entry

### Device Management
- `GET /api/devices` - Get user devices
- `POST /api/devices/register` - Register new device

### Encryption Manager
- `GET /api/encryption/keys` - Get encryption keys
- `POST /api/encryption/generate` - Generate new encryption key
- `GET /api/encryption/export/<key_id>` - Export encryption key

## WebSocket Events

The backend supports real-time updates through WebSocket connections:

- `team_member_added` - New team member joined
- `new_audit_log` - New audit log entry
- `device_registered` - New device registered
- `policy_created` - New security policy created

## Database

Uses SQLite database (`secureclip.db`) with the following tables:
- `user` - User accounts
- `device` - Registered devices
- `clipboard_entry` - Clipboard data
- `audit_log` - Audit trail
- `security_policy` - Security policies
- `team_member` - Team memberships
- `encryption_key` - Encryption keys

## Features

✅ **Real-time WebSocket connections**
✅ **JWT Authentication**
✅ **SQLite database with SQLAlchemy ORM**
✅ **CORS enabled for frontend**
✅ **Complete API coverage for all frontend components**
✅ **Audit logging with real-time updates**
✅ **Team management with live updates**
✅ **Device registration and monitoring**
✅ **Security policy management**
✅ **Encryption key management**

## Frontend Integration

The frontend is already configured to connect to this backend. Make sure:

1. Flask server is running on port 5000
2. Frontend is running on port 5173
3. Both services can communicate (no firewall blocking)

The frontend will automatically connect via WebSocket for real-time updates.
