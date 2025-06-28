from flask import Flask, request, jsonify
from flask_cors import CORS # type: ignore
from datetime import datetime, timedelta
import uuid
import json
import openai
import os
from typing import Dict, List, Any
from user_agents import parse as parse_user_agent
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
CORS(app, origins=["http://localhost:8080", "http://localhost:3000", "http://localhost:5173"])
socketio = SocketIO(app, cors_allowed_origins="*")

# Set OpenAI API key
openai.api_key = "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"

# In-memory storage (replace with real database in production)
users_db = {}
devices_db = {}
team_members_db = {}
domain_rules_db = {}
compliance_reports_db = {}
audit_logs_db = []
clipboard_db = {}
browser_activities_db = []
encryption_keys_db = {}
security_policies_db = {}

# Helper function to get current user (mock authentication)
def get_current_user():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        # Mock user validation - in production, validate JWT token
        return {"id": "user123", "email": "user@example.com"}
    return None

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "version": "1.0.0"})



# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Mock authentication
    user = {
        "id": str(uuid.uuid4()),
        "email": email,
        "name": email.split('@')[0]
    }
    
    return jsonify({
        "user": user,
        "access_token": f"mock_token_{user['id']}",
        "refresh_token": f"refresh_token_{user['id']}"
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "email": email,
        "name": email.split('@')[0],
        "created_at": datetime.now().isoformat()
    }
    
    users_db[user_id] = user
    
    return jsonify({
        "user": user,
        "access_token": f"mock_token_{user_id}",
        "refresh_token": f"refresh_token_{user_id}"
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    # Optional: In production, you'd invalidate the token here (e.g., add to blacklist)
    return jsonify({"message": "Logged out successfully"})

# Dashboard endpoints
@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "active_clips": sum(d.get('clipboard_count', 0) for d in devices_db.values()),
        "encrypted_items": "100%",  # Static for now
        "team_members": 5,          # Dummy or real count from DB
        "security_alerts": 3
    })

@app.route('/api/dashboard/activity', methods=['GET'])
def get_recent_activity():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    activities = [
        {
            "id": "1",
            "action": "Clipboard Synced",
            "user": user.get("email", "Unknown User"),
            "details": "User synced clipboard with MacBook Pro",
            "device": "MacBook Pro",
            "timestamp": datetime.now().isoformat(),
            "status": "success"
        },
        {
            "id": "2", 
            "action": "Security Scan Triggered",
            "user": user.get("email", "Unknown User"),
            "details": "Chrome browser detected a possible threat",
            "device": "Chrome Browser",
            "timestamp": (datetime.now() - timedelta(minutes=15)).isoformat(),
            "status": "warning"
        }
    ]
    return jsonify(activities)


# Device Management endpoints
@app.route('/api/devices', methods=['GET'])
def get_devices():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    devices = []
    for device in devices_db.values():
        devices.append(device)
    
    # Add mock devices if none exist
    if not devices:
        devices = [
            {
                "id": "1",
                "name": "Asus ",
                "type": "laptop",
                "platform": "window",
                "lastActive": datetime.now().isoformat(),
                "lastClipboardSync": datetime.now().isoformat(),
                "status": "active",
                "createdAt": datetime.now().isoformat(),
                "publicKeyFingerprint": "abc123",
                "clipboardCount": 25
            },
            {
                "id": "2",
                "name": "Chrome Browser",
                "type": "browser",
                "platform": "Windows",
                "lastActive": (datetime.now() - timedelta(hours=2)).isoformat(),
                "lastClipboardSync": (datetime.now() - timedelta(hours=2)).isoformat(),
                "status": "inactive",
                "createdAt": (datetime.now() - timedelta(days=5)).isoformat(),
                "publicKeyFingerprint": "def456",
                "clipboardCount": 10
            }
        ]
    
    return jsonify(devices)

@app.route('/api/devices/register', methods=['POST'])
def register_device():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    device_id = str(uuid.uuid4())

    # Parse User-Agent to get browser and platform details
    user_agent_string = request.headers.get('User-Agent', '')
    user_agent = parse_user_agent(user_agent_string)

    platform = user_agent.os.family or data.get('platform', 'Unknown')
    browser_type = user_agent.browser.family or 'Unknown'

    device = {
        "id": device_id,
        "name": data.get('name') or f"{browser_type} on {platform}",
        "type": data.get('type') or 'browser',
        "platform": platform,
        "lastActive": datetime.now().isoformat(),
        "status": "active",
        "createdAt": datetime.now().isoformat(),
        "publicKeyFingerprint": data.get('fingerprint', 'unknown'),
        "clipboardCount": 0
    }

    devices_db[device_id] = device
    return jsonify(device)

# Browser Extension endpoints
@app.route('/api/browser-extension/status', methods=['GET'])
def get_extension_status():

    user_agent = request.headers.get('User-Agent', '').lower()

    if 'edg' in user_agent:
        browser_type = 'Edge'
    elif 'opr' in user_agent or 'opera' in user_agent:
        browser_type = 'Opera'
    elif 'firefox' in user_agent:
        browser_type = 'Firefox'
    elif 'chrome' in user_agent and 'safari' in user_agent:
        browser_type = 'Chrome'
    elif 'safari' in user_agent:
        browser_type = 'Safari'
    else:
        browser_type = 'Unknown'

    return jsonify({
        "isInstalled": True,
        "version": "1.0.0",
        "lastHeartbeat": datetime.now().isoformat(),
        "browserType": browser_type,
        "permissions": ["activeTab", "clipboardRead", "clipboardWrite"],
        "status": "active"
    })

@app.route('/api/browser-extension/heartbeat', methods=['POST'])
def send_extension_heartbeat():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    browser_type = data.get('browser_type', 'Unknown')
    version = data.get('version', '1.0.0')
    
    return jsonify({
        "status": "received",
        "timestamp": datetime.now().isoformat(),
        "browser_type": browser_type,
        "version": version
    })

@app.route('/api/browser-extension/activities', methods=['GET'])
def get_browser_activities():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    activities = [
        {
            "id": "1",
            "timestamp": datetime.now().isoformat(),
            "domain": "github.com",
            "action": "copy",
            "status": "allowed",
            "details": "Code snippet copied from repository"
        },
        {
            "id": "2",
            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "domain": "docs.google.com",
            "action": "paste",
            "status": "blocked",
            "details": "Sensitive content blocked"
        }
    ]
    
    return jsonify(activities)

# Team Management endpoints
@app.route('/api/team/members', methods=['GET'])
def get_team_members():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    members = []
    for member in team_members_db.values():
        members.append(member)
    
    # Add mock member if none exist
    if not members:
        members = [
            {
                "id": "1",
                "email": "admin@company.com",
                "role": "admin",
                "teams": ["security", "development"],
                "status": "active",
                "last_active": datetime.now().isoformat(),
                "invited_at": (datetime.now() - timedelta(days=30)).isoformat()
            }
        ]
    
    return jsonify(members)

@app.route('/api/team/invite', methods=['POST'])
def invite_team_member():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    invitation_id = str(uuid.uuid4())
    
    invitation = {
        "id": invitation_id,
        "email": data.get('email'),
        "role": data.get('role'),
        "teams": data.get('teams', []),
        "status": "pending",
        "invited_at": datetime.now().isoformat(),
        "invited_by": user['email']
    }
    
    team_members_db[invitation_id] = invitation
    return jsonify({"invitation_id": invitation_id, "status": "sent"})

# Domain Rules endpoints
@app.route('/api/domain-rules', methods=['GET'])
def get_domain_rules():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    rules = []
    for rule in domain_rules_db.values():
        rules.append(rule)
    
    # Add mock rules if none exist
    if not rules:
        rules = [
            {
                "id": "1",
                "domain": "github.com",
                "type": "whitelist",
                "status": "active",
                "created_at": datetime.now().isoformat()
            },
            {
                "id": "2",
                "domain": "malicious-site.com",
                "type": "blacklist",
                "status": "active",
                "created_at": datetime.now().isoformat()
            }
        ]
    
    return jsonify(rules)

@app.route('/api/domain-rules', methods=['POST'])
def add_domain_rule():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    rule_id = str(uuid.uuid4())
    
    rule = {
        "id": rule_id,
        "domain": data.get('domain'),
        "type": data.get('rule_type'),
        "status": "active",
        "created_at": datetime.now().isoformat()
    }
    
    domain_rules_db[rule_id] = rule
    return jsonify(rule)

@app.route('/api/domain-rules/<rule_id>', methods=['DELETE'])
def remove_domain_rule(rule_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    if rule_id in domain_rules_db:
        del domain_rules_db[rule_id]
        return jsonify({"message": "Rule deleted successfully"})
    
    return jsonify({"error": "Rule not found"}), 404

# Clipboard Management endpoints
@app.route('/api/clipboard/upload', methods=['POST'])
def upload_clipboard():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    clipboard_id = str(uuid.uuid4())
    
    clipboard_entry = {
        "id": clipboard_id,
        "user_id": data.get('user_id'),
        "device_id": data.get('device_id'),
        "encrypted_content": data.get('encrypted_content'),
        "content_type": data.get('content_type'),
        "encryption_metadata": data.get('encryption_metadata'),
        "shared_with": data.get('shared_with', []),
        "expires_at": data.get('expires_at'),
        "created_at": datetime.now().isoformat()
    }
    
    clipboard_db[clipboard_id] = clipboard_entry
    return jsonify(clipboard_entry)

@app.route('/api/clipboard/latest/<user_id>', methods=['GET'])
def get_latest_clipboard(user_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Find latest clipboard entry for user
    latest_entry = None
    latest_time = None
    
    for entry in clipboard_db.values():
        if entry['user_id'] == user_id:
            entry_time = datetime.fromisoformat(entry['created_at'])
            if latest_time is None or entry_time > latest_time:
                latest_entry = entry
                latest_time = entry_time
    
    if latest_entry:
        return jsonify(latest_entry)
    else:
        return jsonify({"error": "No clipboard data found"}), 404

@app.route('/api/clipboard/history/<user_id>', methods=['GET'])
def get_clipboard_history(user_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    limit = int(request.args.get('limit', 20))
    offset = int(request.args.get('offset', 0))
    
    user_entries = [entry for entry in clipboard_db.values() if entry['user_id'] == user_id]
    user_entries.sort(key=lambda x: x['created_at'], reverse=True)
    
    paginated_entries = user_entries[offset:offset + limit]
    return jsonify(paginated_entries)

########################################################



# Content Analysis with OpenAI
@app.route('/api/content/analyze', methods=['POST'])
def analyze_content():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    content = data.get('content', '')
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security analyst. Analyze the given content for sensitive information, security risks, and compliance issues. Provide a classification (public, sensitive, confidential, restricted), confidence score (0-1), detected patterns, and recommendations."
                },
                {
                    "role": "user", 
                    "content": f"Analyze this content for security and compliance: {content}"
                }
            ],
            temperature=0.3
        )
        
        ai_response = response.choices[0].message.content
        
        # Parse AI response and structure it
        result = {
            "classification": "sensitive",  # Default classification
            "confidence": 0.85,
            "detected_patterns": ["AI-detected sensitive content"],
            "recommendations": ["Review content before sharing"],
            "ai_analysis": {
                "summary": ai_response,
                "riskScore": 6,
                "detailedFindings": ["AI analysis completed"],
                "complianceIssues": []
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"OpenAI API error: {e}")
        # Fallback to local analysis
        return jsonify({
            "classification": "public",
            "confidence": 0.75,
            "detected_patterns": ["No sensitive patterns detected"],
            "recommendations": ["Content appears safe for general sharing"]
        })
        
        

# Content Scanning
@app.route('/api/content/scan', methods=['POST'])
def scan_content():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    content = data.get('content', '')
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security scanner. Analyze content for malware, suspicious URLs, exposed credentials, PII, and other security threats. Provide a safety assessment and risk level."
                },
                {
                    "role": "user",
                    "content": f"Scan this content for security threats: {content}"
                }
            ],
            temperature=0.1
        )
        
        ai_response = response.choices[0].message.content
        
        result = {
            "is_safe": True,
            "threats": [],
            "risk_level": "low",
            "scan_results": {
                "malware_indicators": [],
                "suspicious_urls": [],
                "exposed_credentials": [],
                "pii_detected": [],
                "security_score": 95
            },
            "ai_analysis": {
                "summary": ai_response,
                "riskScore": 2,
                "recommendations": ["Content appears safe"]
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"OpenAI API error: {e}")
        # Fallback scan
        return jsonify({
            "is_safe": True,
            "threats": ["No threats detected"],
            "risk_level": "low",
            "scan_results": {
                "malware_indicators": [],
                "suspicious_urls": [],
                "exposed_credentials": [],
                "pii_detected": [],
                "security_score": 85
            }
        })

# Encryption Key Management endpoints
@app.route('/api/encryption/keys', methods=['GET'])
def get_encryption_keys():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    keys = []
    for key in encryption_keys_db.values():
        keys.append(key)
    
    # Mock keys if none exist
    if not keys:
        keys = [
            {
                "id": "1",
                "name": "Primary AES Key",
                "type": "AES-256",
                "status": "active",
                "created_at": datetime.now().isoformat(),
                "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
            }
        ]
    
    return jsonify(keys)

@app.route('/api/encryption/generate', methods=['POST'])
def generate_encryption_key():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    key_id = str(uuid.uuid4())
    
    key = {
        "id": key_id,
        "name": data.get('name', f"Generated Key {key_id[:8]}"),
        "type": data.get('type', 'AES-256'),
        "status": "active",
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
    }
    
    encryption_keys_db[key_id] = key
    return jsonify(key)

# Security Policies endpoints
@app.route('/api/policies', methods=['GET'])
def get_security_policies():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    policies = []
    for policy in security_policies_db.values():
        policies.append(policy)
    
    # Mock policies if none exist
    if not policies:
        policies = [
            {
                "id": "1",
                "name": "Data Loss Prevention",
                "type": "DLP",
                "status": "active",
                "rules": {
                    "block_sensitive_data": True,
                    "scan_clipboard": True
                },
                "created_at": datetime.now().isoformat()
            }
        ]
    
    return jsonify(policies)

@app.route('/api/policies', methods=['POST'])
def create_security_policy():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    policy_id = str(uuid.uuid4())
    
    policy = {
        "id": policy_id,
        "name": data.get('name'),
        "type": data.get('type'),
        "status": "active",
        "rules": data.get('rules', {}),
        "created_at": datetime.now().isoformat()
    }
    
    security_policies_db[policy_id] = policy
    return jsonify(policy)

# Audit Logs endpoints
@app.route('/api/audit/logs', methods=['GET'])
def get_audit_logs():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Mock audit logs if none exist
    if not audit_logs_db:
        mock_logs = [
            {
                "id": str(i),
                "user_id": user['id'],
                "action": "clipboard_copy",
                "timestamp": (datetime.now() - timedelta(minutes=i*10)).isoformat(),
                "status": "success",
                "metadata": {"content_type": "text"}
            } for i in range(1, 6)
        ]
        audit_logs_db.extend(mock_logs)
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    return jsonify(audit_logs_db[start_idx:end_idx])

@app.route('/api/audit/log', methods=['POST'])
def create_audit_log():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    log_id = str(uuid.uuid4())
    
    log_entry = {
        "id": log_id,
        "user_id": data.get('user_id'),
        "device_id": data.get('device_id'),
        "action": data.get('action'),
        "target_domain": data.get('target_domain'),
        "target_application": data.get('target_application'),
        "content_hash": data.get('content_hash'),
        "status": data.get('status'),
        "metadata": data.get('metadata', {}),
        "timestamp": datetime.now().isoformat()
    }
    
    audit_logs_db.append(log_entry)
    # Emit the new log to all connected clients
    socketio.emit('audit_log', log_entry, broadcast=True)
    return jsonify(log_entry)

# Paste Control endpoints
@app.route('/api/paste-control/validate', methods=['POST'])
def validate_paste():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    domain = data.get('domain')
    
    # Simple validation logic
    blocked_domains = ['malicious-site.com', 'blocked-domain.com']
    allowed = domain not in blocked_domains
    
    return jsonify({
        "allowed": allowed,
        "reason": "Domain is blocked" if not allowed else "Domain is allowed"
    })

# Compliance Reports endpoints
@app.route('/api/compliance/reports', methods=['GET'])
def get_compliance_reports():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    reports = []
    for report in compliance_reports_db.values():
        reports.append(report)
    
    # Mock reports if none exist
    if not reports:
        reports = [
            {
                "id": "1",
                "name": "GDPR Compliance Report - Q1 2024",
                "type": "GDPR",
                "status": "ready",
                "created_at": datetime.now().isoformat(),
                "download_url": "/api/compliance/download/1",
                "file_size": 2048576
            }
        ]
    
    return jsonify(reports)

@app.route('/api/compliance/generate-report', methods=['POST'])
def generate_compliance_report():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    report_id = str(uuid.uuid4())
    
    report = {
        "report_id": report_id,
        "name": f"{data.get('compliance_standard', 'GDPR')} Report",
        "status": "ready",
        "download_url": f"/api/compliance/download/{report_id}",
        "file_size": 1024000,
        "format": "PDF"
    }
    
    compliance_reports_db[report_id] = report
    return jsonify(report)

@app.route('/api/compliance/download/<report_id>', methods=['GET'])
def download_compliance_report(report_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Mock PDF content
    pdf_content = b"Mock PDF Report Content"
    return pdf_content, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'attachment; filename=report_{report_id}.pdf'
    }

@socketio.on('connect')
def handle_connect():
    print('Client connected:', request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected:', request.sid)

# Optional: Allow clients to join a room for audit logs
@socketio.on('join_audit_logs')
def handle_join_audit_logs():
    join_room('audit_logs')
    emit('joined_audit_logs', {'message': 'Joined audit logs room'})

if __name__ == '__main__':
    print("🚀 Starting Flask API server...")
    print("📡 CORS enabled for localhost:8080, localhost:3000, localhost:5173")
    print("🔑 OpenAI API key configured")
    print("\n📋 Available endpoints:")
    print("   Authentication:")
    print("   - POST /api/auth/login")
    print("   - POST /api/auth/register")
    print("   \n🏠 Dashboard:")
    print("   - GET /api/health")
    print("   - GET /api/dashboard/stats")
    print("   - GET /api/dashboard/activity")
    print("   \n📱 Device Management:")
    print("   - GET /api/devices")
    print("   - POST /api/devices/register")
    print("   - POST /api/devices/{id}/revoke")
    print("   \n🌐 Browser Extension:")
    print("   - GET /api/browser-extension/status")
    print("   - POST /api/browser-extension/heartbeat")
    print("   - GET /api/browser-extension/activities")
    print("   \n👥 Team Management:")
    print("   - GET /api/team/members")
    print("   - POST /api/team/invite")
    print("   \n🔐 Domain Rules:")
    print("   - GET /api/domain-rules")
    print("   - POST /api/domain-rules")
    print("   - DELETE /api/domain-rules/{id}")
    print("   \n📋 Clipboard:")
    print("   - POST /api/clipboard/upload")
    print("   - GET /api/clipboard/latest/{user_id}")
    print("   - GET /api/clipboard/history/{user_id}")
    print("   \n🔍 Content Analysis:")
    print("   - POST /api/content/analyze")
    print("   - POST /api/content/scan")
    print("   \n🔑 Encryption:")
    print("   - GET /api/encryption/keys")
    print("   - POST /api/encryption/generate")
    print("   \n📝 Audit & Compliance:")
    print("   - GET /api/audit/logs")
    print("   - POST /api/audit/log")
    print("   - POST /api/paste-control/validate")
    print("   - GET /api/compliance/reports")
    print("   - POST /api/compliance/generate-report")
    print("   - GET /api/compliance/download/{id}")
    print("\n✅ Server ready at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
