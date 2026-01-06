from flask import Flask, render_template, request, redirect, session, send_from_directory, jsonify, flash
import os
import json
import socket
import subprocess
import psutil
from datetime import datetime
import shutil
import re
import hashlib
import secrets
import ssl
from werkzeug.utils import secure_filename
from functools import wraps

# Password hashing - try bcrypt first, fallback to werkzeug
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    from werkzeug.security import generate_password_hash, check_password_hash
    HAS_BCRYPT = False

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VAULT = os.path.join(BASE_DIR, "vault")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "file_log.json")
SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret_key")

# Generate or load strong secret key
def get_or_create_secret_key():
    """Generate a strong secret key or load existing one"""
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    else:
        # Generate a strong random secret key (32 bytes = 256 bits)
        secret_key = secrets.token_urlsafe(32)
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(secret_key)
        return secret_key

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
app.secret_key = get_or_create_secret_key()

# Security configurations
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB limit
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
                      '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar', '.mp4', '.mp3', 
                      '.avi', '.mov', '.csv', '.json', '.xml', '.html', '.css', '.js',
                      '.py', '.java', '.cpp', '.c', '.h', '.md', '.rtf', '.odt'}
BLOCKED_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', 
                      '.jar', '.app', '.deb', '.rpm', '.msi', '.dmg', '.sh', '.ps1'}


def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)


def load_logs():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def save_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def hash_password(password):
    """Hash a password using bcrypt or werkzeug fallback"""
    if HAS_BCRYPT:
        # Generate salt and hash password (bcrypt automatically handles salt)
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        # Fallback to werkzeug's pbkdf2
        return generate_password_hash(password)


def verify_password(password_hash, password):
    """Verify a password against its hash"""
    if HAS_BCRYPT:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            return False
    else:
        return check_password_hash(password_hash, password)


def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_folder_size(folder):
    total = 0
    if os.path.exists(folder):
        for f in os.listdir(folder):
            fp = os.path.join(folder, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


def get_network_info():
    info = {"hostname": socket.gethostname(), "ip": "Unknown"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except:
        pass
    return info


def get_system_stats():
    return {
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('D:\\').percent if os.path.exists('D:\\') else psutil.disk_usage('C:\\').percent
    }


def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and malicious characters"""
    if not filename:
        return None
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Use werkzeug's secure_filename
    filename = secure_filename(filename)
    
    # Additional sanitization
    filename = re.sub(r'[^\w\s.-]', '', filename)
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename if filename else None


def validate_file_extension(filename):
    """Check if file extension is allowed"""
    if not filename:
        return False
    
    _, ext = os.path.splitext(filename.lower())
    
    # Block dangerous extensions
    if ext in BLOCKED_EXTENSIONS:
        return False
    
    # Check if extension is in allowed list
    if ext in ALLOWED_EXTENSIONS:
        return True
    
    # For lab project, allow other extensions but log them
    return True  # You can change this to False for stricter control


def validate_file_size(file):
    """Validate file size"""
    if not file:
        return False
    
    # Get file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)  # Reset file pointer
    
    return size <= MAX_FILE_SIZE and size > 0


def validate_receiver(receiver, all_users):
    """Validate receiver exists and prevent injection"""
    if not receiver or not isinstance(receiver, str):
        return False
    
    # Sanitize receiver name
    receiver = receiver.strip()
    if not re.match(r'^[a-zA-Z0-9_-]+$', receiver):
        return False
    
    return receiver in all_users


def scan_lan_devices():
    devices = []
    try:
        net_info = get_network_info()
        ip = net_info["ip"]
        if ip != "Unknown":
            base_ip = ".".join(ip.split(".")[:-1])
            for i in range(1, 10):
                target = f"{base_ip}.{i}"
                try:
                    result = subprocess.run(
                        ["ping", "-n", "1", "-w", "100", target],
                        capture_output=True, timeout=1, creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if result.returncode == 0:
                        try:
                            hostname = socket.gethostbyaddr(target)[0]
                        except:
                            hostname = "Unknown"
                        devices.append({"ip": target, "hostname": hostname})
                except:
                    pass
    except:
        pass
    return devices


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if "user" in session:
        return redirect("/dashboard")
    
    users = load_users()
    if request.method == "POST":
        user = request.form["username"].strip()
        pwd = request.form["password"]

        if user in users:
            stored_hash = users[user]
            # Check if it's an old plaintext password (for migration)
            if isinstance(stored_hash, str) and not stored_hash.startswith('$2b$') and not stored_hash.startswith('$pbkdf2'):
                # Old plaintext password - verify and migrate
                if stored_hash == pwd:
                    # Migrate to hashed password
                    users[user] = hash_password(pwd)
                    save_users(users)
                    session["user"] = user
                    return redirect("/dashboard")
                else:
                    error = "Invalid username or password!"
            else:
                # Verify hashed password
                if verify_password(stored_hash, pwd):
                    session["user"] = user
                    return redirect("/dashboard")
                else:
                    error = "Invalid username or password!"
        else:
            error = "Invalid username or password!"

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        users = load_users()
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            error = "All fields required!"
        elif len(username) < 3 or len(username) > 20:
            error = "Username must be 3-20 characters!"
        elif not re.match(r'^[a-zA-Z0-9_-]+$', username):
            error = "Username can only contain letters, numbers, underscore, and hyphen!"
        elif len(password) < 4:
            error = "Password must be at least 4 characters!"
        elif username in users:
            error = "Username already exists!"
        else:
            # Hash password before storing
            users[username] = hash_password(password)
            save_users(users)
            os.makedirs(os.path.join(VAULT, username), exist_ok=True)
            return redirect("/")

    return render_template("register.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    user = session["user"]
    users = load_users().keys()

    user_folder = os.path.join(VAULT, user)
    os.makedirs(user_folder, exist_ok=True)
    
    files = []
    for f in os.listdir(user_folder):
        fp = os.path.join(user_folder, f)
        if os.path.isfile(fp):
            files.append({
                "name": f,
                "size": format_size(os.path.getsize(fp)),
                "date": datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M")
            })

    logs = load_logs()
    received_files = [log for log in logs if log.get("receiver") == user]
    
    storage_used = format_size(get_folder_size(user_folder))
    net_info = get_network_info()
    sys_stats = get_system_stats()

    return render_template(
        "dashboard.html",
        user=user,
        users=users,
        files=files,
        received_files=received_files,
        storage_used=storage_used,
        net_info=net_info,
        sys_stats=sys_stats
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    sender = session["user"]
    receivers = request.form.getlist("receivers")
    file = request.files.get("file")

    # Security validations
    if not file or not file.filename:
        flash("No file selected!", "error")
        return redirect("/dashboard")
    
    if not receivers:
        flash("Please select at least one receiver!", "error")
        return redirect("/dashboard")
    
    # Sanitize filename
    original_filename = file.filename
    safe_filename = sanitize_filename(original_filename)
    
    if not safe_filename:
        flash("Invalid filename!", "error")
        return redirect("/dashboard")
    
    # Validate file extension
    if not validate_file_extension(safe_filename):
        flash("File type not allowed or blocked for security!", "error")
        return redirect("/dashboard")
    
    # Validate file size
    if not validate_file_size(file):
        flash(f"File too large! Maximum size is {format_size(MAX_FILE_SIZE)}", "error")
        return redirect("/dashboard")
    
    # Validate receivers
    all_users = set(load_users().keys())
    valid_receivers = []
    for receiver in receivers:
        if validate_receiver(receiver, all_users):
            valid_receivers.append(receiver)
        else:
            flash(f"Invalid receiver: {receiver}", "error")
    
    if not valid_receivers:
        flash("No valid receivers selected!", "error")
        return redirect("/dashboard")
    
    try:
        # Generate unique temp filename to prevent conflicts
        temp_suffix = hashlib.md5(f"{sender}_{datetime.now().timestamp()}".encode()).hexdigest()[:8]
        temp_filename = f"_temp_{temp_suffix}_{safe_filename}"
        temp_path = os.path.join(VAULT, temp_filename)
        
        # Save file temporarily
        file.save(temp_path)
        file_size = os.path.getsize(temp_path)
        file_size_formatted = format_size(file_size)
        
        logs = load_logs()
        
        # Copy to each receiver with secure path handling
        for receiver in valid_receivers:
            receiver_folder = os.path.join(VAULT, receiver)
            os.makedirs(receiver_folder, exist_ok=True)
            
            # Ensure we're within the vault directory (prevent path traversal)
            receiver_folder = os.path.abspath(receiver_folder)
            if not receiver_folder.startswith(os.path.abspath(VAULT)):
                continue
            
            file_path = os.path.join(receiver_folder, safe_filename)
            
            # Prevent overwrite attacks - add timestamp if file exists
            if os.path.exists(file_path):
                name, ext = os.path.splitext(safe_filename)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_filename = f"{name}_{timestamp}{ext}"
                file_path = os.path.join(receiver_folder, safe_filename)
            
            shutil.copy2(temp_path, file_path)
            
            logs.append({
                "filename": safe_filename,
                "original_filename": original_filename,
                "sender": sender,
                "receiver": receiver,
                "size": file_size_formatted,
                "size_bytes": file_size,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "transfer_id": f"T{len(logs) + 1:06d}"
            })
        
        save_logs(logs)
        
        # Remove temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        flash(f"File '{safe_filename}' sent successfully to {len(valid_receivers)} recipient(s)!", "success")
        
    except Exception as e:
        flash(f"Upload failed: {str(e)}", "error")
        # Clean up temp file on error
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

    return redirect("/dashboard")


@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")
    
    user = session["user"]
    
    # Sanitize filename to prevent path traversal
    safe_filename = sanitize_filename(filename)
    if not safe_filename:
        flash("Invalid filename!", "error")
        return redirect("/dashboard")
    
    # Ensure user folder is within vault
    user_folder = os.path.abspath(os.path.join(VAULT, user))
    vault_abs = os.path.abspath(VAULT)
    
    if not user_folder.startswith(vault_abs):
        flash("Invalid file path!", "error")
        return redirect("/dashboard")
    
    file_path = os.path.join(user_folder, safe_filename)
    
    # Verify file exists and is within user's folder
    if not os.path.exists(file_path) or not os.path.abspath(file_path).startswith(user_folder):
        flash("File not found!", "error")
        return redirect("/dashboard")
    
    return send_from_directory(user_folder, safe_filename, as_attachment=True)


@app.route("/delete/<filename>")
def delete_file(filename):
    if "user" not in session:
        return redirect("/")
    
    user = session["user"]
    
    # Sanitize filename to prevent path traversal
    safe_filename = sanitize_filename(filename)
    if not safe_filename:
        flash("Invalid filename!", "error")
        return redirect("/dashboard")
    
    # Ensure user folder is within vault
    user_folder = os.path.abspath(os.path.join(VAULT, user))
    vault_abs = os.path.abspath(VAULT)
    
    if not user_folder.startswith(vault_abs):
        flash("Invalid file path!", "error")
        return redirect("/dashboard")
    
    file_path = os.path.join(user_folder, safe_filename)
    
    # Verify file exists and is within user's folder (prevent path traversal)
    if os.path.exists(file_path) and os.path.abspath(file_path).startswith(user_folder):
        try:
            os.remove(file_path)
            flash(f"File '{safe_filename}' deleted successfully!", "success")
        except Exception as e:
            flash(f"Failed to delete file: {str(e)}", "error")
    else:
        flash("File not found!", "error")
    
    return redirect("/dashboard")


@app.route("/api/scan")
def api_scan():
    if "user" not in session:
        return jsonify([])
    return jsonify(scan_lan_devices())


@app.route("/api/stats")
def api_stats():
    if "user" not in session:
        return jsonify({})
    return jsonify(get_system_stats())


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# Admin credentials (stored securely)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH_FILE = os.path.join(BASE_DIR, ".admin_hash")


def get_admin_password_hash():
    """Get or create admin password hash"""
    if os.path.exists(ADMIN_PASSWORD_HASH_FILE):
        with open(ADMIN_PASSWORD_HASH_FILE, 'r') as f:
            return f.read().strip()
    else:
        # Create default admin password hash (admin123)
        default_hash = hash_password("admin123")
        with open(ADMIN_PASSWORD_HASH_FILE, 'w') as f:
            f.write(default_hash)
        return default_hash


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if "admin" in session:
        return redirect("/admin")
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        admin_hash = get_admin_password_hash()
        
        if username == ADMIN_USERNAME and verify_password(admin_hash, password):
            session["admin"] = username
            return redirect("/admin")
        else:
            error = "Invalid admin credentials!"
    
    return render_template("admin_login.html", error=error)


@app.route("/admin")
def admin_dashboard():
    if "admin" not in session:
        return redirect("/admin/login")
    
    admin_name = session["admin"]
    logs = load_logs()
    users = list(load_users().keys())
    
    # Process logs to ensure transfer_id exists
    for i, log in enumerate(logs):
        if "transfer_id" not in log:
            log["transfer_id"] = f"T{len(logs) - i:06d}"
    
    # Calculate statistics
    total_transfers = len(logs)
    unique_senders = list(set(log.get("sender", "") for log in logs if log.get("sender")))
    unique_receivers = list(set(log.get("receiver", "") for log in logs if log.get("receiver")))
    
    # Active transfers (in-memory) - for now, we'll use recent logs as active
    # In a real scenario, you might track these separately
    active_transfer_entries = logs[-10:] if logs else []  # Last 10 transfers as "active"
    active_transfers = len(active_transfer_entries)
    
    # Reverse logs to show latest first
    logs_reversed = list(reversed(logs))
    
    net_info = get_network_info()
    sys_stats = get_system_stats()
    
    return render_template(
        "admin.html",
        admin_name=admin_name,
        total_transfers=total_transfers,
        active_transfers=active_transfers,
        active_transfer_entries=active_transfer_entries,
        unique_senders=unique_senders,
        unique_receivers=unique_receivers,
        users=users,
        net_info=net_info,
        sys_stats=sys_stats,
        logs=logs_reversed
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")


def create_self_signed_cert():
    """Create self-signed SSL certificate for HTTPS (if not exists)"""
    cert_file = os.path.join(BASE_DIR, "cert.pem")
    key_file = os.path.join(BASE_DIR, "key.pem")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    try:
        import ipaddress
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "LAN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSN Secure Share"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Save certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return cert_file, key_file
    except ImportError:
        print("Warning: cryptography library not installed. HTTPS disabled.")
        print("Install with: pip install cryptography")
        return None, None
    except Exception as e:
        print(f"Warning: Could not create SSL certificate: {e}")
        return None, None


if __name__ == "__main__":
    os.makedirs(VAULT, exist_ok=True)
    net = get_network_info()
    
    # Try to enable HTTPS
    cert_file, key_file = create_self_signed_cert()
    use_https = cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file)
    
    print("\n" + "="*50)
    print("  SSN SECURE SHARE")
    print("="*50)
    
    if use_https:
        print(f"  HTTPS Server: https://{net['ip']}:5000")
        print(f"  HTTPS Local:  https://127.0.0.1:5000")
        print("  NOTE: Using self-signed certificate (browser will show warning)")
        print("  NOTE: Click 'Advanced' -> 'Proceed to site' to continue")
    else:
        print(f"  HTTP Server: http://{net['ip']}:5000")
        print(f"  HTTP Local:  http://127.0.0.1:5000")
        print("  NOTE: HTTPS not available (install 'cryptography' for HTTPS)")
    
    print(f"  Path:   {BASE_DIR}")
    print("="*50 + "\n")
    
    # Security configurations
    if use_https:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=context)
    else:
        app.run(host="0.0.0.0", port=5000, debug=False)
