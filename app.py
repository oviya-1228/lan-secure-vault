from flask import Flask, render_template, request, redirect, session, send_from_directory, jsonify
import os
import json
import socket
import subprocess
import psutil
from datetime import datetime
import shutil

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
app.secret_key = "lan-secret-key-2026"

VAULT = os.path.join(BASE_DIR, "vault")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "file_log.json")


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

        if user in users and users[user] == pwd:
            session["user"] = user
            return redirect("/dashboard")
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
        elif username in users:
            error = "Username already exists!"
        else:
            users[username] = password
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
    receivers = request.form.getlist("receivers")  # Get multiple receivers
    file = request.files["file"]

    if file and file.filename and receivers:
        # Save file temporarily
        temp_path = os.path.join(VAULT, f"_temp_{file.filename}")
        file.save(temp_path)
        file_size = format_size(os.path.getsize(temp_path))
        
        logs = load_logs()
        
        # Copy to each receiver
        for receiver in receivers:
            receiver_folder = os.path.join(VAULT, receiver)
            os.makedirs(receiver_folder, exist_ok=True)
            file_path = os.path.join(receiver_folder, file.filename)
            shutil.copy2(temp_path, file_path)
            
            logs.append({
                "filename": file.filename,
                "sender": sender,
                "receiver": receiver,
                "size": file_size,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        save_logs(logs)
        
        # Remove temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return redirect("/dashboard")


@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")
    user = session["user"]
    return send_from_directory(os.path.join(VAULT, user), filename, as_attachment=True)


@app.route("/delete/<filename>")
def delete_file(filename):
    if "user" not in session:
        return redirect("/")
    user = session["user"]
    file_path = os.path.join(VAULT, user, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
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


if __name__ == "__main__":
    os.makedirs(VAULT, exist_ok=True)
    net = get_network_info()
    print("\n" + "="*50)
    print("  SSN SECURE SHARE")
    print("="*50)
    print(f"  Server: http://{net['ip']}:5000")
    print(f"  Local:  http://127.0.0.1:5000")
    print(f"  Path:   {BASE_DIR}")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
