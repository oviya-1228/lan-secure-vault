from flask import Flask, render_template, request, redirect, session, send_from_directory
import os
import json
from datetime import datetime   # ✅ NEW

app = Flask(__name__)
app.secret_key = "lan-secret"

VAULT = "vault"
USERS_FILE = "users.json"
LOG_FILE = "file_log.json"      # ✅ NEW


# ---------- Helper Functions ----------
def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)


# ✅ FILE LOG HELPERS
def load_logs():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    with open(LOG_FILE, "r") as f:
        return json.load(f)


def save_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def login():
    users = load_users()
    if request.method == "POST":
        user = request.form["username"]
        pwd = request.form["password"]

        if user in users and users[user] == pwd:
            session["user"] = user
            return redirect("/dashboard")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        users = load_users()
        username = request.form["username"]
        password = request.form["password"]

        if username not in users:
            users[username] = password
            save_users(users)

            os.makedirs(f"{VAULT}/{username}", exist_ok=True)
            return redirect("/")

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    user = session["user"]
    users = load_users().keys()

    user_folder = f"{VAULT}/{user}"
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)

    # ✅ GET FILES SENT TO THIS USER
    logs = load_logs()
    received_files = [log for log in logs if log["receiver"] == user]

    return render_template(
        "dashboard.html",
        user=user,
        users=users,
        files=files,
        received_files=received_files
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session:
        return redirect("/")

    sender = session["user"]               # ✅ SENDER
    receiver = request.form["receiver"]
    file = request.files["file"]

    os.makedirs(f"{VAULT}/{receiver}", exist_ok=True)
    file_path = f"{VAULT}/{receiver}/{file.filename}"
    file.save(file_path)

    # ✅ LOG WHO SENT THE FILE
    logs = load_logs()
    logs.append({
        "filename": file.filename,
        "sender": sender,
        "receiver": receiver,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_logs(logs)

    return redirect("/dashboard")


@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/")

    user = session["user"]
    return send_from_directory(f"{VAULT}/{user}", filename)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- Run Server ----------
app.run(host="0.0.0.0", port=5000)
