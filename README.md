# LAN Secure File Vault

A LAN-only secure file sharing and data vault system built using Flask.  
This project simulates an internal private cloud where users inside the same Local Area Network (LAN) can securely upload, send, and download files without any internet or third-party cloud dependency.

---

## 🔐 Project Overview

Many organizations such as banks, government offices, and legal firms handle sensitive documents that should never leave their internal network.  
This project demonstrates a **LAN-based private cloud** that enables:

- Secure file sharing within an organization
- User-based access and accountability
- Zero dependency on external cloud services

---

## ✨ Key Features

- LAN-only access using internal IP address
- Dynamic user registration and login
- Send files to specific users (targeted sharing)
- View received files with sender name and timestamp
- Local data vault for file storage
- Audit log for file transfers
- Simple and clean Bootstrap-based UI
- No internet required after setup

---

## 🧱 System Architecture

Client Devices (LAN)
├── User A
├── User B
└── User C
|
| (Local IP / Intranet)
v
LAN Server (Flask)
├── User Management (users.json)
├── File Transfer Logs (file_log.json)
└── Secure File Vault (local folders)

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, Bootstrap 5
- **Storage**: Local File System
- **Authentication**: Session-based (Flask)
- **Logging**: JSON-based audit logs
- **Version Control**: Git, GitHub

---

## 📁 Project Structure
lan-secure-vault/
├── app.py
├── .gitignore
├── templates/
│ ├── login.html
│ ├── register.html
│ └── dashboard.html
├── static/
│ └── style.css
├── vault/ # Ignored in Git (local data)
├── users.json # Ignored in Git
└── file_log.json # Ignored in Git


---

## 🚀 How to Run the Project

### 1️⃣ Clone the repository
```bash
git clone https://github.com/oviya-1228/lan-secure-vault.git
cd lan-secure-vault
2️⃣ Install dependencies
pip install flask

3️⃣ Run the server
python app.py

4️⃣ Access the application

Open a browser on any device connected to the same LAN:

http://<server-ip>:5000


Example:

http://192.168.1.15:5000

----- Demo Flow

Register a new user

Login with credentials

Upload a file and select a recipient

Receiver logs in and sees:

File name

Sender name

Timestamp

Receiver downloads the file

-----Audit Logging

Every file transfer is logged with:

Filename

Sender

Receiver

Date and time

This ensures traceability and accountability within the LAN.

----- Security Notes (Demo Scope)

Files never leave the local network

No internet or cloud services involved

Sensitive data excluded from GitHub using .gitignore

Password hashing and encryption can be added as future enhancements

----- Applications

Banks – Internal document sharing

Government offices – Citizen records

Legal firms – Case files and evidence

Educational institutions – Internal file exchange

----- Future Enhancements

Role-based access control (Admin / Auditor)

Password hashing (bcrypt)

Admin approval for new users

File encryption at rest

Online user status

File expiry and auto-deletion

 Author

Oviya
GitHub: https://github.com/oviya-1228

License

This project is for academic and demonstration purposes.


---

##  What to do next

1. In your repo folder, create a file named:


README.md

2. Paste the above content
3. Save it
4. Run:
```bash
git add README.md
git commit -m "Add README documentation"
git push
