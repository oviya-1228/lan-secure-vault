# SSN Secure Share

A file sharing app we built for our Networks Lab at SSN College of Engineering. Basically it lets people on the same LAN share files without needing internet or any cloud stuff.

## What it does

- Share files with other users on your network
- Multi-share: send to multiple people at once
- Drag and drop upload
- See who sent you what (inbox)
- Delete files you don't need anymore
- Shows your network info and connected devices

## How to run

1. Install the requirements:
```
pip install -r requirements.txt
```

Or install individually:
```
pip install flask psutil bcrypt cryptography
```

2. Run the app:
```
python app.py
```

3. Open in browser:
   - **HTTPS** (recommended): `https://127.0.0.1:5000` (self-signed cert - browser will show warning, click "Advanced" → "Proceed")
   - **HTTP**: `http://127.0.0.1:5000` (if HTTPS not available)
   - The terminal shows your LAN IP for network access

## Security Features

🔒 **Password Hashing** - Passwords are hashed using bcrypt (never stored in plain text)  
🔒 **HTTPS/TLS** - Encrypted file transfers (self-signed certificate for LAN use)  
🔒 **Strong Session Keys** - Automatically generated secure secret keys  
🔒 **File Validation** - File type and size restrictions  
🔒 **Path Traversal Protection** - Prevents directory escape attacks  

## Tech used

- Flask (Python)
- HTML/CSS/JS
- psutil for system stats
- bcrypt for password hashing
- cryptography for HTTPS/TLS encryption

