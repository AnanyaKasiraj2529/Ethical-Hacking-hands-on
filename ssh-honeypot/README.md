# 🔐 SSH Honeypot – Python-Based Threat Capture System

## 📌 Project Overview

This project implements a custom SSH Honeypot using Python and the `paramiko` library.  
The honeypot simulates an SSH server and captures unauthorized login attempts, credentials, and attacker behavior for defensive security research.

This project demonstrates:

- SSH protocol emulation
- Logging architecture
- Credential harvesting detection
- Threat monitoring in a controlled lab
---
# 🖥️ Environment: Kali Linux
---
# 🛠️ Step-by-Step Implementation Guide
## Step 1 — Update System
```bash
sudo apt update
```
## Step 2 — Install Python Virtual Environment Support
```bash
sudo apt install python3-venv -y
```
## Step 3 — Create Project Directory
```bash
mkdir SSH_Honeypot
cd SSH_Honeypot
python3 -m venv venv
source venv/bin/activate
```
## Must be able to see: (venv) user@kali:~/SSH_Honeypot$
## Requirements - pip install paramiko

🚀 Running the SSH Honeypot
```bash
sudo python honeypot.py
```
## Expected output:
```bash
[+] SSH Honeypot running on port 2222
```
🧪 Testing the Honeypot
Open a second terminal and simulate an attacker:
```bash
ssh attacker@127.0.0.1 -p 2222
```
Enter any password when prompted.
The connection will close after the attempt.

📊 Viewing Captured Logs
View Captured Credentials
```bash
cat logs/credentials.log
```
