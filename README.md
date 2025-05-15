# 🔒 Secure Data Encryption System 🔒

A Python-based secure data storage and retrieval system with encryption, password hashing, and brute-force protection.

## 🌟 Features

- 🔐 AES-256 encryption using Fernet
- 🔑 Password hashing with SHA-256
- ⏳ 30-second lockout after 3 failed attempts
- 📁 Secure data storage in JSON format
- 👨‍💻 Admin login for system management
- 🖥️ Streamlit-powered web interface

## 🛠️ Technical Breakdown

### 1. 📚 Imported Libraries
```python
import streamlit as st       # Web interface
import hashlib               # Password hashing
import json                  # Data storage
import os                    # File operations
import time                  # Lockout timing
from cryptography.fernet import Fernet  # Encryption

2. 📂 File Setup python
DATA_FILE = "data.json"      # User data storage
KEY_FILE = "key.key"         # Encryption key storage

3. 🛡️ Core Functions
🔄 load_or_create_key()
Checks for existing encryption key

Generates new key if none exists

Returns Fernet key object

📥 load_data()
Loads encrypted user data from JSON

Returns empty dict if no data exists

📤 save_data(data)
Safely saves all user data to JSON file

🔥 hash_passkey(passkey)
Converts passwords to SHA-256 hashes

Prevents password storage in plaintext

4. ⚙️ System Initialization
python
key = load_or_create_key()           # Load encryption key
cipher = Fernet(key)                 # Create cipher suite
stored_data = load_data()            # Load all user data

5. 🖥️ Web Interface
🏠 Home Page
Welcome message and system overview

💾 Store Data
python
username = st.text_input("Username")
plaintext = st.text_area("Text to encrypt")
passkey = st.text_input("Password", type="password")
Encrypts text with user password

Stores hashed password only

🔍 Retrieve Data
python
if st.session_state.failed_attempts >= 3:
    st.error("Locked out for 30 seconds!")
else:
    # Decryption form
Implements 30-second lockout after 3 fails

Verifies password before decryption

👨‍💻 Admin Login
python
admin_pass = st.text_input("Admin Password", type="password")
if admin_pass == "admin123":
    st.success("Admin access granted!")
Resets failed attempts counter

(Note: Hardcoded password for demo only)

⚠️ Security Notes
Feature	Implementation	Consideration
🔐 Encryption	AES-256	Strong industry standard
🔑 Password Storage	SHA-256 hash	Prevents plaintext storage
🚫 Brute Force Protection	3-attempt lockout	Basic but effective
👨‍💻 Admin Access	Hardcoded password	❌ Not production-safe
🚀 Getting Started
Install requirements:

bash
pip install streamlit cryptography
Run the system:

bash
streamlit run secure_encryption.py
📜 License
This project is for educational purposes only. Not recommended for production use without significant security enhancements.

Made with ❤️ by [NAZIA SHOUKAT]
