import streamlit as st
import hashlib
import json
import os
import time
import re
from cryptography.fernet import Fernet
from datetime import datetime

# ----- Constants -----
DATA_FILE = "data.json"
KEY_FILE = "key.key"
ADMIN_HASH_FILE = "admin_hash.txt"
MIN_PASSWORD_LENGTH = 8
MAX_INPUT_LENGTH = 1000

# Password validation regex
PASSWORD_PATTERN = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')

# ----- Utility Functions -----
def validate_password(password):
    """Validate password strength"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    if not PASSWORD_PATTERN.match(password):
        return False, "Password must contain at least one letter, one number, and one special character"
    return True, "Password is strong"

def log_security_event(event):
    """Log security events"""
    timestamp = datetime.now().isoformat()
    log_entry = f"{timestamp} - {event}\n"
    try:
        with open("security.log", "a") as f:
            f.write(log_entry)
    except Exception:
        pass  # Silently fail if logging is not possible

def validate_input(text, max_length=MAX_INPUT_LENGTH):
    """Validate and sanitize input"""
    if not text or not isinstance(text, str):
        return False, "Input cannot be empty"
    if len(text) > max_length:
        return False, f"Input must be less than {max_length} characters"
    # Basic sanitization
    text = text.strip()
    if not text:
        return False, "Input cannot be empty after sanitization"
    return True, text

def load_or_create_admin_hash():
    """Load or create admin password hash"""
    if os.path.exists(ADMIN_HASH_FILE):
        with open(ADMIN_HASH_FILE, "r") as f:
            return f.read().strip()
    # Create new admin hash with a secure default password
    default_admin = "Admin@123"  # This should be changed immediately after first login
    admin_hash = hash_passkey(default_admin)
    with open(ADMIN_HASH_FILE, "w") as f:
        f.write(admin_hash)
    return admin_hash

# Load or create encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# Load or initialize user data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Hash a passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# ----- Initialization -----
cipher = Fernet(load_or_create_key())
stored_data = load_data()

# Session state
if "username" not in st.session_state:
    st.session_state.username = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Handle rerun manually
if st.session_state.get("rerun_flag"):
    st.session_state["rerun_flag"] = False
    st._set_query_params()
    st.stop()

def fake_rerun():
    st.session_state["rerun_flag"] = True
    st.stop()

# ----- UI -----
st.title("🔐 Secure Data Encryption System (Multi-User + Persistent + Lockout)")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ----- Home Page -----
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Multi-user data encryption with passkey protection and lockout system.")

# ----- Store Data -----
elif choice == "Store Data":
    st.subheader("📥 Store Data Securely")
    username = st.text_input("Username:")
    user_data = st.text_area("Enter Text to Encrypt:")
    passkey = st.text_input("Set a Passkey:", type="password")
    
    # Add password strength indicator
    if passkey:
        is_valid, msg = validate_password(passkey)
        if is_valid:
            st.success("✅ " + msg)
        else:
            st.warning("⚠️ " + msg)
    
    # Validate username
    if username:
        is_valid, msg = validate_input(username, 50)  # Limit username length
        if not is_valid:
            st.error(f"❌ {msg}")
            username = None
    
    # Validate user data
    if user_data:
        is_valid, msg = validate_input(user_data)
        if not is_valid:
            st.error(f"❌ {msg}")
            user_data = None

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            is_valid, msg = validate_password(passkey)
            if not is_valid:
                st.error(f"❌ {msg}")
                st.stop()
                
            try:
                encrypted_text = cipher.encrypt(user_data.encode()).decode()
                hashed_pass = hash_passkey(passkey)

                # Store under user with timestamp
                if username not in stored_data:
                    stored_data[username] = []
                stored_data[username].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_pass,
                    "timestamp": datetime.now().isoformat()
                })
                save_data(stored_data)
                st.success("✅ Data securely stored.")
                st.code(encrypted_text, language="text")
                log_security_event(f"Data stored for user: {username}")
            except Exception as e:
                st.error(f"❌ Error storing data: {str(e)}")
                log_security_event(f"Error storing data for user {username}: {str(e)}")
        else:
            st.error("⚠️ Please fill all fields correctly.")

# ----- Retrieve Data -----
elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Your Data")

    # Lockout check
    if st.session_state.failed_attempts >= 3:
        remaining = int(st.session_state.lockout_time - time.time())
        if remaining > 0:
            st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
            st.stop()
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0

    username = st.text_input("Username:")
    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            entries = stored_data.get(username, [])
            hashed_pass = hash_passkey(passkey)
            match_found = False

            for item in entries:
                if item["encrypted_text"] == encrypted_text and item["passkey"] == hashed_pass:
                    try:
                        decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                        st.success("✅ Decrypted Data:")
                        st.code(decrypted, language="text")
                        st.session_state.failed_attempts = 0
                        match_found = True
                        break
                    except:
                        pass

            if not match_found:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect credentials! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + 30  # 30 seconds lock
                    st.warning("🚫 Too many attempts. Locked for 30 seconds.")
                    st.stop()
        else:
            st.error("⚠️ All fields are required!")

# ----- Login (to Reset Lockout) -----
elif choice == "Login":
    st.subheader("🔑 Admin Login (Reset Lockout)")
    admin_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if not admin_pass:
            st.error("⚠️ Please enter the admin password")
        else:
            admin_hash = load_or_create_admin_hash()
            if hash_passkey(admin_pass) == admin_hash:
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = 0
                st.success("✅ Reauthorized. Lockout cleared.")
                
                # Add option to change admin password
                if st.checkbox("Change Admin Password"):
                    new_pass = st.text_input("New Admin Password:", type="password")
                    confirm_pass = st.text_input("Confirm New Password:", type="password")
                    
                    if st.button("Update Password"):
                        if new_pass != confirm_pass:
                            st.error("❌ Passwords do not match")
                        else:
                            is_valid, msg = validate_password(new_pass)
                            if not is_valid:
                                st.error(f"❌ {msg}")
                            else:
                                new_hash = hash_passkey(new_pass)
                                with open(ADMIN_HASH_FILE, "w") as f:
                                    f.write(new_hash)
                                st.success("✅ Admin password updated successfully")
                fake_rerun()
            else:
                st.error("❌ Incorrect master password.")
                # Log failed admin login attempt
                log_security_event("Failed admin login attempt")