import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# ----- Utility Functions -----
DATA_FILE = "data.json"
KEY_FILE = "key.key"

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

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            encrypted_text = cipher.encrypt(user_data.encode()).decode()
            hashed_pass = hash_passkey(passkey)

            # Store under user
            if username not in stored_data:
                stored_data[username] = []
            stored_data[username].append({
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            })
            save_data(stored_data)
            st.success("✅ Data securely stored.")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Please fill all fields.")

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
        if admin_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0
            st.success("✅ Reauthorized. Lockout cleared.")
            fake_rerun()
        else:
            st.error("❌ Incorrect master password.")
            
            
            # Admin can log in via "Login" tab to reset lockout.


# import streamlit as st
# import hashlib
# import json
# import os
# import time
# from cryptography.fernet import Fernet 


# # -------Utility Functions -------
# DATA_FILE = "data.json"

# KEY_FILE = "key.key"

# # Load and create encryption key

# def load_or_create_key():

#    if os.path.exists(KEY_FILE):
      
#      with open(KEY_FILE, "wb")as f :
#         f.write(key)

#         return key

# # Load or initialize user data

# def load_data():

#     if os.path.exists(DATA_FILE):
#         with open(DATA_FILE, "r") as f:
#             return json.load(f)  

#     return {}

# # Save data to JSON 

# def save_data(data):

#     with open(DATA_FILE, "w") as f:
#         json.dump(data, f)


# # Hash a passkey

# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # ------Initialization-------

# cipher = Fernet(load_or_create_key())

# stored_data = load_data()

# # -------Session State-------
# if "username" not in st.session_state:
#     st.session_state.username = ""
# if "failed_attempts" not in st.session_state:
#       st.session_state.failed_attempts = 0  

# if "lockout_time" not in st.session_state:
#     st.session_state.lockout_time = 0

# if "authorized" not in st.session_state:
#     st.session_state.authorized = True

# # -------Handle Return manually

# if st.session_state.get("rerun_flag"):

#     st.session_state[rerun_flag] = False

#     st._set_query_params()

#     st.stop()

# def fake_rerun():
#     st.session_state["rerun_flag"] = True

#     st.stop()

# # -------UI--------
# st.title("🔐 Secure Data Encryption System (Multi-User +Persistent = Lockout)") 

# menu = ["Home","Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation",menu)

# # -------Home Page-------
# if choice == "Home":

#     st.subheader("🏠 Welcome")

#     st.write("Multi-User data encryption with passkey protection and lockout system.")

# # -------Store Data--------
# elif choice == "Store Data":

#     st.subheader("🔒 Store Data Securely")

#     username = st.text_input("Username:")

#     user_data = st.text_area("Enter Text to Encrypt:")    

#     passkey = st.text_input("Set a Passkey:",type = "password")

#     if st.button("Encrypt & save"):
#         if Username and user_data and passkey:

#             encrypt_text = cipher.encrypt(user_data.encode()).decode()
#             hashed_pass = hash_passkey(passkey)

# # ----------Store Under user
#             if username not in stored_data:

#                 stored_data[username] = []

#             stored_data[username].append({
#                 "encrypted_text": encrypted_text,
#                 "passkey":hashed_pass
#             })   
#             save_data(stored_data) 

#             st.success("✅ Data securely stored!") 

#             st.code(encrypt_text,language="text")

#         else:
#             st.error("❌ Please fill in all fields.")              

# # --------Retrieve Data -------

# elif choice == "Retrieve Data":
#     st.subheader("🔑 Retrieve Data")

# # --------Lockout Check -----

#     if st.session_state.failed_attempts >= 3:

#         remaining = int(st.session_state.lockout_time-time.time())
#         if remaining > 0:
#             st.error(f"🚫 Too many failed attempts.try again in {remaining} seconds.")

#             st.stop()
#         else:
#             st.session_state.failed_attempts = 0

#             st.session_state.lockout_time = 0

#     username = st.text_input("Username:")

#     encrypted_text = st.text_area("Paste Encrypted Text:")

#     passkey = st.text_input("Enter Passkey:",type="password")

#     if st.button("Decrypt"):

#         if username and encrypted_text and  passkey:
#             entries = stored_data.get(username,[])

#             hashed_pass = hash_passkey(passkey)

#             match_found = False

#             for item in entries:

#                 if item["encrypted_text"] == encrypted_text and item["passkey"] == hashed_pass:

#                     try:
#                         decrypted = cipher.decrypt(encrypted_text.encode()).decode()

#                         st.success("✅ Decrypted Data:")

#                         st.code(decrypted,language = "text")

#                         st.session_state.failed_attempts = 0

#                         match_found = True

#                         break

#                     except:

#                         pass

#             if not match_found:

#                st.session_state.failed_attempts += 1

#                remaining = 3 -st.session_state.failed_attempts

#                st.error(f"❌ Incorrect credentials! Attempts remaining:{remaining} ")   

#                if st.session_state.failed_attempts >= 3:

#                   st.session_state.lockout_time = time.time() + 30 # 30 seconds lock

#                   st.warning("🚫 Too many attempts. You are locked out for 30 seconds.")  

#                   st.stop()

#         else:
#             st.error("⚠️ All fields are required!.")          

# # ---Login(to Reset Lockout) ---

# elif choice == "Login":

#     st.subheader("⚠️ Admin login (Reset Lockout)")

#     admin_pass = st.text_input("Enter Master Password:",type="password")

#     if st.button("Login"):

#         if admin_pass == "admin123":

#             st.session_state.failed_attempts = 0

#             st.session_state.lockout_time = 0