import os, time, json
from config import VAULT_FILE, LOG_FILE, PANIC_FILE
from crypto_utils import encrypt_data, decrypt_data

def save_passwords(passwords, password):
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data(passwords, password))

def load_passwords(password):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
        return decrypt_data(encrypted, password)

def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def save_panic_password(password):
    with open(PANIC_FILE, "w") as f:
        f.write(password)

def load_panic_password():
    if os.path.exists(PANIC_FILE):
        with open(PANIC_FILE, "r") as f:
            return f.read().strip()
    return None
