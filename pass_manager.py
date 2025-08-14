#!/usr/bin/env python3
"""
PyVault — Minimal AES + SHA-256 Password Manager
License: MIT
"""

import os
import json
import base64
import getpass
import secrets
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ===== Config =====
VAULT_FILE = "vault.json"
ITERATIONS = 200_000
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16

# ===== Utils =====
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the master password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt data using AES-GCM."""
    nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using AES-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ===== Vault Management =====
def init_vault():
    """Initialize a new vault."""
    if os.path.exists(VAULT_FILE):
        print("Vault already exists. Delete it first to re-init.")
        return
    master_pwd = getpass.getpass("Create master password: ")
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key(master_pwd, salt)
    vault_data = {}
    nonce, ciphertext = encrypt(key, json.dumps(vault_data).encode())
    data = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "vault": base64.b64encode(ciphertext).decode(),
    }
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f)
    print("Vault initialized.")

def load_vault_prompt() -> Tuple[Dict[str, Any], bytes, Dict[str, Any]]:
    """Prompt for master password and return (vault_dict, key, store_dict)."""
    if not os.path.exists(VAULT_FILE):
        print("No vault found. Run 'init' to create one.")
        raise SystemExit
    with open(VAULT_FILE, "r") as f:
        store = json.load(f)
    master_pwd = getpass.getpass("Enter master password: ")
    salt = base64.b64decode(store["salt"])
    key = derive_key(master_pwd, salt)
    nonce = base64.b64decode(store["nonce"])
    ciphertext = base64.b64decode(store["vault"])
    try:
        decrypted = decrypt(key, nonce, ciphertext)
    except Exception:
        print("Invalid password or corrupted vault.")
        raise SystemExit
    vault_dict = json.loads(decrypted.decode())
    return vault_dict, key, store

def save_vault(vault_dict: Dict[str, Any], key: bytes, store: Dict[str, Any]):
    """Save the updated vault."""
    nonce, ciphertext = encrypt(key, json.dumps(vault_dict).encode())
    store["nonce"] = base64.b64encode(nonce).decode()
    store["vault"] = base64.b64encode(ciphertext).decode()
    with open(VAULT_FILE, "w") as f:
        json.dump(store, f)
    print("Vault saved.")

# ===== CLI Commands =====
def add_entry():
    vault, key, store = load_vault_prompt()
    name = input("Entry name: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    vault[name] = {"username": username, "password": password}
    save_vault(vault, key, store)

def get_entry():
    vault, _, _ = load_vault_prompt()
    name = input("Entry name: ")
    entry = vault.get(name)
    if entry:
        print(f"Username: {entry['username']}\nPassword: {entry['password']}")
    else:
        print("Entry not found.")

def list_entries():
    vault, _, _ = load_vault_prompt()
    for name in vault:
        print(name)

def delete_entry():
    vault, key, store = load_vault_prompt()
    name = input("Entry name to delete: ")
    if name in vault:
        del vault[name]
        save_vault(vault, key, store)
    else:
        print("Entry not found.")

# ===== Main CLI =====
def main():
    while True:
        print("\nCommands: init, add, get, list, del, exit")
        cmd = input("> ").strip().lower()
        if cmd == "init":
            init_vault()
        elif cmd == "add":
            add_entry()
        elif cmd == "get":
            get_entry()
        elif cmd == "list":
            list_entries()
        elif cmd == "del":
            delete_entry()
        elif cmd == "exit":
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()
