
# 🔐 PyVault — Minimal AES + SHA-256 Password Manager

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)  

**PyVault** is a lightweight, single-file password manager built in Python for educational purposes.  
It uses **PBKDF2-HMAC-SHA256** to derive a strong key from a master password and **AES-GCM** for authenticated encryption of your vault.

> ⚠️ **Disclaimer:** This is a proof-of-concept for learning cryptography in Python.  
Not intended for production use without additional hardening.

---

## ✨ Features

- 🔑 **Master Password Protection** — Key derived with PBKDF2-HMAC-SHA256  
- 🔒 **Secure Encryption** — AES-GCM for confidentiality + integrity  
- 📦 **Single File** — Easy to read, modify, and run locally  
- 🛠 **Interactive CLI** — Simple commands to add, list, get, delete, and export entries  
- ♻️ **Change Master Password** without losing existing data

---

## 📂 Repository Structure

```

p vault/
├─ password\_manager.py    # Main application
├─ requirements.txt       # Dependencies
└─ README.md              # Project documentation

````

---

## 🚀 Quickstart

**1. Clone the repo**
```bash
git clone https://github.com/<your-username>/pyvault.git
cd pyvault
````

**2. Create a virtual environment & install dependencies**

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**3. Run the application**

```bash
python password_manager.py
```

---

## 🖥 Usage

When you run `password_manager.py`, you can use these commands:

| Command         | Description                                |
| --------------- | ------------------------------------------ |
| `init`          | Create a new encrypted vault               |
| `unlock`        | Unlock the vault with your master password |
| `add`           | Add a new entry                            |
| `get`           | Retrieve an entry                          |
| `list`          | List all stored entries                    |
| `del`           | Delete an entry                            |
| `change-master` | Change the master password                 |
| `export`        | Export vault to JSON                       |
| `lock`          | Lock the vault                             |
| `exit`          | Exit the program                           |

---

## 🔐 Security Notes

* **Key Derivation:** PBKDF2-HMAC-SHA256 with high iteration count slows brute-force attempts.
* **Encryption:** AES-GCM ensures both confidentiality and integrity.
* **Storage:** Vault is stored encrypted on disk; without the master password, it’s unreadable.
* **Threat Model:** Protects against offline file theft; does not defend against malware, keyloggers, or memory scraping.

---

## 📜 License

This project is licensed under the **MIT License** — free to use, modify, and share.

---

## ⭐ Contribute

Pull requests and forks are welcome.
If you have ideas to improve security, CLI UX, or add features, open an issue.

---

## 📣 Share

If you found this helpful, give it a ⭐ on GitHub and share it with your friends!

```

