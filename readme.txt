Password Manager

A simple but secure **desktop password manager** written in Python with **AES encryption**, **panic password protection**, and a **modern Tkinter/ttkbootstrap GUI**.

---

## ✨ Features

* **Master password protection** – all data is encrypted with AES using PBKDF2 key derivation.
* **Password categories** – organize accounts by category.
* **Password generator** – quickly generate random strong passwords.
* **Panic password** – entering a special password wipes all stored data.
* **Auto-lock** – vault locks automatically after inactivity.
* **Modify / Delete entries** – full control over stored credentials.
* **Import / Export** – backup and restore your encrypted vault.
* **Logs** – access logs are recorded in a hidden file.
* **Modern UI** – built with `ttkbootstrap` for a clean look.

---

## 📂 Project Structure

```
password_manager/
│── main.py              # Entry point (run this file)
│── gui.py               # Main Tkinter/ttkbootstrap user interface
│── crypto_utils.py      # AES encryption/decryption + PBKDF2
│── storage.py           # File operations (vault, panic password, logs)
│── config.py            # Settings (filenames, timeout, attempts)
```

---

## 🚀 Usage

### 1. Install requirements

Make sure you have Python **3.9+** installed, then install dependencies:

```bash
pip install cryptography ttkbootstrap
```

### 2. Run the app

```bash
python main.py
```

### 3. First run

* When launched for the first time, the vault will be empty.
* You will be prompted to set a **master password**.
* Optionally, you can set a **panic password** (a fake password that erases the vault if used).

### 4. Managing entries

* Use **Add Password** to store credentials (site/app, username, password, category).
* Select entries to **View**, **Modify**, or **Delete**.
* Copy credentials directly from the app.

### 5. Import / Export

* Export your vault as an encrypted JSON file.
* Import back using the same master password.

---

## ⚠️ Security Notes

* The vault file (`.vault._data.11`) and panic password file are stored **locally**.
* All sensitive data is encrypted with **AES-256 (CFB mode)** using a derived key from the master password.
* Logs are written to a hidden file (`._vaultlog.88`).
* The vault **auto-locks** after inactivity (configurable).
* If you forget the **master password**, there is no recovery method.

---

## 🛠️ Configuration

You can adjust settings in `config.py`:

```python
VAULT_FILE = ".vault._data.11"
LOG_FILE = "._vaultlog.88"
PANIC_FILE = ".pp.98_data.23"
AUTO_LOCK_TIME = 60   # seconds
MAX_ATTEMPTS = 3
```

---

## 📌 Requirements

* Python 3.9+
* [cryptography](https://pypi.org/project/cryptography/)
* [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap)

---

## 📜 License

This project is provided for **educational and personal use**.
Use at your own risk – the author is **not responsible for data loss**.

