import json
import os
import random
import string
import time
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog, Toplevel, Text, Scrollbar
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.style import Style

VAULT_FILE = ".vault._data.11"
LOG_FILE = "._vaultlog.88"
PANIC_FILE = ".pp.98_data.23"
AUTO_LOCK_TIME = 60  # 1 minutes
MAX_ATTEMPTS = 3

# --- Encryption Helper Functions ---
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(json.dumps(data).encode()) + encryptor.finalize()
    return salt + iv + ct

def decrypt_data(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ct = encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return json.loads(decryptor.update(ct) + decryptor.finalize())

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

# --- GUI ---
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("<log101>")
        self.passwords = {}
        self.master_password = None
        self.last_activity = time.time()
        self.categories = set()
        self.panic_password = load_panic_password()

        self.style = Style(theme='solar')
        self.style.configure('TButton', font=('Courier', 9), borderradius=10, padding=5)

        self.setup_ui()
        self.init_login()
        self.start_auto_lock_timer()

    def setup_ui(self):
        self.frame = tb.Frame(self.root, padding=10)
        self.frame.pack(fill=BOTH, expand=YES)

        self.category_var = tk.StringVar()
        self.category_combo = tb.Combobox(self.frame, textvariable=self.category_var)
        self.category_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_list())
        self.category_combo.pack(fill=X, pady=(0, 10))

        self.search_var = tk.StringVar()
        self.search_entry = tb.Entry(self.frame, textvariable=self.search_var)
        self.search_entry.pack(fill=X, pady=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.filter_list)

        self.listbox = tk.Listbox(self.frame, font=("Courier", 10), height=10, bg="#2e2e2e", fg="#d4d4d4")
        self.listbox.pack(fill=BOTH, expand=YES, pady=(0, 10))

        btn_frame = tb.Frame(self.frame)
        btn_frame.pack(fill=X, pady=5)

        tb.Button(btn_frame, text="új felvétel", bootstyle=SUCCESS, command=self.add_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="megtekintés", bootstyle=INFO, command=self.view_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="másolás", bootstyle=INFO, command=self.copy_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="törlés", bootstyle=DANGER, command=self.delete_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="módosítás", bootstyle=INFO, command=self.modify_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="jelszógenerátor", bootstyle=SECONDARY, command=self.generate_password).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="export", bootstyle=WARNING, command=self.export_data).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="import", bootstyle=PRIMARY, command=self.import_data).pack(side=LEFT, expand=YES, padx=2)
        tb.Button(btn_frame, text="önvédelmi mód", bootstyle=DANGER, command=self.set_panic_password).pack(side=LEFT, expand=YES, padx=2)

        self.skin_var = tk.StringVar(value="solar")
        self.skin_combo = tb.Combobox(self.frame, textvariable=self.skin_var, values=["darkly", "solar", "minty"])
        self.skin_combo.bind("<<ComboboxSelected>>", self.change_skin)
        self.skin_combo.pack(fill=X, pady=(0, 10))

        self.root.bind_all("<Any-KeyPress>", self.reset_timer)
        self.root.bind_all("<Any-Button>", self.reset_timer)

    def init_login(self):
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            master_pw = simpledialog.askstring("Mesterjelszó", "Add meg a mesterjelszavad:", show='*')
            if not master_pw:
                self.root.destroy()
                return
            if master_pw == self.panic_password:
                self.lockdown_trigger()
                return
            try:
                self.passwords = load_passwords(master_pw)
                self.master_password = master_pw
                self.refresh_list()
                log_event("Sikeres bejelentkezés")
                return
            except Exception:
                attempts += 1
                messagebox.showerror("Hiba", f"Helytelen mesterjelszó ({attempts}/{MAX_ATTEMPTS})")

        log_event("Túl sok hibás bejelentkezési próbálkozás")
        messagebox.showwarning("Zárolva", "Túl sok hibás próbálkozás. A vault zárolva lett.")
        self.root.destroy()

    def set_panic_password(self):
        new_panic_pw = simpledialog.askstring("Önvédelmi jelszó", "Add meg az önvédelmi jelszavad:", show='*')
        if new_panic_pw:
            if new_panic_pw == self.master_password:
                messagebox.showerror("Hiba", "Az önvédelmi jelszó nem lehet azonos a mesterjelszóval.")
                return
            self.panic_password = new_panic_pw
            save_panic_password(new_panic_pw)
            messagebox.showinfo("Beállítva", "Önvédelmi jelszó beállítva.")

    def lockdown_trigger(self):
        log_event("Önvédelmi mód aktiválva")
        if os.path.exists(VAULT_FILE):
            os.remove(VAULT_FILE)
        self.root.destroy()

    def start_auto_lock_timer(self):
        def check_lock():
            while True:
                if time.time() - self.last_activity > AUTO_LOCK_TIME:
                    self.lock_vault()
                    break
                time.sleep(5)
        threading.Thread(target=check_lock, daemon=True).start()

    def reset_timer(self, event=None):
        self.last_activity = time.time()

    def lock_vault(self):
        log_event("Vault automatikusan zárolva")
        messagebox.showinfo("Zárolva", "Biztonsági okokból a vault zárolva lett.")
        self.play_lock_sound()
        self.logoff()

    def logoff(self):
        self.passwords = {}
        self.master_password = None
        self.last_activity = time.time()
        self.categories = set()
        self.listbox.delete(0, tk.END)
        self.init_login()

    def play_lock_sound(self):
        print("Playing lock sound...")

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        self.categories = {data['category'] for data in self.passwords.values() if 'category' in data}
        self.category_combo['values'] = ["All"] + sorted(list(self.categories))
        selected_cat = self.category_var.get()
        for site, data in self.passwords.items():
            if selected_cat in ("", "All") or data.get("category") == selected_cat:
                expiry_date = data.get("expiry_date")
                if expiry_date:
                    try:
                        expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d")
                        if datetime.now() > expiry_date:
                            site = f"{site} (LEJÁRT)"
                    except ValueError:
                        pass
                self.listbox.insert(tk.END, site)

    def filter_list(self, event=None):
        search_term = self.search_var.get().lower()
        self.listbox.delete(0, tk.END)
        selected_cat = self.category_var.get()
        for site, data in self.passwords.items():
            if (selected_cat in ("", "All") or data.get("category") == selected_cat) and \
               (search_term in site.lower() or search_term in data.get("category", "").lower()):
                expiry_date = data.get("expiry_date")
                if expiry_date:
                    try:
                        expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d")
                        if datetime.now() > expiry_date:
                            site = f"{site} (LEJÁRT)"
                    except ValueError:
                        pass
                self.listbox.insert(tk.END, site)

    def add_password(self):
        def save_new():
            site = site_entry.get().strip()
            pw = pw_entry.get().strip()
            category = cat_entry.get().strip() or "General"
            note = note_area.get("1.0", tk.END).strip()
            expiry_date = expiry_entry.get().strip()

            if not site or not pw:
                messagebox.showerror("Hiba", "A szolgáltatás és jelszó mezők kötelezőek.")
                return

            password_data = {"password": pw, "category": category, "note": note}
            if expiry_date:
                password_data["expiry_date"] = expiry_date

            self.passwords[site] = password_data
            save_passwords(self.passwords, self.master_password)
            self.refresh_list()
            log_event(f"Új jelszó hozzáadva: {site}")
            add_win.destroy()

        def generate_pw():
            chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(chars) for _ in range(12))
            pw_entry.delete(0, tk.END)
            pw_entry.insert(0, password)

        add_win = Toplevel(self.root)
        add_win.title("Új jelszó hozzáadása")
        add_win.geometry("400x450")
        add_win.resizable(False, False)

        tb.Label(add_win, text="Szolgáltatás neve:").pack(pady=(10, 0))
        site_entry = tb.Entry(add_win)
        site_entry.pack(fill=X, padx=20)

        tb.Label(add_win, text="Jelszó:").pack(pady=(10, 0))
        pw_entry = tb.Entry(add_win, show='*')
        pw_entry.pack(fill=X, padx=20)

        tb.Button(add_win, text="Jelszógenerátor", bootstyle=SECONDARY, command=generate_pw).pack(pady=(5, 10))

        tb.Label(add_win, text="Kategória:").pack()
        cat_entry = tb.Entry(add_win)
        cat_entry.pack(fill=X, padx=20)

        tb.Label(add_win, text="Lejárati dátum (pl. 2023-12-31):").pack(pady=(10, 0))
        expiry_entry = tb.Entry(add_win)
        expiry_entry.pack(fill=X, padx=20)

        tb.Label(add_win, text="Megjegyzés:").pack(pady=(10, 0))
        note_area = Text(add_win, wrap="word", height=5, font=("Courier", 10), bg="#1e1e1e", fg="#ffffff")
        note_area.pack(fill=X, padx=20, pady=(0, 10))

        tb.Button(add_win, text="Hozzáadás", bootstyle=SUCCESS, command=save_new).pack(pady=10)

    def view_password(self):
        selected = self.listbox.curselection()
        if not selected:
            return
        site = self.listbox.get(selected[0])
        data = self.passwords.get(site, {})

        expiry_date = data.get("expiry_date")
        if expiry_date:
            try:
                expiry_date = datetime.strptime(expiry_date, "%Y-%m-%d")
                if datetime.now() > expiry_date:
                    messagebox.showerror("Lejárt", "Ez a jelszó lejárt.")
                    return
            except ValueError:
                pass

        pw = data.get("password", '')
        note = data.get("note", '')
        messagebox.showinfo(site, f"Jelszó: {pw}\n\nMegjegyzés: {note}")
        log_event(f"Jelszó megtekintve: {site}")

    def copy_password(self):
        selected = self.listbox.curselection()
        if not selected:
            return
        site = self.listbox.get(selected[0])
        pw = self.passwords.get(site, {}).get("password", '')
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        messagebox.showinfo("Másolva", f"A jelszó vágólapra másolva: {site}")
        log_event(f"Jelszó másolva: {site}")

    def delete_password(self):
        selected = self.listbox.curselection()
        if not selected:
            return
        site = self.listbox.get(selected[0])
        if messagebox.askyesno("Megerősítés", f"Törlöd ezt: {site}?"):
            del self.passwords[site]
            self.refresh_list()
            save_passwords(self.passwords, self.master_password)
            log_event(f"Jelszó törölve: {site}")

    def generate_password(self):
        length = simpledialog.askinteger("Hossz", "Hány karakteres legyen a jelszó?", initialvalue=12)
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length or 12))
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Jelszó generálva", f"A jelszót a vágólapra másoltuk:\n{password}")
        log_event("Jelszó generálva")

    def export_data(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON fájl", "*.json")])
        if not path:
            return
        with open(path, "w") as f:
            json.dump(self.passwords, f, indent=4)
        log_event(f"Jelszavak exportálva: {path}")

    def import_data(self):
        path = filedialog.askopenfilename(filetypes=[("JSON fájl", "*.json")])
        if not path:
            return
        try:
            with open(path, "r") as f:
                imported = json.load(f)
                self.passwords.update(imported)
                save_passwords(self.passwords, self.master_password)
                self.refresh_list()
                log_event(f"Jelszavak importálva: {path}")
        except Exception as e:
            messagebox.showerror("Hiba", f"Nem sikerült importálni: {e}")
            log_event(f"Import hiba: {e}")

    def modify_password(self):
        selected = self.listbox.curselection()
        if not selected:
            return
        site = self.listbox.get(selected[0])
        data = self.passwords.get(site, {})

        def save_modified():
            pw = pw_entry.get().strip()
            category = cat_entry.get().strip() or "General"
            note = note_area.get("1.0", tk.END).strip()
            expiry_date = expiry_entry.get().strip()

            if not pw:
                messagebox.showerror("Hiba", "A jelszó mező kötelező.")
                return

            password_data = {"password": pw, "category": category, "note": note}
            if expiry_date:
                password_data["expiry_date"] = expiry_date

            self.passwords[site] = password_data
            save_passwords(self.passwords, self.master_password)
            self.refresh_list()
            log_event(f"Jelszó módosítva: {site}")
            modify_win.destroy()

        modify_win = Toplevel(self.root)
        modify_win.title("Jelszó módosítása")
        modify_win.geometry("400x450")
        modify_win.resizable(False, False)

        tb.Label(modify_win, text="Szolgáltatás neve:").pack(pady=(10, 0))
        tb.Label(modify_win, text=site).pack()

        tb.Label(modify_win, text="Jelszó:").pack(pady=(10, 0))
        pw_entry = tb.Entry(modify_win, show='*')
        pw_entry.insert(0, data.get("password", ""))
        pw_entry.pack(fill=X, padx=20)

        tb.Label(modify_win, text="Kategória:").pack(pady=(10, 0))
        cat_entry = tb.Entry(modify_win)
        cat_entry.insert(0, data.get("category", ""))
        cat_entry.pack(fill=X, padx=20)

        tb.Label(modify_win, text="Lejárati dátum (pl. 2023-12-31):").pack(pady=(10, 0))
        expiry_entry = tb.Entry(modify_win)
        expiry_entry.insert(0, data.get("expiry_date", ""))
        expiry_entry.pack(fill=X, padx=20)

        tb.Label(modify_win, text="Megjegyzés:").pack(pady=(10, 0))
        note_area = Text(modify_win, wrap="word", height=5, font=("Courier", 10), bg="#1e1e1e", fg="#ffffff")
        note_area.insert("1.0", data.get("note", ""))
        note_area.pack(fill=X, padx=20, pady=(0, 10))

        tb.Button(modify_win, text="Módosítás", bootstyle=SUCCESS, command=save_modified).pack(pady=10)

    def change_skin(self, event=None):
        skin = self.skin_var.get()
        self.style = Style(theme=skin)
        log_event(f"Skin váltva: {skin}")

if __name__ == "__main__":
    root = tb.Window(themename="solar")
    app = PasswordManagerApp(root)
    root.mainloop()
