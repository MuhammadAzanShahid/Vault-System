# main.py - Vault Desktop Client (Final Version)
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Listbox, Scrollbar
import customtkinter as ctk
from cryptography.fernet import Fernet
import zipfile
import base64
import time
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# === Secure Key Derivation ===
def get_key_from_password(password: str) -> bytes:
    salt = b'saltybackup2025__'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key


class VaultDesktopApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("Vault Desktop Client v2.0")
        self.root.geometry("1150x760")
        self.root.minsize(950, 650)

        # Cloud
        self.server_url = ctk.StringVar(value="http://127.0.0.1:5000")
        self.api_key = ctk.StringVar()
        self.connected = False
        self.cloud_backups = []

        # Backup
        self.backup_sources = []
        self.save_location = ""

        # Restore
        self.enc_file_path = ""
        self.restore_destination = ""

        self.setup_ui()

    def setup_ui(self):
        # Header
        header = ctk.CTkFrame(self.root, height=70)
        header.pack(fill="x", padx=20, pady=(15, 10))
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="Vault Desktop Client", font=ctk.CTkFont(size=30, weight="bold")).pack(side="left", padx=20)
        ctk.CTkLabel(header, text="Secure • Encrypted • Cloud Sync", font=ctk.CTkFont(size=14), text_color="#94a3b8").pack(side="right", padx=20)

        tabview = ctk.CTkTabview(self.root)
        tabview.pack(fill="both", expand=True, padx=20, pady=10)
        tabview.add("Backup")
        tabview.add("Restore")
        tabview.add("Cloud Sync")

        # ==================== BACKUP TAB ====================
        backup_frame = tabview.tab("Backup")
        ctk.CTkLabel(backup_frame, text="Create Encrypted Backup", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(30, 15))

        ctk.CTkButton(backup_frame, text="Add Files or Folders", height=50, fg_color="#3b82f6",
                      font=ctk.CTkFont(size=16, weight="bold"), command=self.add_backup_items).pack(pady=15, padx=120, fill="x")

        list_frame = ctk.CTkFrame(backup_frame)
        list_frame.pack(fill="both", expand=True, padx=120, pady=10)
        self.source_listbox = Listbox(list_frame, bg="#1e293b", fg="#e2e8f0", font=("Consolas", 11), selectbackground="#3b82f6")
        self.source_listbox.pack(side="left", fill="both", expand=True)
        sb1 = Scrollbar(list_frame)
        sb1.pack(side="right", fill="y")
        self.source_listbox.config(yscrollcommand=sb1.set)
        sb1.config(command=self.source_listbox.yview)

        ctk.CTkButton(backup_frame, text="Remove Selected", fg_color="#ef4444", command=self.remove_selected_item).pack(pady=5)

        ctk.CTkButton(backup_frame, text="Select Save Location", height=45, fg_color="#2563eb",
                      command=self.select_save_location).pack(pady=12, padx=120, fill="x")
        self.dest_label = ctk.CTkLabel(backup_frame, text="No save location selected", text_color="#f87171")
        self.dest_label.pack(pady=5)

        self.backup_btn = ctk.CTkButton(backup_frame, text="Create Encrypted Backup", height=55, fg_color="#16a34a",
                                        font=ctk.CTkFont(size=18, weight="bold"), command=self.create_backup, state="disabled")
        self.backup_btn.pack(pady=30, padx=200, fill="x")

        # ==================== RESTORE TAB ====================
        restore_frame = tabview.tab("Restore")
        ctk.CTkLabel(restore_frame, text="Restore from Encrypted Backup", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(30, 20))

        ctk.CTkButton(restore_frame, text="Select .enc.zip File", height=45, fg_color="#dc2626",
                      command=self.select_enc_file).pack(pady=12, padx=120, fill="x")
        self.enc_label = ctk.CTkLabel(restore_frame, text="No file selected", text_color="#f87171")
        self.enc_label.pack(pady=5)

        ctk.CTkButton(restore_frame, text="Select Restore Destination", height=45, fg_color="#dc2626",
                      command=self.select_restore_dest).pack(pady=12, padx=120, fill="x")
        self.restore_dest_label = ctk.CTkLabel(restore_frame, text="No destination selected", text_color="#f87171")
        self.restore_dest_label.pack(pady=5)

        self.restore_btn = ctk.CTkButton(restore_frame, text="Decrypt & Restore", height=55, fg_color="#7c3aed",
                                         font=ctk.CTkFont(size=18, weight="bold"), command=self.restore_backup, state="disabled")
        self.restore_btn.pack(pady=30, padx=200, fill="x")

        # ==================== CLOUD TAB ====================
        cloud_frame = tabview.tab("Cloud Sync")
        ctk.CTkLabel(cloud_frame, text="Connect to Your Vault Cloud", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(25, 15))

        entry_frame = ctk.CTkFrame(cloud_frame)
        entry_frame.pack(pady=10, padx=120, fill="x")
        ctk.CTkLabel(entry_frame, text="Server URL:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=20)
        ctk.CTkEntry(entry_frame, textvariable=self.server_url, height=40).pack(pady=5, padx=20, fill="x")

        ctk.CTkLabel(entry_frame, text="Your API Key (from Dashboard):", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=20, pady=(15,0))
        ctk.CTkEntry(entry_frame, textvariable=self.api_key, show="*", height=40).pack(pady=5, padx=20, fill="x")

        ctk.CTkButton(entry_frame, text="Connect & Refresh Backups", fg_color="#16a34a", height=50,
                      font=ctk.CTkFont(size=16, weight="bold"), command=self.connect_to_cloud).pack(pady=20)

        self.status_label = ctk.CTkLabel(cloud_frame, text="Not connected", text_color="#ef4444", font=ctk.CTkFont(size=15, weight="bold"))
        self.status_label.pack(pady=10)

        # Cloud Backups List
        cloud_list_frame = ctk.CTkFrame(cloud_frame)
        cloud_list_frame.pack(fill="both", expand=True, padx=120, pady=15)
        self.backup_listbox = Listbox(cloud_list_frame, bg="#1e293b", fg="#e2e8f0", font=("Consolas", 11), selectbackground="#3b82f6")
        self.backup_listbox.pack(side="left", fill="both", expand=True)
        sb2 = Scrollbar(cloud_list_frame)
        sb2.pack(side="right", fill="y")
        self.backup_listbox.config(yscrollcommand=sb2.set)
        sb2.config(command=self.backup_listbox.yview)

        ctk.CTkButton(cloud_frame, text="Download Selected Backup", fg_color="#ea580c", height=50,
                      font=ctk.CTkFont(size=16, weight="bold"), command=self.download_selected_backup).pack(pady=15)

    # ==================== BACKUP FUNCTIONS ====================
    def add_backup_items(self):
        choice = messagebox.askyesnocancel("Add Items", "Yes → Select Folder\nNo → Select Files\nCancel → Cancel")
        if choice is None: return
        if choice:
            folder = filedialog.askdirectory(title="Select Folder to Backup")
            if folder and folder not in self.backup_sources:
                self.backup_sources.append(folder)
                self.source_listbox.insert(tk.END, f"[Folder] {os.path.basename(folder)}")
        else:
            files = filedialog.askopenfilenames(title="Select Files to Backup")
            for f in files:
                if f not in self.backup_sources:
                    self.backup_sources.append(f)
                    self.source_listbox.insert(tk.END, f"[File] {os.path.basename(f)}")
        self.update_backup_button()

    def remove_selected_item(self):
        sel = self.source_listbox.curselection()
        if sel:
            idx = sel[0]
            self.source_listbox.delete(idx)
            self.backup_sources.pop(idx)
            self.update_backup_button()

    def update_backup_button(self):
        if self.backup_sources and self.save_location:
            self.backup_btn.configure(state="normal")
        else:
            self.backup_btn.configure(state="disabled")

    def select_save_location(self):
        folder = filedialog.askdirectory(title="Where to Save Backup?")
        if folder:
            self.save_location = folder
            self.dest_label.configure(text=f"Save: {os.path.basename(folder)}", text_color="#86efac")
            self.update_backup_button()

    def create_backup(self):
        if not self.backup_sources:
            messagebox.showwarning("Empty", "Pehle files/folders select karo!")
            return

        password = simpledialog.askstring("Password", "Enter strong password (8+ characters):", show='*')
        if not password or len(password) < 8:
            messagebox.showerror("Error", "Password must be 8+ characters!")
            return

        timestamp = int(time.time())
        zip_path = os.path.join(self.save_location, f"vault_backup_{timestamp}.zip")
        enc_path = os.path.join(self.save_location, f"vault_backup_{timestamp}.enc.zip")

        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
                for item in self.backup_sources:
                    if os.path.isfile(item):
                        z.write(item, os.path.basename(item))
                    else:
                        for root, _, files in os.walk(item):
                            for file in files:
                                full_path = os.path.join(root, file)
                                arcname = os.path.relpath(full_path, item)
                                z.write(full_path, arcname)

            key = get_key_from_password(password)
            fernet = Fernet(key)
            with open(zip_path, 'rb') as f:
                encrypted = fernet.encrypt(f.read())
            with open(enc_path, 'wb') as f:
                f.write(encrypted)
            os.remove(zip_path)

            messagebox.showinfo("Success", f"Encrypted backup created!\n{os.path.basename(enc_path)}")

            if self.connected and messagebox.askyesno("Upload", "Upload to cloud?"):
                self.upload_to_cloud(enc_path)

            self.backup_sources.clear()
            self.source_listbox.delete(0, tk.END)
            self.update_backup_button()

        except Exception as e:
            messagebox.showerror("Failed", f"Backup failed:\n{str(e)}")

    # ==================== RESTORE ====================
    def select_enc_file(self):
        file = filedialog.askopenfilename(title="Select Backup", filetypes=[("Vault Backup", "*.enc.zip")])
        if file:
            self.enc_file_path = file
            self.enc_label.configure(text=os.path.basename(file), text_color="#86efac")
            self.check_restore_ready()

    def select_restore_dest(self):
        folder = filedialog.askdirectory(title="Restore Destination")
        if folder:
            self.restore_destination = folder
            self.restore_dest_label.configure(text=os.path.basename(folder), text_color="#86efac")
            self.check_restore_ready()

    def check_restore_ready(self):
        if self.enc_file_path and self.restore_destination:
            self.restore_btn.configure(state="normal")
        else:
            self.restore_btn.configure(state="disabled")

    def restore_backup(self):
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if not password: return

        try:
            key = get_key_from_password(password)
            fernet = Fernet(key)
            with open(self.enc_file_path, 'rb') as f:
                decrypted = fernet.decrypt(f.read())

            temp_zip = self.enc_file_path.replace(".enc.zip", "_restored.zip")
            with open(temp_zip, 'wb') as f:
                f.write(decrypted)

            with zipfile.ZipFile(temp_zip, 'r') as z:
                z.extractall(self.restore_destination)

            os.remove(temp_zip)
            messagebox.showinfo("Success", f"Restore completed!\nFiles restored to:\n{self.restore_destination}")

            self.enc_file_path = self.restore_destination = ""
            self.enc_label.configure(text="No file selected", text_color="#f87171")
            self.restore_dest_label.configure(text="No destination", text_color="#f87171")
            self.check_restore_ready()

        except Exception as e:
            messagebox.showerror("Error", "Wrong password or file corrupted!")

    # ==================== CLOUD FUNCTIONS (FULLY COMPATIBLE WITH YOUR SERVER) ====================
    def connect_to_cloud(self):
        url = self.server_url.get().strip().rstrip("/")
        key = self.api_key.get().strip()
        if not url or not key:
            messagebox.showerror("Error", "Server URL aur API Key daalo!")
            return

        try:
            headers = {"X-API-Key": key}
            r = requests.get(f"{url}/api/backups", headers=headers, timeout=15)
            r.raise_for_status()
            data = r.json()

            self.connected = True
            self.status_label.configure(text=f"Connected: {data.get('username', 'User')} • {data.get('total_size_mb', 0)} MB", text_color="#86efac")

            self.cloud_backups = data.get("backups", [])
            self.backup_listbox.delete(0, tk.END)
            for b in self.cloud_backups:
                self.backup_listbox.insert(tk.END, f"{b['name']} • {b['size']} MB • {b['time']}")

            messagebox.showinfo("Connected", "Successfully connected to your Vault Cloud!")

        except Exception as e:
            self.connected = False
            self.status_label.configure(text="Connection Failed", text_color="#ef4444")
            messagebox.showerror("Error", f"Connection failed:\n{str(e)}")

    def upload_to_cloud(self, file_path):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Pehle connect karo!")
            return

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                headers = {'X-API-Key': self.api_key.get()}
                r = requests.post(f"{self.server_url.get().rstrip('/')}/api/upload_backup", files=files, headers=headers, timeout=120)
                r.raise_for_status()

            messagebox.showinfo("Success", "Backup uploaded to cloud!")
            self.connect_to_cloud()

        except Exception as e:
            messagebox.showerror("Upload Failed", str(e))

    def download_selected_backup(self):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Connect karo pehle!")
            return
        sel = self.backup_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select", "Koi backup select karo!")
            return

        backup = self.cloud_backups[sel[0]]
        save_path = filedialog.asksaveasfilename(initialfile=backup['name'], defaultextension=".enc.zip")
        if not save_path: return

        try:
            url = f"{self.server_url.get().rstrip('/')}/api/download_backup/{backup['name']}"
            headers = {"X-API-Key": self.api_key.get()}
            r = requests.get(url, headers=headers, stream=True, timeout=120)
            r.raise_for_status()

            with open(save_path, 'wb') as f:
                for chunk in r.iter_content(8192):
                    f.write(chunk)

            messagebox.showinfo("Downloaded", f"Backup downloaded!\n{save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Download failed:\n{str(e)}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = VaultDesktopApp()
    app.run()