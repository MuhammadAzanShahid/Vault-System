import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import zipfile
import os
import shutil

SERVER_URL = 'http://127.0.0.1:5000/api/upload'
USER_KEY = 'your_key'  # App mein input dalo


def compress_folder(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                z.write(full_path, arcname)


def upload_folder():
    folder = filedialog.askdirectory()
    if not folder:
        return

    zip_path = 'temp_zip.zip'
    compress_folder(folder, zip_path)

    try:
        with open(zip_path, 'rb') as f:
            files = {'file': f}
            r = requests.post(SERVER_URL, files=files)
        if r.status_code == 200:
            messagebox.showinfo("Success", "Folder uploaded and synced!")
        else:
            messagebox.showerror("Error", r.json()['error'])
    except Exception as e:
        messagebox.showerror("Error", str(e))
    os.remove(zip_path)


# GUI
root = tk.Tk()
root.title("Vault App")
root.geometry("400x200")

tk.Label(root, text="Select Folder to Sync").pack(pady=20)
tk.Button(root, text="Browse & Upload", command=upload_folder).pack(pady=10)

root.mainloop()