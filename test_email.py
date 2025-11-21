from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import random          # <-- ADDED: For OTP generation
import smtplib
from email.mime.text import MIMEText
import hashlib
import requests
import zipfile
import shutil
import time

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # Secure key

# ================== CONFIG (PAKISTAN - NOV 2025) ==================
PCLOUD_USERNAME = 'muhammadazanshahid8@gmail.com'
PCLOUD_PASSWORD = '$Cm#qpt3urBcwM*'
PCLOUD_REGION = 'us'  # us or eu
SENDER_EMAIL = 'muhammadazanshahid8@gmail.com'
SENDER_PASSWORD = 'tvixttwiqiovthzc'  # 16 chars, NO SPACES!
VAULT_FOLDER = r'D:\projectss\vault 3.0'  # Raw string for space
REMOTE_PATH = '/vault.backup.enc'

# Create vault folder if not exists
os.makedirs(VAULT_FOLDER, exist_ok=True)

# ================== DATABASE ==================
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ================== PCLOUD AUTH & UPLOAD/DOWNLOAD ==================
def get_pcloud_auth():
    base = 'api' if PCLOUD_REGION == 'us' else 'eapi'
    url = f'https://{base}.pcloud.com/'
    r = requests.get(url + 'getdigest')
    data = r.json()
    if data['result'] != 0:
        raise Exception(f"pCloud error: {data['error']}")
    digest = data['digest']
    username_lower = PCLOUD_USERNAME.lower()
    sha1_user = hashlib.sha1(username_lower.encode()).hexdigest()
    sha1_pass = hashlib.sha1((PCLOUD_PASSWORD + sha1_user + digest).encode()).hexdigest()
    params = {
        'getauth': 1, 'logout': 1, 'username': PCLOUD_USERNAME,
        'digest': digest, 'passworddigest': sha1_pass
    }
    r = requests.get(url + 'userinfo', params=params)
    data = r.json()
    if data['result'] != 0:
        raise Exception(f"pCloud auth failed: {data['error']}")
    return data['auth']

def upload_to_pcloud(local_file):
    auth = get_pcloud_auth()
    base = 'api' if PCLOUD_REGION == 'us' else 'eapi'
    url = f'https://{base}.pcloud.com/uploadfile'
    params = {'auth': auth, 'path': REMOTE_PATH, 'renameifexists': 1}
    with open(local_file, 'rb') as f:
        files = {'file': f}
        r = requests.post(url, params=params, files=files, timeout=300)
    data = r.json()
    if data['result'] != 0:
        raise Exception(f"Upload failed: {data['error']}")

def download_from_pcloud(output_file):
    auth = get_pcloud_auth()
    base = 'api' if PCLOUD_REGION == 'us' else 'eapi'
    url = f'https://{base}.pcloud.com/getfilelink'
    params = {'auth': auth, 'path': REMOTE_PATH, 'forcedownload': 1}
    r = requests.get(url, params=params)
    data = r.json()
    if data['result'] != 0:
        raise Exception(f"Download link error: {data['error']}")
    host = data['hosts'][0]
    path = data['path']
    download_url = f'https://{host}{path}'
    with requests.get(download_url, stream=True) as r:
        r.raise_for_status()
        with open(output_file, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024*1024):
                f.write(chunk)

# ================== ZIP & ENCRYPTION ==================
def zip_vault(output_zip):
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(VAULT_FOLDER):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, VAULT_FOLDER)
                z.write(full_path, arcname)

def unzip_vault(zip_path):
    if os.path.exists(VAULT_FOLDER):
        shutil.rmtree(VAULT_FOLDER)
    os.makedirs(VAULT_FOLDER)
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(VAULT_FOLDER)

def encrypt_file(input_path, output_path, key):
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        i = 0
        while True:
            chunk = fin.read(1024*1024)
            if not chunk:
                break
            encrypted = bytearray(b ^ key_bytes[i % key_len] for i, b in enumerate(chunk))
            fout.write(encrypted)
            i += len(chunk)

def decrypt_file(input_path, output_path, key):
    encrypt_file(input_path, output_path, key)  # XOR is symmetric

# ================== SEND OTP (GMAIL - FULL DEBUG) ==================
def send_otp(email, otp):
    try:
        msg = MIMEText(f"""
        <h2>Vault App - Login OTP</h2>
        <p><b>OTP: {otp}</b></p>
        <p>Valid for 5 minutes.</p>
        <p>Time: {time.strftime('%Y-%m-%d %H:%M:%S PKT')}</p>
        <hr>
        <small>From: Vault App (Pakistan)</small>
        """, 'html')
        msg['Subject'] = 'Vault App - Your OTP'
        msg['From'] = SENDER_EMAIL
        msg['To'] = email

        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        server.set_debuglevel(1)  # FULL LOGS IN TERMINAL
        server.ehlo()
        server.starttls()
        server.ehlo()  # CRITICAL AFTER STARTTLS
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, [email], msg.as_string())
        server.quit()
        print(f"OTP SENT to {email}")
    except Exception as e:
        error_msg = f"Email Failed: {str(e)}"
        print("ERROR:", error_msg)
        flash(error_msg)
        raise

# ================== ROUTES ==================
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        email = request.form['email'].strip()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, password, email))
            conn.commit()
            flash('Registered! Ab login karo.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT id, email FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['otp_time'] = time.time()
            session['user_id'] = user[0]
            session['email'] = user[1]
            try:
                send_otp(user[1], otp)
                flash('OTP bheja gaya! (Spam check karo)')
                return redirect(url_for('verify_otp'))
            except:
                flash('Email send fail. Check terminal.')
        else:
            flash('Galat username ya password.')
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        return redirect(url_for('login'))
    if time.time() - session.get('otp_time', 0) > 300:
        session.clear()
        flash('OTP expire. Dobara login karo.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form['otp'] == session.get('otp'):
            session.pop('otp', None)
            session.pop('otp_time', None)
            session['logged_in'] = True
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Galat OTP.')
    return render_template('verify_otp.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form['action']
        key = request.form['key'].strip()
        try:
            if action == 'sync':
                zip_path = 'temp_vault.zip'
                enc_path = 'temp_vault.enc'
                zip_vault(zip_path)
                encrypt_file(zip_path, enc_path, key)
                upload_to_pcloud(enc_path)
                os.remove(zip_path)
                os.remove(enc_path)
                flash('Vault backup ho gaya pCloud pe!')
            elif action == 'restore':
                enc_path = 'temp_vault.enc'
                zip_path = 'temp_vault.zip'
                download_from_pcloud(enc_path)
                decrypt_file(enc_path, zip_path, key)
                unzip_vault(zip_path)
                os.remove(enc_path)
                os.remove(zip_path)
                flash('Vault restore ho gaya!')
        except Exception as e:
            flash(f'Error: {str(e)}')
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout successful.')
    return redirect(url_for('home'))

# ================== RUN ==================
if __name__ == '__main__':
    print("Vault App LIVE: http://127.0.0.1:5000")
    print("Pakistan Time:", time.strftime("%Y-%m-%d %H:%M:%S PKT"))
    app.run(host='127.0.0.1', port=5000, debug=True)