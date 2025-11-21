from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
import sqlite3
import os
import random
import smtplib
from email.mime.text import MIMEText
import hashlib
import zipfile
import time
import base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# ================== CONFIG ==================
SENDER_EMAIL = 'muhammadazanshahid8@gmail.com'
SENDER_PASSWORD = 'tvixttwiqiovthzc'
DEFAULT_BACKUPS_FOLDER = r'C:\VaultBackups'
os.makedirs(DEFAULT_BACKUPS_FOLDER, exist_ok=True)

# ================== DATABASE INIT ==================
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, api_key TEXT)''')
    try:
        c.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

# ================== BACKUP INFO ==================
def get_backup_info(folder):
    backups = []
    if not os.path.exists(folder):
        return backups
    for f in os.listdir(folder):
        if f.endswith('.enc.zip'):
            path = os.path.join(folder, f)
            size_mb = round(os.path.getsize(path) / (1024*1024), 2)
            mtime = time.strftime('%d %b %Y, %I:%M %p', time.localtime(os.path.getmtime(path)))
            backups.append({
                'name': f,
                'size': size_mb,
                'time': mtime
            })
    return sorted(backups, key=lambda x: x['time'], reverse=True)

# ================== EMAIL OTP ==================
def send_otp(email, otp):
    try:
        msg = MIMEText(f"""
        <h2>Vault App - Login OTP</h2>
        <p><b>OTP: {otp}</b></p>
        <p>Valid for 5 minutes.</p>
        <hr><small>Vault App (Pakistan)</small>
        """, 'html')
        msg['Subject'] = 'Vault App - Your OTP'
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.quit()
    except Exception as e:
        print("Email Error:", e)
        flash('Email send failed. Check terminal.', 'error')

# ================== ROUTES ==================
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form['email'].strip().lower()

        if len(username) < 3 or len(password) < 6:
            flash('Username >= 3, Password >= 6 chars.', 'error')
            return redirect(url_for('register'))

        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed, email))
            user_id = c.lastrowid
            api_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
            c.execute("UPDATE users SET api_key = ? WHERE id = ?", (api_key, user_id))
            conn.commit()
            flash(f'Account ban gaya! API Key (SAVE IT): {api_key}', 'success')
            flash('Yeh key sirf ek baar dikhegi!', 'warning')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username/email already taken.', 'error')
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
        c.execute("SELECT id, email, username FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['otp_time'] = time.time()
            session['user_id'] = user[0]
            session['email'] = user[1]
            session['username'] = user[2]
            try:
                send_otp(user[1], otp)
                flash('OTP bheja gaya! (Spam check karo)', 'success')
                return redirect(url_for('verify_otp'))
            except:
                flash('Email send fail. Terminal check karo.', 'error')
        else:
            flash('Wrong username/password.', 'error')
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or time.time() - session.get('otp_time', 0) > 300:
        session.clear()
        flash('OTP expired. Dobara login karo.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form['otp'] == session['otp']:
            session['logged_in'] = True
            session.pop('otp', None)
            session.pop('otp_time', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Galat OTP.', 'error')
    return render_template('verify_otp.html')

# ================== DASHBOARD (Google Drive Style + Delete + Download) ==================
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_folder = os.path.join(DEFAULT_BACKUPS_FOLDER, f"user_{user_id}")
    os.makedirs(user_folder, exist_ok=True)

    # Handle Delete
    if request.method == 'POST' and 'delete_backup' in request.form:
        filename = request.form['delete_backup']
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path) and filename.endswith('.enc.zip'):
            os.remove(file_path)
            flash(f'Deleted: {filename}', 'success')
        else:
            flash('File not found or invalid.', 'error')
        return redirect(url_for('dashboard'))

    # API Key Auto Generate
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT api_key FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    api_key = result[0] if result and result[0] else None
    if not api_key:
        api_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        c.execute("UPDATE users SET api_key = ? WHERE id = ?", (api_key, user_id))
        conn.commit()
        flash(f'Naya API Key generate: {api_key}', 'success')
        flash('COPY kar lo — sirf ek baar dikhega!', 'warning')
    conn.close()

    # Get Backups
    backups = get_backup_info(user_folder)
    total_size = round(sum(b['size'] for b in backups), 2) if backups else 0

    return render_template('dashboard.html',
                           total_size=total_size,
                           backups=backups,
                           api_key=api_key)

# ================== Download Single Backup (Web se) ==================
@app.route('/download_backup/<filename>')
def download_backup(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user_folder = os.path.join(DEFAULT_BACKUPS_FOLDER, f"user_{session['user_id']}")
    file_path = os.path.join(user_folder, filename)
    if os.path.exists(file_path) and filename.endswith('.enc.zip'):
        return send_from_directory(user_folder, filename, as_attachment=True)
    flash('File not found!', 'error')
    return redirect(url_for('dashboard'))

# ================== Desktop Client Download ==================
@app.route('/download_vault_client')
def download_vault_client():
    return send_file('vault_client.py', as_attachment=True, download_name='VaultClient.py')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('home'))

# ================== API FOR DESKTOP CLIENT ==================
@app.route('/api/backups', methods=['GET'])
def api_get_backups():
    api_key = request.headers.get('X-API-Key')
    if not api_key: return jsonify({'error': 'API Key required'}), 401

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    conn.close()
    if not user: return jsonify({'error': 'Invalid API Key'}), 401

    user_folder = os.path.join(DEFAULT_BACKUPS_FOLDER, f"user_{user[0]}")
    backups = get_backup_info(user_folder)
    total = round(sum(b['size'] for b in backups), 2) if backups else 0

    return jsonify({'username': user[1], 'total_size_mb': total, 'backups': backups})

@app.route('/api/upload_backup', methods=['POST'])
def api_upload_backup():
    api_key = request.headers.get('X-API-Key')
    if not api_key: return jsonify({'error': 'API Key required'}), 401

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    conn.close()
    if not user: return jsonify({'error': 'Invalid API Key'}), 401

    user_folder = os.path.join(DEFAULT_BACKUPS_FOLDER, f"user_{user[0]}")
    os.makedirs(user_folder, exist_ok=True)

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    if not filename.endswith('.enc.zip'):
        filename = f"upload_{int(time.time())}.enc.zip"
    path = os.path.join(user_folder, filename)
    file.save(path)

    size_mb = round(os.path.getsize(path) / (1024*1024), 2)
    time_str = time.strftime('%d %b %Y, %I:%M %p')

    return jsonify({'success': True, 'name': filename, 'size_mb': size_mb, 'time': time_str})

@app.route('/api/download_backup/<path:filename>')
def api_download_backup(filename):
    api_key = request.headers.get('X-API-Key')
    if not api_key: return "Unauthorized", 401

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    conn.close()
    if not user: return "Invalid Key", 401

    user_folder = os.path.join(DEFAULT_BACKUPS_FOLDER, f"user_{user[0]}")
    file_path = os.path.join(user_folder, filename)
    if not os.path.exists(file_path): return "Not found", 404

    return send_from_directory(user_folder, filename, as_attachment=True)

# ================== RUN ==================
if __name__ == '__main__':
    print("Vault Server LIVE → http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)