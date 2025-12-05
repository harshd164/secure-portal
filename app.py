import os
import secrets
import hashlib
import datetime
import io
import base64
import sqlite3
import math
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename

# --- LIBRARIES FOR RENDERING ---
try:
    import fitz  # PyMuPDF
    from docx import Document
except ImportError:
    pass

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = 'secure_storage'
DB_FILE = 'secure_portal.db'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (email TEXT PRIMARY KEY, role TEXT, password TEXT)''')
    
    # Updated Schema for Precision Geofencing
    c.execute('''CREATE TABLE IF NOT EXISTS files 
                 (id TEXT PRIMARY KEY, filename TEXT, owner TEXT, 
                  beneficiary TEXT, pin_hash TEXT, expiry TEXT, 
                  target_lat REAL, target_lon REAL, radius_meters INTEGER, 
                  key_hex TEXT)''')
    
    try:
        c.execute("INSERT INTO users VALUES ('admin@corp.com', 'owner', 'admin123')")
        c.execute("INSERT INTO users VALUES ('user@corp.com', 'beneficiary', 'user123')")
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

init_db()

# --- GEOLOCATION LOGIC (HAVERSINE FORMULA) ---
def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculates distance between two GPS points in meters.
    """
    R = 6371000  # Radius of Earth in meters
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    
    a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c  # Distance in meters

# --- ROUTES ---

@app.route('/')
def index():
    if 'user' in session:
        if session['role'] == 'owner': return redirect(url_for('owner_dashboard'))
        return redirect(url_for('beneficiary_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE email=? AND password=?", (email, password))
    row = c.fetchone()
    conn.close()
    if row:
        session['user'] = email
        session['role'] = row[0]
        return redirect(url_for('index'))
    flash("Invalid Credentials", "danger")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/owner')
def owner_dashboard():
    if session.get('role') != 'owner': return redirect(url_for('index'))
    return render_template('dashboard_owner.html')

@app.route('/upload', methods=['POST'])
def upload():
    if session.get('role') != 'owner': return redirect(url_for('index'))
    f = request.files['file']
    if not f: return redirect(url_for('owner_dashboard'))
    
    # Encrypt
    key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    plaintext = f.read()
    aesgcm = AESGCM(key)
    encrypted_data = nonce + aesgcm.encrypt(nonce, plaintext, None)
    
    file_id = secrets.token_hex(8)
    with open(os.path.join(UPLOAD_FOLDER, file_id), 'wb') as out:
        out.write(encrypted_data)
        
    pin_hash = hashlib.sha256(request.form['pin'].encode()).hexdigest()
    
    # Calculate Expiry
    expiry_dt = datetime.datetime.now() + datetime.timedelta(hours=int(request.form['expiry']))
    
    # Parse Geo-Fence Data
    try:
        lat = float(request.form['target_lat'])
        lon = float(request.form['target_lon'])
        radius = int(request.form['radius'])
    except ValueError:
        flash("Invalid Coordinates", "danger")
        return redirect(url_for('owner_dashboard'))
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (file_id, secure_filename(f.filename), session['user'],
               request.form['beneficiary'], pin_hash, expiry_dt.isoformat(),
               lat, lon, radius, key.hex()))
    conn.commit()
    conn.close()
    flash("Secure Geofence Active. File Uploaded.", "success")
    return redirect(url_for('owner_dashboard'))

@app.route('/beneficiary')
def beneficiary_dashboard():
    if session.get('role') != 'beneficiary': return redirect(url_for('index'))
    
    # Just for display city, we still use IP API (Optional visual aid)
    try:
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        loc_data = requests.get(f'http://ip-api.com/json/{user_ip}').json()
        city_display = loc_data.get('city', 'Unknown')
    except:
        city_display = "Unknown"

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Fetch relevant columns
    c.execute("SELECT id, filename, owner, expiry FROM files WHERE beneficiary=?", (session['user'],))
    files = c.fetchall()
    conn.close()
    return render_template('dashboard_beneficiary.html', files=files, city=city_display)

@app.route('/view/<file_id>', methods=['POST'])
def view_file(file_id):
    if session.get('role') != 'beneficiary': abort(403)
    pin = request.form['pin']
    
    # Get Client GPS from hidden form fields
    try:
        client_lat = float(request.form['client_lat'])
        client_lon = float(request.form['client_lon'])
    except (ValueError, TypeError):
        flash("GPS Data Missing. Please enable location permissions.", "danger")
        return redirect(url_for('beneficiary_dashboard'))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    conn.close()
    if not row: abort(404)
    
    # Row Structure: 
    # 0:id, 1:filename, 2:owner, 3:ben, 4:pin, 5:expiry, 
    # 6:lat, 7:lon, 8:radius, 9:key
    
    # 1. PIN Check
    if hashlib.sha256(pin.encode()).hexdigest() != row[4]:
        flash("Incorrect PIN", "danger")
        return redirect(url_for('beneficiary_dashboard'))
    
    # 2. Expiry Check
    if datetime.datetime.now() > datetime.datetime.fromisoformat(row[5]):
        flash("File Expired", "danger")
        return redirect(url_for('beneficiary_dashboard'))
        
    # 3. HIGH PRECISION LOCATION CHECK
    target_lat, target_lon, radius = row[6], row[7], row[8]
    
    distance = calculate_distance(client_lat, client_lon, target_lat, target_lon)
    
    print(f"DEBUG: Dist: {distance:.2f}m | Radius: {radius}m")
    
    if distance > radius:
        flash(f"ACCESS DENIED. You are {distance:.1f}m away from the authorized zone (Radius: {radius}m).", "danger")
        return redirect(url_for('beneficiary_dashboard'))

    # --- DECRYPTION & RENDERING ---
    try:
        with open(os.path.join(UPLOAD_FOLDER, file_id), 'rb') as f:
            encrypted_data = f.read()
            
        key = bytes.fromhex(row[9])
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        filename = row[1]
        ext = os.path.splitext(filename)[1].lower()
        
        # ... (Rendering logic same as before) ...
        if ext == '.pdf':
            doc = fitz.open(stream=plaintext, filetype="pdf")
            pages_b64 = []
            for page in doc:
                pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))
                img_data = pix.tobytes("png")
                b64_str = base64.b64encode(img_data).decode('utf-8')
                pages_b64.append(b64_str)
            return render_template('viewer.html', pages=pages_b64, type='pdf', filename=filename)
        elif ext in ['.docx', '.doc']:
            doc_stream = io.BytesIO(plaintext)
            document = Document(doc_stream)
            html_content = ""
            for para in document.paragraphs:
                if para.text.strip():
                    html_content += f"<p>{para.text}</p>"
            return render_template('viewer.html', content=html_content, type='docx', filename=filename)
        elif ext in ['.png', '.jpg', '.jpeg']:
            img_b64 = base64.b64encode(plaintext).decode('utf-8')
            return render_template('viewer.html', content=img_b64, type='image', filename=filename)
        else:
            try:
                text = plaintext.decode('utf-8')
            except:
                text = "File type not supported for preview."
            return render_template('viewer.html', content=text, type='text', filename=filename)

    except Exception as e:
        flash(f"Decryption Error: {str(e)}", "danger")
        return redirect(url_for('beneficiary_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)