import os
import ssl
import smtplib
import random
import string
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, jsonify, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_messenger_key_change_in_prod'
# Using threading mode for stability across Python versions
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# --- Database Configuration ---
DB_NAME = "messenger.db"

def get_db_connection():
    # Using check_same_thread=False is safe here because we open/close connections 
    # strictly within the request/socket handler scope, preventing cross-thread leaks.
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;") # Improves concurrent read/write performance
    return conn

def init_db():
    """Automated table-initialization block. Creates tables on startup if they don't exist."""
    with get_db_connection() as conn:
        # Users Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                username TEXT
            )
        ''')
        
        # Messages Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT,
                sender TEXT,
                text_encrypted TEXT,
                timestamp TEXT
            )
        ''')
        
        # OTPs Table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS otps (
                email TEXT PRIMARY KEY,
                otp_hash TEXT,
                username TEXT,
                expires_at DATETIME
            )
        ''')
        
        # Composite Index on chat_id and timestamp for ultra-fast thread fetching
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_chat_id_timestamp 
            ON messages (chat_id, timestamp)
        ''')
        conn.commit()

# --- Encryption Setup (Encryption at Rest) ---
if os.path.exists('secret.key'):
    with open('secret.key', 'rb') as f:
        ENCRYPTION_KEY = f.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open('secret.key', 'wb') as f:
        f.write(ENCRYPTION_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY)

# --- In-Memory Socket Tracking (Transient) ---
# We still keep this in memory as socket IDs change on every connection
connected_users = {} 

# --- Email Configuration ---
# ⚠️ YAHAN APNI ASLI GMAIL ID AUR APP PASSWORD DAALEIN ⚠️
SENDER_EMAIL = "codewithahmed2005@gmail.com"       # <-- Apni email yahan likhein
SENDER_PASSWORD = "bfsa xqhu blzg nczb"           # <-- Yahan 16 letter ka App Password likhein (bina space ke)

def send_otp_email(recipient_email, otp_code):
    """Sends OTP using Python's built-in smtplib over SSL."""
    subject = "Your Secure Messenger OTP Code"
    body = f"Welcome to Secure Messenger!\n\nYour One-Time Password (OTP) is: {otp_code}\n\nThis code will expire in 5 minutes."

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        return True
    except Exception as e:
        print(f"\n❌ EMAIL SENDING FAILED: {e}\n")
        return False

def get_chat_id(user1, user2):
    return "_".join(sorted([user1, user2]))

# --- Routes ---
@app.route('/')
def index():
    if 'email' not in session:
        return render_template('index.html', logged_in=False, current_user=None)
    return render_template('index.html', logged_in=True, current_user=session['username'])

@app.route('/send_otp', methods=['POST'])
def request_otp():
    try:
        data = request.json
        email = data.get('email', '').strip().lower()
        username = data.get('username', '').strip()
        
        if not email or not username:
            return jsonify({'success': False, 'message': 'Email and Username are required.'}), 400
        
        otp_code = ''.join(random.choices(string.digits, k=6))
        otp_hash = generate_password_hash(otp_code)
        expires_at = datetime.now() + timedelta(minutes=5)
        
        # UPSERT logic: Insert new OTP or update existing one if email requests again
        with get_db_connection() as conn:
            conn.execute('''
                INSERT INTO otps (email, otp_hash, username, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET 
                    otp_hash = excluded.otp_hash,
                    username = excluded.username,
                    expires_at = excluded.expires_at
            ''', (email, otp_hash, username, expires_at))
            conn.commit()
        
        if send_otp_email(email, otp_code):
            return jsonify({'success': True, 'message': 'OTP sent successfully! Check your email.'})
        else:
            # Agar email send nahi hua toh frontend par error dikhayega
            return jsonify({'success': False, 'message': 'Failed to send OTP. Check server terminal for exact error.'}), 500
            
    except Exception as e:
        print(f"Error in /send_otp: {e}")
        return jsonify({'success': False, 'message': f'Server Error: {str(e)}'}), 500

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email', '').strip().lower()
    otp_input = data.get('otp', '')
    
    with get_db_connection() as conn:
        record = conn.execute('SELECT * FROM otps WHERE email = ?', (email,)).fetchone()
        
        if not record:
            return jsonify({'success': False, 'message': 'No OTP requested. Please try again.'}), 400
        
        # Check Expiry
        if datetime.now() > datetime.fromisoformat(record['expires_at']):
            conn.execute('DELETE FROM otps WHERE email = ?', (email,))
            conn.commit()
            return jsonify({'success': False, 'message': 'OTP has expired. Please request a new one.'}), 400
            
        # Validate Hash
        if check_password_hash(record['otp_hash'], otp_input):
            # OTP Correct - Clear it from database
            conn.execute('DELETE FROM otps WHERE email = ?', (email,))
            
            # Save user to users table if signing up for the first time (or update username if changed)
            conn.execute('''
                INSERT INTO users (email, username)
                VALUES (?, ?)
                ON CONFLICT(email) DO UPDATE SET username = excluded.username
            ''', (email, record['username']))
            conn.commit()
            
            # Create Flask Session
            session['email'] = email
            session['username'] = record['username']
            return jsonify({'success': True, 'message': 'Verification successful!'})
        else:
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 401

@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('username', None)
    return redirect('/')

# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return False # Reject connection if not authenticated
    
    username = session['username']
    connected_users[request.sid] = username
    join_room(username) # Join personal room for private messaging
    
    emit('user_list', {'users': list(connected_users.values())}, broadcast=True)
    emit('my_identity', {'username': username})

@socketio.on('disconnect')
def handle_disconnect():
    username = connected_users.pop(request.sid, None)
    if username:
        leave_room(username)
        emit('user_list', {'users': list(connected_users.values())}, broadcast=True)

@socketio.on('fetch_history')
def handle_fetch_history(data):
    peer = data.get('peer')
    current_user = session.get('username')
    if not current_user or not peer: return

    chat_id = get_chat_id(current_user, peer)
    
    # Query database for historical messages
    with get_db_connection() as conn:
        rows = conn.execute(
            'SELECT sender, text_encrypted, timestamp FROM messages WHERE chat_id = ? ORDER BY timestamp ASC', 
            (chat_id,)
        ).fetchall()
    
    history = []
    for row in rows:
        try:
            # Decrypt message before serving to client
            decrypted_text = cipher_suite.decrypt(row['text_encrypted'].encode('utf-8')).decode('utf-8')
            history.append({
                'sender': row['sender'],
                'text': decrypted_text,
                'timestamp': row['timestamp']
            })
        except Exception as e:
            print(f"Decryption error: {e}")
    
    emit('load_history', {'peer': peer, 'history': history})

@socketio.on('private_message')
def handle_private_message(data):
    receiver = data.get('receiver')
    text = data.get('text')
    current_user = session.get('username')
    
    if not current_user or not receiver or not text: return

    # Encrypt text before saving to database
    encrypted_text = cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')
    chat_id = get_chat_id(current_user, receiver)
    timestamp = datetime.now().strftime("%H:%M")
    
    # Insert permanently into database
    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO messages (chat_id, sender, text_encrypted, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (chat_id, current_user, encrypted_text, timestamp))
        conn.commit()

    # Payload to send over WSS (Plaintext over secure socket)
    payload = {
        'sender': current_user,
        'receiver': receiver,
        'text': text,
        'timestamp': timestamp
    }

    # Emit ONLY to the receiver's room and the sender's room
    emit('receive_message', payload, room=receiver)
    emit('receive_message', payload, room=current_user)

# --- Application Startup ---
if __name__ == '__main__':
    # Cloud providers automatically assign a PORT environment variable
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)