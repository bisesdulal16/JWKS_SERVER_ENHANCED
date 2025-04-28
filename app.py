"""
JWKS Server with Enhanced Security
Author: Bishesh Dulal
Date: April 2025

Description:
This server implements:
- RSA key generation with AES-encrypted private key storage
- Secure user registration with Argon2 password hashing
- JWT issuance (valid or expired) with RS256 algorithm
- Public key publication via JWKS endpoint
- Manual rate limiting
- SQLite persistent storage
- Parameterized SQL queries to prevent SQLi attacks
"""

import os
import time
import uuid
import base64
import sqlite3
import jwt

from flask import Flask, request, jsonify
from threading import Lock
from collections import deque
from datetime import datetime, timedelta, UTC
from crypto_utils import encrypt, decrypt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwt import encode as jwt_encode

# --- Configuration ---
app = Flask(__name__)
DB_PATH = "totally_not_my_privateKeys.db"
MAX_REQUESTS_PER_SECOND = 10
RATE_LIMIT_WINDOW = 1  # seconds

# --- Security Components ---
ph = PasswordHasher()
rate_lock = Lock()
request_timestamps = deque()

# --- Database Initialization ---
def init_db():
    """Initialize database schema for keys, users, and auth logs."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER REFERENCES users(id)
            )
        ''')
        conn.commit()

init_db()

# --- Helper Functions ---
def generate_key(expired: bool = False) -> int:
    """Generate RSA key, encrypt it, and store it with an expiration timestamp."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    expiry = datetime.now(UTC) - timedelta(minutes=5) if expired else datetime.now(UTC) + timedelta(hours=1)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    ciphertext, iv = encrypt(pem)
    encrypted_value = f"{ciphertext}::{iv}"

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_value, int(expiry.timestamp())))
        return cursor.lastrowid

def get_valid_key(expired: bool = False):
    """Fetch and decrypt a valid or expired key."""
    now = int(datetime.now(UTC).timestamp())
    query = 'SELECT kid, key FROM keys WHERE exp {} ? LIMIT 1'.format('<' if expired else '>')
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        cursor.execute(query, (now,))
        result = cursor.fetchone()

    if result:
        kid, encrypted_data = result
        ciphertext, iv = encrypted_data.split("::")
        return kid, decrypt(ciphertext, iv)
    return None

# --- Middleware ---
@app.before_request
def apply_rate_limit():
    """Enforce manual rate limiting on /auth POST requests."""
    if request.path == '/auth' and request.method == 'POST':
        with rate_lock:
            now = time.time()
            while request_timestamps and request_timestamps[0] < now - RATE_LIMIT_WINDOW:
                request_timestamps.popleft()
            if len(request_timestamps) >= MAX_REQUESTS_PER_SECOND:
                app.logger.warning(f"Rate limit exceeded from {request.remote_addr}")
                return jsonify(error="Too many requests"), 429
            request_timestamps.append(now)

# --- Endpoints ---
@app.route('/register', methods=['POST'])
def register():
    """Register a new user and return generated password."""
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify(error="Username and email required"), 400

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                (data['username'], password_hash, data['email'])
            )
    except sqlite3.IntegrityError:
        return jsonify(error="Username/email already exists"), 409

    return jsonify(password=password), 201

@app.route('/auth', methods=['POST'])
def authenticate():
    """Authenticate a user and issue a JWT."""
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify(error="Missing credentials"), 400

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (data['username'],))
            user = cursor.fetchone()

        if not user:
            return jsonify(error="Invalid credentials"), 401

        user_id, stored_hash = user
        try:
            ph.verify(stored_hash, data['password'])
        except Exception:
            return jsonify(error="Invalid credentials"), 401

        expired = 'expired' in request.args
        key_data = get_valid_key(expired)
        if not key_data:
            generate_key(expired)
            key_data = get_valid_key(expired)
            if not key_data:
                raise ValueError("Key generation failed")

        kid, private_pem = key_data
        exp_time = datetime.now(UTC) + (timedelta(minutes=-5) if expired else timedelta(minutes=5))

        token = jwt_encode(
            {'sub': data['username'], 'iat': datetime.now(UTC), 'exp': exp_time},
            private_pem,
            algorithm='RS256',
            headers={'kid': str(kid)}
        )

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()
            cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request.remote_addr, user_id))

        return jsonify(token=token)

    except Exception as e:
        app.logger.error(f"Authentication error: {str(e)}")
        return jsonify(error="Internal server error"), 500

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Return all active public keys in JWKS format."""
    keys = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (int(datetime.now(UTC).timestamp()),))
        for kid, encrypted_data in cursor.fetchall():
            ciphertext, iv = encrypted_data.split("::")
            pem = decrypt(ciphertext, iv)
            private_key = serialization.load_pem_private_key(pem.encode(), None, default_backend())
            public_numbers = private_key.public_key().public_numbers()

            keys.append({
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": base64.urlsafe_b64encode(
                    public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
                ).decode().rstrip("="),
                "e": base64.urlsafe_b64encode(
                    public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
                ).decode().rstrip("="),
                "alg": "RS256"
            })

    return jsonify(keys=keys)

# --- Main ---
if __name__ == '__main__':
    generate_key(False)  # Generate valid key
    generate_key(True)   # Generate expired key
    app.run(host='0.0.0.0', port=8080, debug=False)
