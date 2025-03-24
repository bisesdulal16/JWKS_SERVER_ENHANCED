"""
JWKS Server
Author: Bishesh Dulal
Date: February 2025
"""

from flask import Flask, request, jsonify
from datetime import datetime, timedelta, UTC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import base64
import sqlite3
from pathlib import Path
import os

# Initialize Flask application
app = Flask(__name__)

# Ensure we remove any old incompatible DB
db_path = Path("totally_not_my_privateKeys.db")
if db_path.exists():
    os.remove(db_path)

# Set up SQLite database with INTEGER kid
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()
conn.close()

def base64url_encode(value: int) -> str:
    bytes_value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(bytes_value).rstrip(b'=').decode('utf-8')

def generate_key(expired: bool = False) -> int:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    expiry = datetime.now(UTC) + timedelta(hours=1)
    if expired:
        expiry = datetime.now(UTC) - timedelta(minutes=5)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, int(expiry.timestamp())))
    kid = cursor.lastrowid
    conn.commit()
    conn.close()
    return kid

def get_key(expired: bool = False):
    now = int(datetime.now(UTC).timestamp())
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp < ? LIMIT 1', (now,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ? LIMIT 1', (now,))
    result = cursor.fetchone()
    conn.close()
    return result

def get_all_valid_keys():
    now = int(datetime.now(UTC).timestamp())
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
    keys = cursor.fetchall()
    conn.close()
    return keys

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_endpoint():
    keys = get_all_valid_keys()
    valid_keys = []

    for kid, pem in keys:
        private_key = serialization.load_pem_private_key(pem.encode('utf-8'), password=None, backend=default_backend())
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()
        valid_keys.append({
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),  # Must be string in JWKS
            "n": base64url_encode(numbers.n),
            "e": base64url_encode(numbers.e),
            "alg": "RS256"
        })

    return jsonify(keys=valid_keys), 200, {'Content-Type': 'application/json'}

@app.route('/auth', methods=['POST'])
def auth_endpoint():
    expired = 'expired' in request.args
    result = get_key(expired)

    if not result:
        generate_key(expired)
        result = get_key(expired)

    kid, private_pem = result

    exp_time = datetime.now(UTC) + timedelta(minutes=5)
    if expired:
        exp_time = datetime.now(UTC) - timedelta(minutes=5)

    payload = {
        'sub': 'example_user',
        'iat': datetime.now(UTC),
        'exp': exp_time
    }

    try:
        token = jwt.encode(
            payload,
            private_pem,
            algorithm='RS256',
            headers={'kid': str(kid)}  # Ensure string header
        )
    except Exception as e:
        return jsonify(error=f"JWT encoding error: {str(e)}"), 500

    return jsonify(token=token), 201

@app.route('/.well-known/jwks.json', methods=['PUT', 'POST', 'DELETE', 'PATCH'])
def jwks_invalid_methods():
    return jsonify(error="Method Not Allowed"), 405

@app.route('/auth', methods=['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def auth_invalid_methods():
    return jsonify(error="Method Not Allowed"), 405

if __name__ == '__main__':
    generate_key(False)
    generate_key(True)
    app.run(host='0.0.0.0', port=8080, debug=False)
