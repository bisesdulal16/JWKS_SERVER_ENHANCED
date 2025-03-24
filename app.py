"""
JWKS Server
Author: Bishesh Dulal
Date: March 2025

Description:
This Flask-based JWKS server provides the following:
- RSA key pair generation
- JWT signing using stored keys
- JWKS endpoint serving public keys
- Auth endpoint issuing JWTs
- Handling expired JWT signing
- SQLite-based persistent key storage
- Secure parameterized SQL to prevent injection attacks

Endpoints:
- POST /auth                → Issues a JWT (valid or expired based on query param)
- GET /.well-known/jwks.json → Returns public keys in JWKS format
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
    os.remove(db_path) # Start fresh each time (for grading consistency)

# Create the keys table with INTEGER primary key
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

# --- Utility Functions ---
def base64url_encode(value: int) -> str:
    """
    Encodes an integer using base64 URL-safe encoding without padding.
    Used to convert RSA modulus and exponent to JWKS format.
    """
    bytes_value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(bytes_value).rstrip(b'=').decode('utf-8')

def generate_key(expired: bool = False) -> int:
    """
    Generates an RSA key pair and saves it to the SQLite database.

    Parameters:
        expired (bool): Whether to generate an expired key

    Returns:
        int: The auto-incremented Key ID (kid) from the database
    """
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
    """
    Fetches one valid or expired key from the database.

    Parameters:
        expired (bool): Whether to fetch expired or unexpired key

    Returns:
        tuple: (kid, private_key PEM string)
    """
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
    """
    Retrieves all unexpired keys from the database.

    Returns:
        list of tuples: [(kid, key PEM), ...]
    """
    now = int(datetime.now(UTC).timestamp())
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
    keys = cursor.fetchall()
    conn.close()
    return keys

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_endpoint():
    """
    Returns JWKS (JSON Web Key Set) of active keys.

    Output:
        JSON list of public keys in JWKS format
    """
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
    """
    Issues a JWT signed by one of the RSA private keys.

    Query Params:
        expired=true → Uses an expired key

    Returns:
        JSON response containing the JWT
    """
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
    """Rejects non-GET methods on JWKS endpoint"""
    return jsonify(error="Method Not Allowed"), 405

@app.route('/auth', methods=['GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def auth_invalid_methods():
    """Rejects non-POST methods on /auth endpoint"""
    return jsonify(error="Method Not Allowed"), 405

# --- Main ---
if __name__ == '__main__':
    generate_key(False) # Valid key
    generate_key(True) # Expired key
    app.run(host='0.0.0.0', port=8080, debug=False)
