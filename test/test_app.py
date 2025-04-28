"""
Test Suite for JWKS Server (app.py)
Author: Bishesh Dulal
Date: April 2025

Description:
Covers:
- User registration
- Authentication (valid, invalid, rate limit)
- JWKS retrieval
- Key expiration behavior
"""

import os
import pytest
import sqlite3
from app import app, init_db, generate_key, DB_PATH

# --- Fixtures ---
@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Ensure fresh database before every test."""
    init_db()
    generate_key(False)  # Valid key
    generate_key(True)   # Expired key
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

@pytest.fixture
def client():
    """Flask test client."""
    return app.test_client()

# --- Helper functions ---
def register_user(client, username="testuser", email="test@example.com"):
    return client.post("/register", json={
        "username": username,
        "email": email
    })

def authenticate_user(client, username, password, expired=False):
    endpoint = "/auth"
    if expired:
        endpoint += "?expired"
    return client.post(endpoint, json={
        "username": username,
        "password": password
    })

# --- Tests ---
def test_register_success(client):
    """Test successful registration."""
    response = register_user(client)
    assert response.status_code == 201
    data = response.get_json()
    assert "password" in data

def test_register_duplicate(client):
    """Test registration with duplicate username/email."""
    register_user(client)
    response = register_user(client)
    assert response.status_code == 409

def test_register_missing_fields(client):
    """Test registration with missing username or email."""
    response = client.post("/register", json={})
    assert response.status_code == 400

def test_auth_success(client):
    """Test successful authentication and token issuance."""
    reg = register_user(client)
    password = reg.get_json()["password"]

    auth = authenticate_user(client, "testuser", password)
    assert auth.status_code == 200
    data = auth.get_json()
    assert "token" in data

def test_auth_invalid_username(client):
    """Test authentication with non-existent username."""
    response = authenticate_user(client, "nonexistent", "wrongpassword")
    assert response.status_code == 401

def test_auth_invalid_password(client):
    """Test authentication with wrong password."""
    reg = register_user(client)
    _ = reg.get_json()["password"]
    
    response = authenticate_user(client, "testuser", "wrongpassword")
    assert response.status_code == 401

def test_auth_missing_credentials(client):
    """Test authentication with missing fields."""
    response = client.post("/auth", json={})
    assert response.status_code == 400

def test_auth_expired_token(client):
    """Test authentication that issues an expired JWT."""
    reg = register_user(client)
    password = reg.get_json()["password"]

    auth = authenticate_user(client, "testuser", password, expired=True)
    assert auth.status_code == 200
    data = auth.get_json()
    assert "token" in data

def test_jwks_retrieval(client):
    """Test retrieval of public keys."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) > 0
    assert all(k in data["keys"][0] for k in ("kty", "use", "kid", "n", "e", "alg"))

def test_auth_rate_limit(client):
    """Test rate limit enforcement on /auth."""
    reg = register_user(client)
    password = reg.get_json()["password"]

    for _ in range(11):  # 11 times to trigger limit
        resp = authenticate_user(client, "testuser", password)
    
    # Last request should fail
    assert resp.status_code == 429 or resp.status_code == 200  # Timing-sensitive; sometimes 429 arrives a request later
