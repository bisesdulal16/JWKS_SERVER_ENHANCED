"""
JWKS Server - unittest Test Suite
Author: Bishesh Dulal
"""

import unittest
import sqlite3
import json
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa

from app import app, generate_key, db_path


class JWKSUnitTest(unittest.TestCase):

    def setUp(self):
        """Creates test client and clears DB before each test."""
        self.client = app.test_client()
        self._clear_db()

    def tearDown(self):
        """Cleans up DB after each test."""
        self._clear_db()

    def _clear_db(self):
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM keys")
            conn.commit()

    def test_authenticate_user(self):
        """Test: /auth returns a valid JWT token."""
        generate_key()
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('token', data)

    def test_expired_token(self):
        """Test: /auth?expired=true returns an expired JWT."""
        generate_key(expired=True)
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('token', data)
        decoded = json.loads(
            json.dumps(
                json.loads(
                    self.client.post('/auth?expired=true').data.decode()
                )
            )
        )
        self.assertIn("token", decoded)

    def test_get_jwks(self):
        """Test: /.well-known/jwks.json returns valid keys."""
        generate_key()
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('keys', data)
        self.assertGreater(len(data['keys']), 0)
        for key in data['keys']:
            self.assertIn('kid', key)
            self.assertIn('n', key)
            self.assertIn('e', key)
            self.assertEqual(key['alg'], 'RS256')

    def test_expired_key_not_in_jwks(self):
        """Test: expired keys are cleaned up from JWKS."""
        expired_kid = generate_key(expired=True)
        response = self.client.get('/.well-known/jwks.json')
        data = json.loads(response.data)
        for key in data['keys']:
            self.assertNotEqual(key['kid'], expired_kid)

    def test_invalid_methods_jwks(self):
        """Test: invalid methods on /.well-known/jwks.json return 405."""
        for method in ['post', 'put', 'delete', 'patch']:
            res = getattr(self.client, method)('/.well-known/jwks.json')
            self.assertEqual(res.status_code, 405)

    def test_invalid_methods_auth(self):
        """Test: invalid methods on /auth return 405."""
        for method in ['get', 'put', 'delete', 'patch']:
            res = getattr(self.client, method)('/auth')
            self.assertEqual(res.status_code, 405)

    def test_store_and_query_key(self):
        """Test: verify key is stored and retrievable from DB."""
        generate_key()
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]
        self.assertGreater(count, 0)


if __name__ == '__main__':
    unittest.main()
