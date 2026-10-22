"""
JWKS Server Implementation - Project 2
RESTful JWKS server backed by a SQLite database for persistent RSA key storage.
"""

import base64
import json
import sqlite3
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

DB_FILE = "totally_not_my_privateKeys.db"


def int_to_base64url(val: int) -> str:
    """Encode an integer as an unpadded base64url string per RFC 7515/RFC 7517."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def get_db_connection(db_file: str = DB_FILE) -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database."""
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_file: str = DB_FILE):
    """Initializes the SQLite schema and ensures initial active and expired keys exist."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()

    now = int(time.time())

    # Check if we already have at least one valid key
    cursor.execute("SELECT kid FROM keys WHERE exp > ? LIMIT 1", (now,))
    if not cursor.fetchone():
        insert_key(expires_at=now + 3600, db_file=db_file)

    # Check if we already have at least one expired key
    cursor.execute("SELECT kid FROM keys WHERE exp <= ? LIMIT 1", (now,))
    if not cursor.fetchone():
        insert_key(expires_at=now - 3600, db_file=db_file)

    conn.close()


def insert_key(expires_at: int, db_file: str = DB_FILE) -> int:
    """Generates an RSA private key, serializes to PKCS8 PEM, and stores it in the DB."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (pem_bytes, expires_at)
    )
    conn.commit()
    kid = cursor.lastrowid
    conn.close()
    return kid


def get_key_from_db(expired: bool = False, db_file: str = DB_FILE):
    """
    Retrieves a private key row from SQLite.
    If no matching key is found, one is dynamically generated and stored.
    """
    now = int(time.time())
    conn = get_db_connection(db_file)
    cursor = conn.cursor()

    if expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        new_exp = now - 3600 if expired else now + 3600
        kid = insert_key(expires_at=new_exp, db_file=db_file)
        return get_key_by_kid(kid, db_file=db_file)

    return row


def get_key_by_kid(kid: int, db_file: str = DB_FILE):
    """Fetches a specific key record by its integer kid."""
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_valid_jwks(db_file: str = DB_FILE) -> dict:
    """Reads all non-expired keys from SQLite and builds a JWKS response dictionary."""
    now = int(time.time())
    conn = get_db_connection(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()

    jwk_list = []
    for row in rows:
        private_key = serialization.load_pem_private_key(row["key"], password=None)
        pub_numbers = private_key.public_key().public_numbers()
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(row["kid"]),
            "n": int_to_base64url(pub_numbers.n),
            "e": int_to_base64url(pub_numbers.e)
        }
        jwk_list.append(jwk)

    return {"keys": jwk_list}


class JWKSRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for JWKS and Auth endpoints using SQLite backend."""

    db_file = DB_FILE

    def _send_json(self, status_code: int, data: dict):
        """Helper to send JSON response with appropriate headers."""
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error_status(self, status_code: int, message: str):
        """Helper to send standard HTTP error status codes."""
        self._send_json(status_code, {"error": message})

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/.well-known/jwks.json":
            jwks_data = get_valid_jwks(db_file=self.db_file)
            self._send_json(200, jwks_data)
            return

        if parsed.path == "/auth":
            self._send_error_status(405, "Method Not Allowed")
            return

        self._send_error_status(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/auth":
            query_params = parse_qs(parsed.query)
            is_expired = "expired" in query_params

            row = get_key_from_db(expired=is_expired, db_file=self.db_file)
            kid = row["kid"]
            pem_bytes = row["key"]
            exp_time = row["exp"]

            now = int(time.time())
            payload = {
                "sub": "fake-user-123",
                "iat": now if not is_expired else exp_time - 3600,
                "exp": exp_time,
                "iss": "jwks-auth-server"
            }

            headers = {
                "kid": str(kid),
                "alg": "RS256"
            }

            token = jwt.encode(
                payload=payload,
                key=pem_bytes,
                algorithm="RS256",
                headers=headers
            )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode("utf-8"))
            return

        if parsed.path == "/.well-known/jwks.json":
            self._send_error_status(405, "Method Not Allowed")
            return

        self._send_error_status(404, "Not Found")

    def do_PUT(self):
        self._send_error_status(405, "Method Not Allowed")

    def do_DELETE(self):
        self._send_error_status(405, "Method Not Allowed")

    def do_PATCH(self):
        self._send_error_status(405, "Method Not Allowed")


def run_server(port: int = 8080):
    init_db()
    server_address = ("", port)
    httpd = HTTPServer(server_address, JWKSRequestHandler)
    print(f"JWKS Server running on port {port} using database '{DB_FILE}'...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server(8080)