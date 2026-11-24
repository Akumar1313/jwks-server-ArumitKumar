"""
JWKS Server Implementation - Project 3
RESTful JWKS server with AES-GCM encrypted SQLite key storage, Argon2 user
registration, authentication request logging, and sliding-window rate limiting.
"""

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "totally_not_my_privateKeys.db"
NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM
DB_LOCK = threading.Lock()

# Configurable Argon2 password hasher
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


class ThreadedJWKSServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a larger socket backlog for burst traffic."""

    request_queue_size = 128
    allow_reuse_address = True


class RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 1.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps = deque()
        self._lock = threading.Lock()

    def is_allowed(self) -> bool:
        """Returns True if the request is within the allowed rate limit."""
        now = time.monotonic()
        with self._lock:
            # Drop timestamps that have fallen outside the sliding window
            while self._timestamps and (now - self._timestamps[0]) >= self.window_seconds:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.max_requests:
                return False

            self._timestamps.append(now)
            return True

    def reset(self):
        """Clears tracked request timestamps (useful for testing)."""
        with self._lock:
            self._timestamps.clear()


def int_to_base64url(val: int) -> str:
    """Encode an integer as an unpadded base64url string per RFC 7515/RFC 7517."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def get_aes_key() -> bytes:
    """
    Retrieves the secret from the NOT_MY_KEY environment variable and derives
    a fixed 32-byte (256-bit) AES key using SHA-256.
    """
    raw_key = os.environ.get("NOT_MY_KEY")
    if not raw_key:
        raise EnvironmentError("Environment variable 'NOT_MY_KEY' is not set.")
    return hashlib.sha256(raw_key.encode("utf-8")).digest()


def encrypt_private_key(pem_bytes: bytes) -> bytes:
    """
    Encrypts PEM private key bytes using AES-256-GCM with a random 12-byte IV/nonce.
    The nonce is prepended to the ciphertext so it can be retrieved during decryption.
    """
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, pem_bytes, None)
    return nonce + ciphertext


def decrypt_private_key(encrypted_blob: bytes) -> bytes:
    """Decrypts an AES-256-GCM encrypted private key blob (nonce + ciphertext)."""
    aesgcm = AESGCM(get_aes_key())
    nonce = encrypted_blob[:NONCE_SIZE]
    ciphertext = encrypted_blob[NONCE_SIZE:]
    return aesgcm.decrypt(nonce, ciphertext, None)


@contextmanager
def db_connection(db_file: str = DB_FILE):
    """
    Thread-safe context manager for SQLite connections that handles commits,
    rollbacks, foreign key enforcement, and guaranteed connection cleanup.
    """
    with DB_LOCK:
        conn = sqlite3.connect(db_file, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        try:
            yield conn
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db(db_file: str = DB_FILE):
    """Initializes SQLite tables (keys, users, auth_logs) and seeds initial RSA keys."""
    with db_connection(db_file) as conn:
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

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )

        now = int(time.time())
        cursor.execute("SELECT kid FROM keys WHERE exp > ? LIMIT 1", (now,))
        has_valid = cursor.fetchone() is not None

        cursor.execute("SELECT kid FROM keys WHERE exp <= ? LIMIT 1", (now,))
        has_expired = cursor.fetchone() is not None

    if not has_valid:
        insert_key(expires_at=now + 3600, db_file=db_file)
    if not has_expired:
        insert_key(expires_at=now - 3600, db_file=db_file)


def insert_key(expires_at: int, db_file: str = DB_FILE) -> int:
    """Generates an RSA private key, AES-encrypts it, and stores it in SQLite."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encrypted_key = encrypt_private_key(pem_bytes)

    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypted_key, expires_at),
        )
        return cursor.lastrowid


def get_key_by_kid(kid: int, db_file: str = DB_FILE):
    """Fetches a specific key record by its integer kid."""
    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,))
        return cursor.fetchone()


def get_key_from_db(expired: bool = False, db_file: str = DB_FILE):
    """
    Retrieves an encrypted private key row from SQLite.
    If no matching key is found, one is dynamically generated and stored.
    """
    now = int(time.time())
    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp ASC LIMIT 1",
                (now,),
            )
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,),
            )
        row = cursor.fetchone()

    if row is None:
        new_exp = now - 3600 if expired else now + 3600
        kid = insert_key(expires_at=new_exp, db_file=db_file)
        return get_key_by_kid(kid, db_file=db_file)

    return row


def get_valid_jwks(db_file: str = DB_FILE) -> dict:
    """Decrypts all non-expired keys from SQLite and builds a JWKS response dictionary."""
    now = int(time.time())
    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()

    jwk_list = []
    for row in rows:
        pem_bytes = decrypt_private_key(row["key"])
        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        pub_numbers = private_key.public_key().public_numbers()
        jwk_list.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": str(row["kid"]),
                "n": int_to_base64url(pub_numbers.n),
                "e": int_to_base64url(pub_numbers.e),
            }
        )

    return {"keys": jwk_list}


def register_user(username: str, email: str = None, db_file: str = DB_FILE) -> str:
    """
    Generates a UUIDv4 password, hashes it with Argon2, stores the user,
    and returns the plaintext password.
    """
    raw_password = str(uuid.uuid4())
    hashed_password = password_hasher.hash(raw_password)

    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, hashed_password, email),
        )

    return raw_password


def get_user_id_by_username(username: str, db_file: str = DB_FILE):
    """Looks up a user's integer ID by username, returning None if not found."""
    if not username:
        return None
    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return row["id"] if row else None


def log_auth_request(request_ip: str, user_id=None, db_file: str = DB_FILE):
    """Logs a successful authentication request into auth_logs and updates last_login."""
    with db_connection(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request_ip, user_id),
        )
        if user_id is not None:
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )


class JWKSRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for JWKS, Registration, and Auth endpoints."""

    db_file = DB_FILE
    rate_limiter = RateLimiter(max_requests=10, window_seconds=1.0)

    def _send_json(self, status_code: int, data: dict):
        """Helper to send a JSON response with appropriate headers."""
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_error_status(self, status_code: int, message: str):
        """Helper to send standard HTTP error status codes."""
        self._send_json(status_code, {"error": message})

    def _read_json_body(self) -> dict:
        """Safely reads and parses an optional JSON request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        raw_body = self.rfile.read(content_length)
        return json.loads(raw_body.decode("utf-8"))

    def _extract_username(self, body: dict):
        """Extracts username from JSON body or HTTP Basic Auth header if present."""
        if isinstance(body, dict) and body.get("username"):
            return body["username"]

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                return decoded.split(":", 1)[0]
            except (ValueError, UnicodeDecodeError):
                return None
        return None

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/.well-known/jwks.json":
            try:
                jwks_data = get_valid_jwks(db_file=self.db_file)
                self._send_json(200, jwks_data)
            except (sqlite3.Error, EnvironmentError, ValueError) as exc:
                self._send_error_status(500, f"Internal Server Error: {exc}")
            return

        if parsed.path in ("/auth", "/register"):
            self._send_error_status(405, "Method Not Allowed")
            return

        self._send_error_status(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/register":
            try:
                body = self._read_json_body()
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_error_status(400, "Invalid JSON payload")
                return

            username = body.get("username") if isinstance(body, dict) else None
            email = body.get("email") if isinstance(body, dict) else None

            if not username:
                self._send_error_status(400, "Missing required field: username")
                return

            try:
                generated_password = register_user(
                    username=username,
                    email=email,
                    db_file=self.db_file,
                )
                self._send_json(201, {"password": generated_password})
            except sqlite3.IntegrityError:
                self._send_error_status(409, "Username or email already exists")
            except sqlite3.Error as exc:
                self._send_error_status(500, f"Database error: {exc}")
            return

        if parsed.path == "/auth":
            # Enforce rate limit before processing or logging the request
            if not self.rate_limiter.is_allowed():
                self._send_error_status(429, "Too Many Requests")
                return

            try:
                body = self._read_json_body()
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {}

            query_params = parse_qs(parsed.query)
            is_expired = "expired" in query_params

            try:
                row = get_key_from_db(expired=is_expired, db_file=self.db_file)
                kid = row["kid"]
                pem_bytes = decrypt_private_key(row["key"])
                exp_time = row["exp"]

                username = self._extract_username(body)
                user_id = get_user_id_by_username(username, db_file=self.db_file)

                now = int(time.time())
                payload = {
                    "sub": username or "fake-user-123",
                    "iat": now if not is_expired else exp_time - 3600,
                    "exp": exp_time,
                    "iss": "jwks-auth-server",
                }
                headers = {"kid": str(kid), "alg": "RS256"}

                token = jwt.encode(
                    payload=payload,
                    key=pem_bytes,
                    algorithm="RS256",
                    headers=headers,
                )

                # Log only successful authentication requests
                request_ip = self.client_address[0]
                log_auth_request(
                    request_ip=request_ip,
                    user_id=user_id,
                    db_file=self.db_file,
                )

                self._send_json(200, {"token": token})
            except (sqlite3.Error, EnvironmentError, ValueError) as exc:
                self._send_error_status(500, f"Internal Server Error: {exc}")
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
    httpd = ThreadedJWKSServer(server_address, JWKSRequestHandler)
    print(f"JWKS Server running on port {port} using database '{DB_FILE}'...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server(8080)