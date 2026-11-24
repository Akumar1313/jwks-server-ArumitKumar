import base64
import os
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
import requests
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

import main
from main import (
    DB_FILE,
    JWKSRequestHandler,
    ThreadedJWKSServer,
    db_connection,
    decrypt_private_key,
    get_key_from_db,
    init_db,
    int_to_base64url,
)

BASE_URL = "http://127.0.0.1:8080"


@pytest.fixture(scope="module", autouse=True)
def setup_server_and_db():
    # Provide an encryption key for the test run
    os.environ["NOT_MY_KEY"] = "test-suite-super-secret-aes-key"

    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    init_db(DB_FILE)

    server = ThreadedJWKSServer(("127.0.0.1", 8080), JWKSRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.3)

    yield

    server.shutdown()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure each test starts with a clean rate-limit window."""
    JWKSRequestHandler.rate_limiter.reset()


def base64url_to_int(val_str: str) -> int:
    rem = len(val_str) % 4
    if rem > 0:
        val_str += "=" * (4 - rem)
    val_bytes = base64.urlsafe_b64decode(val_str)
    return int.from_bytes(val_bytes, byteorder="big")


def test_int_to_base64url():
    val = 65537
    encoded = int_to_base64url(val)
    assert base64url_to_int(encoded) == val


def test_db_tables_and_initial_keys_exist():
    with db_connection(DB_FILE) as conn:
        cursor = conn.cursor()
        for table in ("keys", "users", "auth_logs"):
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            )
            assert cursor.fetchone() is not None, f"Missing table: {table}"

        now = int(time.time())
        cursor.execute("SELECT COUNT(*) AS total FROM keys WHERE exp > ?", (now,))
        assert cursor.fetchone()["total"] >= 1

        cursor.execute("SELECT COUNT(*) AS total FROM keys WHERE exp <= ?", (now,))
        assert cursor.fetchone()["total"] >= 1


def test_private_keys_are_encrypted_in_db():
    with db_connection(DB_FILE) as conn:
        rows = conn.execute("SELECT key FROM keys").fetchall()
        assert len(rows) >= 2
        for row in rows:
            raw_blob = row["key"]
            # Must NOT be stored in plaintext PEM format
            assert b"BEGIN PRIVATE KEY" not in raw_blob
            # Must decrypt back to valid PEM
            decrypted = decrypt_private_key(raw_blob)
            assert decrypted.startswith(b"-----BEGIN PRIVATE KEY-----")


def test_missing_not_my_key_raises_error(monkeypatch):
    monkeypatch.delenv("NOT_MY_KEY", raising=False)
    with pytest.raises(EnvironmentError):
        main.get_aes_key()


def test_jwks_endpoint_returns_only_valid_keys():
    res = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert res.status_code == 200
    data = res.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    now = int(time.time())
    with db_connection(DB_FILE) as conn:
        rows = conn.execute("SELECT kid FROM keys WHERE exp <= ?", (now,)).fetchall()
        expired_kids = {str(r["kid"]) for r in rows}

    returned_kids = {k["kid"] for k in data["keys"]}
    assert returned_kids.isdisjoint(expired_kids)


def test_register_user_and_argon2_hash():
    payload = {"username": "cooluser", "email": "cool@example.com"}
    res = requests.post(f"{BASE_URL}/register", json=payload)
    assert res.status_code in (200, 201)

    password = res.json().get("password")
    assert password is not None
    # Verify returned password is a valid UUIDv4
    parsed_uuid = uuid.UUID(password)
    assert parsed_uuid.version == 4

    # Verify stored hash in DB is Argon2 and matches the returned password
    with db_connection(DB_FILE) as conn:
        row = conn.execute(
            "SELECT username, password_hash, email FROM users WHERE username = ?",
            ("cooluser",),
        ).fetchone()
        assert row is not None
        assert row["email"] == "cool@example.com"
        assert row["password_hash"].startswith("$argon2")
        ph = PasswordHasher()
        assert ph.verify(row["password_hash"], password)

    # Duplicate registration should fail with 409 Conflict
    dup_res = requests.post(f"{BASE_URL}/register", json=payload)
    assert dup_res.status_code == 409


def test_register_invalid_requests():
    res_bad_json = requests.post(
        f"{BASE_URL}/register",
        data="not-json",
        headers={"Content-Type": "application/json"},
    )
    assert res_bad_json.status_code == 400

    res_missing_user = requests.post(f"{BASE_URL}/register", json={"email": "a@b.com"})
    assert res_missing_user.status_code == 400


def test_auth_valid_jwt_and_logging():
    # Register a fresh user
    reg = requests.post(
        f"{BASE_URL}/register",
        json={"username": "authuser", "email": "auth@example.com"},
    )
    assert reg.status_code == 201
    password = reg.json()["password"]

    res = requests.post(
        f"{BASE_URL}/auth",
        json={"username": "authuser", "password": password},
    )
    assert res.status_code == 200
    token = res.json().get("token")
    assert token is not None

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"

    jwks = requests.get(f"{BASE_URL}/.well-known/jwks.json").json()
    target_jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

    public_numbers = RSAPublicNumbers(
        e=base64url_to_int(target_jwk["e"]),
        n=base64url_to_int(target_jwk["n"]),
    )
    pem = public_numbers.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    claims = jwt.decode(token, pem, algorithms=["RS256"])
    assert claims["sub"] == "authuser"
    assert claims["exp"] > int(time.time())

    # Verify the request was logged in auth_logs with the correct user_id and IP
    with db_connection(DB_FILE) as conn:
        user_row = conn.execute(
            "SELECT id, last_login FROM users WHERE username = ?", ("authuser",)
        ).fetchone()
        assert user_row["last_login"] is not None

        log_row = conn.execute(
            "SELECT request_ip, request_timestamp, user_id FROM auth_logs WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_row["id"],),
        ).fetchone()
        assert log_row is not None
        assert log_row["request_ip"] == "127.0.0.1"
        assert log_row["request_timestamp"] is not None


def test_auth_expired_jwt():
    res = requests.post(f"{BASE_URL}/auth?expired=true")
    assert res.status_code == 200
    token = res.json().get("token")
    assert token is not None

    header = jwt.get_unverified_header(token)
    row = main.get_key_by_kid(int(header["kid"]), db_file=DB_FILE)
    assert row["exp"] <= int(time.time())

    decrypted_pem = decrypt_private_key(row["key"])
    private_key = serialization.load_pem_private_key(decrypted_pem, password=None)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, pem, algorithms=["RS256"])


def test_auth_rate_limiter_and_unlogged_rejections():
    with db_connection(DB_FILE) as conn:
        before_count = conn.execute("SELECT COUNT(*) AS c FROM auth_logs").fetchone()["c"]

    def send_auth(_):
        return requests.post(f"{BASE_URL}/auth").status_code

    # Send 15 concurrent requests within the same 1-second window
    with ThreadPoolExecutor(max_workers=15) as executor:
        statuses = list(executor.map(send_auth, range(15)))

    assert statuses.count(200) == 10
    assert statuses.count(429) == 5

    # Only the 10 successful requests should be logged
    with db_connection(DB_FILE) as conn:
        after_count = conn.execute("SELECT COUNT(*) AS c FROM auth_logs").fetchone()["c"]
    assert after_count - before_count == 10


def test_dynamic_fallback_generation():
    test_db = "temp_fallback_test.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    conn = sqlite3.connect(test_db)
    try:
        conn.execute(
            "CREATE TABLE keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)"
        )
        conn.commit()
    finally:
        conn.close()

    valid_row = get_key_from_db(expired=False, db_file=test_db)
    assert valid_row["exp"] > int(time.time())

    expired_row = get_key_from_db(expired=True, db_file=test_db)
    assert expired_row["exp"] <= int(time.time())

    if os.path.exists(test_db):
        os.remove(test_db)


def test_http_error_methods_and_paths():
    assert requests.get(f"{BASE_URL}/auth").status_code == 405
    assert requests.get(f"{BASE_URL}/register").status_code == 405
    assert requests.post(f"{BASE_URL}/.well-known/jwks.json").status_code == 405
    assert requests.put(f"{BASE_URL}/auth").status_code == 405
    assert requests.delete(f"{BASE_URL}/auth").status_code == 405
    assert requests.patch(f"{BASE_URL}/auth").status_code == 405
    assert requests.get(f"{BASE_URL}/invalid").status_code == 404
    assert requests.post(f"{BASE_URL}/invalid").status_code == 404