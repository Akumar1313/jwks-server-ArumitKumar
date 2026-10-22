import base64
import os
import sqlite3
import threading
import time
from http.server import HTTPServer
import pytest
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

import main
from main import (
    JWKSRequestHandler,
    int_to_base64url,
    get_db_connection,
    init_db,
    insert_key,
    get_key_from_db,
    get_valid_jwks,
    DB_FILE,
)


@pytest.fixture(scope="module", autouse=True)
def setup_server_and_db():
    # Fresh database for test run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

    init_db(DB_FILE)

    server = HTTPServer(("127.0.0.1", 8080), JWKSRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.5)

    yield

    server.shutdown()
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)


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


def test_db_table_and_initial_keys_exist():
    conn = get_db_connection(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
    assert cursor.fetchone() is not None

    now = int(time.time())
    cursor.execute("SELECT COUNT(*) AS total FROM keys WHERE exp > ?", (now,))
    assert cursor.fetchone()["total"] >= 1

    cursor.execute("SELECT COUNT(*) AS total FROM keys WHERE exp <= ?", (now,))
    assert cursor.fetchone()["total"] >= 1
    conn.close()


def test_jwks_endpoint_returns_only_valid_keys():
    res = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")
    assert res.status_code == 200
    data = res.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    # Verify no expired keys appear in JWKS
    now = int(time.time())
    conn = get_db_connection(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT kid FROM keys WHERE exp <= ?", (now,))
    expired_kids = {str(row["kid"]) for row in cursor.fetchall()}
    conn.close()

    returned_kids = {k["kid"] for k in data["keys"]}
    assert returned_kids.isdisjoint(expired_kids)


def test_auth_valid_jwt():
    res = requests.post(
        "http://127.0.0.1:8080/auth",
        json={"username": "userABC", "password": "password123"}
    )
    assert res.status_code == 200
    token = res.json().get("token")
    assert token is not None

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"

    # Decode and verify signature using public key from JWKS
    jwks = requests.get("http://127.0.0.1:8080/.well-known/jwks.json").json()
    target_jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

    public_numbers = RSAPublicNumbers(
        e=base64url_to_int(target_jwk["e"]),
        n=base64url_to_int(target_jwk["n"])
    )
    public_key = public_numbers.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    claims = jwt.decode(token, pem, algorithms=["RS256"])
    assert claims["sub"] == "fake-user-123"
    assert claims["exp"] > int(time.time())


def test_auth_expired_jwt():
    res = requests.post("http://127.0.0.1:8080/auth?expired=true")
    assert res.status_code == 200
    token = res.json().get("token")
    assert token is not None

    header = jwt.get_unverified_header(token)
    row = main.get_key_by_kid(int(header["kid"]), db_file=DB_FILE)
    assert row["exp"] <= int(time.time())

    # Verifying an expired JWT must raise ExpiredSignatureError
    private_key = serialization.load_pem_private_key(row["key"], password=None)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, pem, algorithms=["RS256"])


def test_dynamic_fallback_generation():
    test_db = "temp_fallback_test.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    # Empty table
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)")
    conn.close()

    # Must generate and return valid row
    valid_row = get_key_from_db(expired=False, db_file=test_db)
    assert valid_row["exp"] > int(time.time())

    # Must generate and return expired row
    expired_row = get_key_from_db(expired=True, db_file=test_db)
    assert expired_row["exp"] <= int(time.time())

    if os.path.exists(test_db):
        os.remove(test_db)


def test_http_error_methods_and_paths():
    assert requests.get("http://127.0.0.1:8080/auth").status_code == 405
    assert requests.post("http://127.0.0.1:8080/.well-known/jwks.json").status_code == 405
    assert requests.put("http://127.0.0.1:8080/auth").status_code == 405
    assert requests.delete("http://127.0.0.1:8080/auth").status_code == 405
    assert requests.patch("http://127.0.0.1:8080/auth").status_code == 405
    assert requests.get("http://127.0.0.1:8080/invalid").status_code == 404
    assert requests.post("http://127.0.0.1:8080/invalid").status_code == 404