import base64
import json
import threading
import time
from http.server import HTTPServer
import pytest
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

import main
from main import JWKSRequestHandler, KeyManager, int_to_base64url


# Start server in a background thread for integration tests
@pytest.fixture(scope="module", autouse=True)
def start_test_server():
    server = HTTPServer(("127.0.0.1", 8080), JWKSRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(0.5)
    yield
    server.shutdown()


def base64url_to_int(val_str: str) -> int:
    """Decode base64url string to int."""
    rem = len(val_str) % 4
    if rem > 0:
        val_str += "=" * (4 - rem)
    val_bytes = base64.urlsafe_b64decode(val_str)
    return int.from_bytes(val_bytes, byteorder="big")


def test_int_to_base64url():
    val = 65537
    encoded = int_to_base64url(val)
    assert base64url_to_int(encoded) == val


def test_jwks_endpoint_returns_200_and_only_unexpired_keys():
    res = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")
    assert res.status_code == 200
    data = res.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    # Verify that 'expired-key-1' is NOT present in JWKS
    kids = [k["kid"] for k in data["keys"]]
    assert "expired-key-1" not in kids
    assert "active-key-1" in kids

    # Check JWK schema
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "n" in key
    assert "e" in key
    assert "kid" in key


def test_auth_valid_jwt():
    res = requests.post("http://127.0.0.1:8080/auth")
    assert res.status_code == 200
    body = res.json()
    token = body.get("token")
    assert token is not None

    # Inspect header and payload without verification first
    unverified_header = jwt.get_unverified_header(token)
    assert unverified_header["alg"] == "RS256"
    assert unverified_header["kid"] == "active-key-1"

    unverified_claims = jwt.decode(token, options={"verify_signature": False})
    assert unverified_claims["sub"] == "fake-user-123"
    assert unverified_claims["exp"] > int(time.time())

    # Verify signature against public key from JWKS
    jwks_res = requests.get("http://127.0.0.1:8080/.well-known/jwks.json").json()
    jwk = next(k for k in jwks_res["keys"] if k["kid"] == unverified_header["kid"])

    public_numbers = RSAPublicNumbers(
        e=base64url_to_int(jwk["e"]),
        n=base64url_to_int(jwk["n"])
    )
    public_key = public_numbers.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    verified = jwt.decode(token, pem, algorithms=["RS256"])
    assert verified["sub"] == "fake-user-123"


def test_auth_expired_jwt():
    res = requests.post("http://127.0.0.1:8080/auth?expired=true")
    assert res.status_code == 200
    token = res.json().get("token")
    assert token is not None

    unverified_header = jwt.get_unverified_header(token)
    assert unverified_header["kid"] == "expired-key-1"

    unverified_claims = jwt.decode(token, options={"verify_signature": False})
    assert unverified_claims["exp"] < int(time.time())

    # Decoding with expiration verification should fail with ExpiredSignatureError
    with pytest.raises(jwt.ExpiredSignatureError):
        expired_record = main.KEY_MANAGER.get_expired_key()
        pem = expired_record["public_key"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        jwt.decode(token, pem, algorithms=["RS256"])


def test_http_methods_and_status_codes():
    # GET on /auth -> 405 Method Not Allowed
    res = requests.get("http://127.0.0.1:8080/auth")
    assert res.status_code == 405

    # POST on JWKS endpoint -> 405 Method Not Allowed
    res = requests.post("http://127.0.0.1:8080/.well-known/jwks.json")
    assert res.status_code == 405

    # Unsupported methods
    res = requests.put("http://127.0.0.1:8080/auth")
    assert res.status_code == 405
    res = requests.delete("http://127.0.0.1:8080/auth")
    assert res.status_code == 405
    res = requests.patch("http://127.0.0.1:8080/auth")
    assert res.status_code == 405

    # Unknown endpoints -> 404
    res = requests.get("http://127.0.0.1:8080/unknown-route")
    assert res.status_code == 404
    res = requests.post("http://127.0.0.1:8080/unknown-route")
    assert res.status_code == 404


def test_key_manager_dynamic_fallbacks():
    km = KeyManager()
    km.keys = []
    valid_key = km.get_valid_key()
    assert valid_key["expires_at"] > int(time.time())

    km.keys = []
    expired_key = km.get_expired_key()
    assert expired_key["expires_at"] <= int(time.time())