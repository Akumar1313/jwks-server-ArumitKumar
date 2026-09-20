"""
JWKS Server Implementation
Fulfills RESTful JWKS endpoint and /auth JWT issuance requirements.
"""

import base64
import json
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt


def int_to_base64url(val: int) -> str:
    """Encode an integer as an unpadded base64url string per RFC 7515/RFC 7517."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


class KeyManager:
    """Generates and manages RSA key pairs with kid and expiration timestamps."""

    def __init__(self):
        self.keys = []
        self._init_keys()

    def generate_key(self, expires_at: int, kid: str = None):
        """Generates an RSA private key and stores its metadata."""
        if kid is None:
            kid = str(uuid.uuid4())

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        key_record = {
            "kid": kid,
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "expires_at": expires_at
        }
        self.keys.append(key_record)
        return key_record

    def _init_keys(self):
        """Pre-seeds an active key and an expired key."""
        now = int(time.time())
        # Unexpired key (valid for 1 hour)
        self.generate_key(expires_at=now + 3600, kid="active-key-1")
        # Expired key (expired 1 hour ago)
        self.generate_key(expires_at=now - 3600, kid="expired-key-1")

    def get_valid_key(self):
        """Returns the first non-expired key record."""
        now = int(time.time())
        for k in self.keys:
            if k["expires_at"] > now:
                return k
        # If none found, generate one dynamically
        return self.generate_key(expires_at=now + 3600)

    def get_expired_key(self):
        """Returns the first expired key record."""
        now = int(time.time())
        for k in self.keys:
            if k["expires_at"] <= now:
                return k
        # If none found, generate one dynamically
        return self.generate_key(expires_at=now - 3600)

    def get_jwks(self):
        """Returns the JWKS dictionary containing only unexpired public keys."""
        now = int(time.time())
        jwk_list = []

        for k in self.keys:
            if k["expires_at"] > now:
                pub_numbers = k["public_key"].public_numbers()
                jwk = {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": k["kid"],
                    "n": int_to_base64url(pub_numbers.n),
                    "e": int_to_base64url(pub_numbers.e)
                }
                jwk_list.append(jwk)

        return {"keys": jwk_list}


# Shared key manager instance
KEY_MANAGER = KeyManager()


class JWKSRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for JWKS and Auth endpoints."""

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

        # Standard well-known JWKS endpoint
        if parsed.path == "/.well-known/jwks.json":
            jwks_data = KEY_MANAGER.get_jwks()
            self._send_json(200, jwks_data)
            return

        # Handle disallowed methods on /auth or 404s
        if parsed.path == "/auth":
            self._send_error_status(405, "Method Not Allowed")
            return

        self._send_error_status(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/auth":
            query_params = parse_qs(parsed.query)
            # Check for the ?expired flag
            is_expired = "expired" in query_params

            now = int(time.time())
            if is_expired:
                key_record = KEY_MANAGER.get_expired_key()
                exp_time = key_record["expires_at"]
            else:
                key_record = KEY_MANAGER.get_valid_key()
                exp_time = key_record["expires_at"]

            payload = {
                "sub": "fake-user-123",
                "iat": now if not is_expired else exp_time - 3600,
                "exp": exp_time,
                "iss": "jwks-auth-server"
            }

            headers = {
                "kid": key_record["kid"],
                "alg": "RS256"
            }

            # Serialize private key to PEM for PyJWT signing
            pem_private_key = key_record["private_key"].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            token = jwt.encode(
                payload=payload,
                key=pem_private_key,
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
    server_address = ("", port)
    httpd = HTTPServer(server_address, JWKSRequestHandler)
    print(f"JWKS Server serving on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server(8080)