from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import sqlite3
import time

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, "x")

    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex

    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def generate_private_key():
    """Generate a new RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def serialize_private_key(private_key):
    """Serialize an RSA private key to PKCS1 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def initialize_database():
    """Create the database/table and ensure valid and expired keys exist."""
    current_time = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
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

        # Make sure at least one expired key exists.
        cursor.execute(
            "SELECT kid FROM keys WHERE exp <= ? LIMIT 1",
            (current_time,),
        )

        if cursor.fetchone() is None:
            expired_key = serialize_private_key(generate_private_key())

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (expired_key, current_time - 3600),
            )

        # Make sure at least one valid key exists.
        cursor.execute(
            "SELECT kid FROM keys WHERE exp >= ? LIMIT 1",
            (current_time + 3600,),
        )

        if cursor.fetchone() is None:
            valid_key = serialize_private_key(generate_private_key())

            # Two hours gives us plenty of time above the 1-hour requirement.
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (valid_key, current_time + 7200),
            )

        conn.commit()


def get_signing_key(expired=False):
    """Read either a valid or expired private key from SQLite."""
    current_time = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        if expired:
            cursor.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (current_time,),
            )
        else:
            cursor.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (current_time,),
            )

        return cursor.fetchone()


def get_valid_keys():
    """Read every non-expired key from SQLite."""
    current_time = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            ORDER BY kid
            """,
            (current_time,),
        )
        return cursor.fetchall()


def load_private_key(pem_data):
    """Deserialize PKCS1 PEM bytes into an RSA private key."""
    return serialization.load_pem_private_key(
        pem_data,
        password=None,
    )


class MyServer(BaseHTTPRequestHandler):

    def send_body(self, status, body=b"", content_type="text/plain"):
        """Send an HTTP response with a body."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        if body:
            self.wfile.write(body)

    def do_PUT(self):
        self.send_body(405)

    def do_PATCH(self):
        self.send_body(405)

    def do_DELETE(self):
        self.send_body(405)

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path != "/auth":
            self.send_body(405)
            return

        # Consume an optional JSON or Basic-auth request body.
        content_length = int(self.headers.get("Content-Length", 0))
        request_body = b""

        if content_length:
            request_body = self.rfile.read(content_length)

        username = "username"

        if request_body:
            try:
                request_json = json.loads(request_body.decode("utf-8"))
                username = request_json.get("username", username)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        params = parse_qs(parsed_path.query, keep_blank_values=True)
        use_expired_key = "expired" in params

        key_row = get_signing_key(expired=use_expired_key)

        if key_row is None:
            self.send_body(500, b"No signing key available")
            return

        kid, key_blob, key_expiration = key_row
        private_key = load_private_key(key_blob)

        token_payload = {
            "user": username,
            "exp": key_expiration,
        }

        headers = {
            "kid": str(kid),
        }

        encoded_jwt = jwt.encode(
            token_payload,
            private_key,
            algorithm="RS256",
            headers=headers,
        )

        if isinstance(encoded_jwt, str):
            encoded_jwt = encoded_jwt.encode("utf-8")

        self.send_body(
            200,
            encoded_jwt,
            "text/plain",
        )

    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path != "/.well-known/jwks.json":
            self.send_body(405)
            return

        jwks = {"keys": []}

        for kid, key_blob, _ in get_valid_keys():
            private_key = load_private_key(key_blob)
            public_numbers = private_key.public_key().public_numbers()

            jwks["keys"].append(
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                }
            )

        body = json.dumps(jwks).encode("utf-8")

        self.send_body(
            200,
            body,
            "application/json",
        )


if __name__ == "__main__":
    initialize_database()

    webServer = HTTPServer((hostName, serverPort), MyServer)

    print(f"Server started at http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
