import json
import threading
import time
from urllib import request, error

import jwt
import pytest

import main


@pytest.fixture
def temp_database(tmp_path, monkeypatch):
    db_path = tmp_path / "totally_not_my_privateKeys.db"
    monkeypatch.setattr(main, "DB_FILE", str(db_path))
    main.initialize_database()
    return db_path


def start_test_server():
    server = main.HTTPServer(("localhost", 0), main.MyServer)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server, thread


def test_database_has_valid_and_expired_keys(temp_database):
    expired = main.get_signing_key(expired=True)
    valid = main.get_signing_key(expired=False)

    assert expired is not None
    assert valid is not None

    now = int(time.time())
    assert expired[2] <= now
    assert valid[2] > now


def test_key_serialization():
    key = main.generate_private_key()
    pem = main.serialize_private_key(key)
    loaded = main.load_private_key(pem)

    assert loaded.private_numbers().public_numbers == key.private_numbers().public_numbers


def test_base64_conversion():
    assert main.int_to_base64(65537) == "AQAB"


def test_auth_valid_key(temp_database):
    server, thread = start_test_server()

    try:
        url = f"http://localhost:{server.server_port}/auth"
        req = request.Request(url, method="POST")

        with request.urlopen(req) as response:
            token = response.read().decode()

        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})

        assert response.status == 200
        assert header["alg"] == "RS256"
        assert payload["user"] == "username"
        assert payload["exp"] > int(time.time())

    finally:
        server.shutdown()
        thread.join()


def test_auth_expired_key(temp_database):
    server, thread = start_test_server()

    try:
        url = f"http://localhost:{server.server_port}/auth?expired=true"
        req = request.Request(url, method="POST")

        with request.urlopen(req) as response:
            token = response.read().decode()

        payload = jwt.decode(token, options={"verify_signature": False})

        assert response.status == 200
        assert payload["exp"] <= int(time.time())

    finally:
        server.shutdown()
        thread.join()


def test_auth_json_username(temp_database):
    server, thread = start_test_server()

    try:
        url = f"http://localhost:{server.server_port}/auth"
        body = json.dumps(
            {
                "username": "userABC",
                "password": "password123",
            }
        ).encode()

        req = request.Request(
            url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )

        with request.urlopen(req) as response:
            token = response.read().decode()

        payload = jwt.decode(token, options={"verify_signature": False})

        assert payload["user"] == "userABC"

    finally:
        server.shutdown()
        thread.join()


def test_jwks_only_contains_valid_keys(temp_database):
    server, thread = start_test_server()

    try:
        url = f"http://localhost:{server.server_port}/.well-known/jwks.json"

        with request.urlopen(url) as response:
            data = json.loads(response.read().decode())

        assert response.status == 200
        assert "keys" in data
        assert len(data["keys"]) >= 1

        valid_kid = str(main.get_signing_key(expired=False)[0])
        expired_kid = str(main.get_signing_key(expired=True)[0])

        kids = [key["kid"] for key in data["keys"]]

        assert valid_kid in kids
        assert expired_kid not in kids

        key = data["keys"][0]
        assert key["alg"] == "RS256"
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key

    finally:
        server.shutdown()
        thread.join()


def test_invalid_routes_and_methods(temp_database):
    server, thread = start_test_server()

    try:
        base = f"http://localhost:{server.server_port}"

        requests = [
            request.Request(base + "/bad", method="GET"),
            request.Request(base + "/bad", method="POST"),
            request.Request(base + "/", method="PUT"),
            request.Request(base + "/", method="PATCH"),
            request.Request(base + "/", method="DELETE"),
        ]

        for req in requests:
            with pytest.raises(error.HTTPError) as exc:
                request.urlopen(req)

            assert exc.value.code == 405

    finally:
        server.shutdown()
        thread.join()
