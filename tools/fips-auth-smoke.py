#!/usr/bin/env python3
"""Exercise FIPS authentication through Vaultwarden's public routes with local fixtures."""

import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DOMAIN = "https://vaultwarden.test"
DUO_SECRET = b"local-duo-fixture-shared-secret-0123456789"
YUBICO_SECRET = b"local-yubico-api-key"
PASSWORD_HASH = base64.b64encode(hashlib.sha256(b"local-fips-test-password").digest()).decode()
PKCE = "correct-test-verifier-with-at-least-forty-three-characters"
CLIENT_HEADERS = {"Bitwarden-Client-Version": "2026.10.2", "Device-Type": "14", "X-Forwarded-Proto": "https"}


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode_url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def jwt(algorithm, claims, sign, *, kid=None):
    header = {"alg": algorithm, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    message = f"{b64url(json_bytes(header))}.{b64url(json_bytes(claims))}"
    return f"{message}.{b64url(sign(message.encode()))}"


def duo_claims(token):
    header, claims, signature = token.split(".")
    assert json.loads(decode_url(header))["alg"] == "HS512"
    expected = hmac.digest(DUO_SECRET, f"{header}.{claims}".encode(), "sha512")
    assert hmac.compare_digest(expected, decode_url(signature)), "Duo request signature"
    return json.loads(decode_url(claims))


def query(url):
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def issue_certificates(directory):
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vaultwarden local fixture CA")])
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    def certificate(subject, public_key, *, ca):
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        )
        if not ca:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    ca_path = directory / "ca.pem"
    leaf_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(certificate(ca_name, ca_key.public_key(), ca=True))
    leaf_path.write_bytes(certificate(server_name, server_key.public_key(), ca=False))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca_path, leaf_path, key_path


class Provider(BaseHTTPRequestHandler):
    """Minimal HTTPS OIDC, Duo, and Yubico OTP endpoints."""

    def log_message(self, *_args):
        pass

    def reply(self, body, content_type="application/json"):
        if isinstance(body, dict):
            body = json_bytes(body)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @property
    def origin(self):
        return f"https://localhost:{self.server.server_port}"

    def do_GET(self):
        path = urlsplit(self.path).path
        issuer = self.origin + "/oidc"
        if path == "/oidc/.well-known/openid-configuration":
            self.reply(
                {
                    "issuer": issuer,
                    "jwks_uri": issuer + "/jwks",
                    "authorization_endpoint": issuer + "/authorize",
                    "token_endpoint": issuer + "/token",
                    "userinfo_endpoint": issuer + "/userinfo",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                }
            )
        elif path == "/oidc/jwks":
            public_key = self.server.oidc_key.public_key().public_numbers()
            self.reply(
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "kid": "local-key",
                            "n": b64url(public_key.n.to_bytes(256, "big")),
                            "e": b64url(public_key.e.to_bytes(3, "big")),
                        }
                    ]
                }
            )
        elif path == "/oidc/userinfo":
            assert self.headers["Authorization"] == "Bearer local-access-token"
            self.reply({"sub": "fips-oidc-subject", "email": "sso@vaultwarden.test", "email_verified": True})
        elif path == "/auth/v2/check":
            credentials = self.headers["Authorization"].removeprefix("Basic ")
            user, mac = base64.b64decode(credentials).decode().split(":", 1)
            canonical = "\n".join((self.headers["Date"], "GET", self.headers["Host"], path, ""))
            assert user == "local-duo-client" and hmac.compare_digest(
                mac, hmac.digest(DUO_SECRET, canonical.encode(), "sha1").hex()
            )
            self.reply({"stat": "OK"})
        elif path == "/yubico":
            params = query(self.path)
            supplied = base64.b64decode(params.pop("h"))
            canonical = "&".join(f"{key}={value}" for key, value in sorted(params.items()))
            assert hmac.compare_digest(supplied, hmac.digest(YUBICO_SECRET, canonical.encode(), "sha1"))
            assert len(params["nonce"]) == 40 and params["nonce"] not in self.server.yubi_nonces
            self.server.yubi_nonces.add(params["nonce"])
            response = {"nonce": params["nonce"], "otp": params["otp"], "status": "OK"}
            canonical = "&".join(f"{key}={value}" for key, value in sorted(response.items()))
            key = b"wrong-fixture-key" if params["otp"].endswith("r") else YUBICO_SECRET
            response["h"] = base64.b64encode(hmac.digest(key, canonical.encode(), "sha1")).decode()
            self.reply("".join(f"{key}={value}\r\n" for key, value in response.items()).encode(), "text/plain")
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlsplit(self.path).path
        form = query("?" + self.rfile.read(int(self.headers["Content-Length"])).decode())
        if path == "/oidc/token":
            assert (
                self.headers["Authorization"]
                == "Basic " + base64.b64encode(b"local-oidc-client:local-oidc-secret").decode()
            )
            assert form["code_verifier"] == PKCE and form["grant_type"] == "authorization_code"
            claims = {
                "iss": self.origin + "/oidc",
                "sub": "fips-oidc-subject",
                "aud": "local-oidc-client",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
                "nonce": self.server.oidc_nonce,
                "email": "sso@vaultwarden.test",
                "email_verified": True,
            }
            key = self.server.bad_oidc_key if form["code"] == "oidc-bad" else self.server.oidc_key
            token = jwt(
                "RS256",
                claims,
                lambda message: key.sign(message, padding.PKCS1v15(), hashes.SHA256()),
                kid="local-key",
            )
            self.reply(
                {"id_token": token, "access_token": "local-access-token", "token_type": "Bearer", "expires_in": 300}
            )
        elif path in ("/oauth/v1/health_check", "/oauth/v1/token"):
            assertion = duo_claims(form["client_assertion"])
            assert assertion["iss"] == "local-duo-client" and assertion["aud"] == self.origin + path
            if path.endswith("health_check"):
                self.reply({"stat": "OK"})
                return
            challenge = self.server.duo_challenge
            claims = {
                "aud": "local-duo-client",
                "iss": self.origin + path,
                "exp": int(time.time()) + 300,
                "nonce": challenge["nonce"],
                "preferred_username": challenge["duo_uname"],
            }
            key = b"invalid-duo-fixture-signature" if form["code"] == "duo-bad" else DUO_SECRET
            self.reply(
                {
                    "id_token": jwt("HS512", claims, lambda message: hmac.digest(key, message, "sha512")),
                    "access_token": "fixture",
                    "expires_in": 300,
                    "token_type": "Bearer",
                }
            )
        else:
            self.send_error(404)


class Vaultwarden:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, *, data=None, form=None, headers=None, expected=200):
        req_headers = {**CLIENT_HEADERS, **(headers or {})}
        payload = None
        if data is not None:
            payload = json_bytes(data)
            req_headers["Content-Type"] = "application/json"
        if form is not None:
            payload = urlencode(form)
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, payload, req_headers)
            response = conn.getresponse()
            body = response.read()
            assert response.status == expected, (method, path, response.status, body.decode(errors="replace"))
            metadata = {key.lower(): value for key, value in response.getheaders()}
            return json.loads(body) if metadata.get("content-type", "").startswith("application/json") else metadata
        finally:
            conn.close()

    def register(self, email):
        verification = self.request(
            "POST",
            "/identity/accounts/register/send-verification-email",
            headers={"Accept": "application/json"},
            data={"email": email},
        )
        self.request(
            "POST",
            "/identity/accounts/register/finish",
            data={
                "email": email,
                "masterPasswordHash": PASSWORD_HASH,
                "emailVerificationToken": verification,
                "kdf": 0,
                "kdfIterations": 600000,
                "key": "fixture",
                "keys": {"encryptedPrivateKey": "fixture", "publicKey": "fixture"},
            },
        )

    def grant(self, *, expected=200, **form):
        return self.request(
            "POST",
            "/identity/connect/token",
            expected=expected,
            form={
                "scope": "api offline_access",
                "client_id": "web",
                "deviceType": "14",
                "deviceName": "local test",
                **form,
            },
        )

    def password(self, email, device, *, expected=200, **form):
        return self.grant(
            expected=expected,
            grant_type="password",
            username=email,
            password=PASSWORD_HASH,
            deviceIdentifier=device,
            **form,
        )

    def setup(self, email, provider):
        self.register(email)
        access_token = self.password(email, str(uuid.uuid4()))["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        data = self.request(
            "POST", f"/api/two-factor/get-{provider}", headers=headers, data={"masterPasswordHash": PASSWORD_HASH}
        )
        return headers, data["userVerificationToken"]


def check_sso(vault, provider):
    vault.register("sso@vaultwarden.test")
    for code, expected, verifier in (
        ("oidc-bad", 400, PKCE),
        ("oidc-wrong-pkce", 400, "x" * 43),
        ("oidc-good", 200, PKCE),
    ):
        state = uuid.uuid4().hex
        metadata = vault.request(
            "GET",
            "/identity/connect/authorize?"
            + urlencode(
                {
                    "client_id": "web",
                    "redirect_uri": DOMAIN + "/sso-connector.html",
                    "state": state,
                    "code_challenge_method": "S256",
                    "code_challenge": b64url(hashlib.sha256(PKCE.encode()).digest()),
                }
            ),
            expected=307,
        )
        auth = query(metadata["location"])
        provider.oidc_nonce = auth["nonce"]
        cookie = metadata["set-cookie"].split(";", 1)[0]
        vault.request(
            "GET",
            "/identity/connect/oidc-signin?" + urlencode({"code": code, "state": auth["state"]}),
            headers={"Cookie": cookie},
            expected=307,
        )
        result = vault.grant(
            expected=expected,
            grant_type="authorization_code",
            code=code,
            code_verifier=verifier,
            deviceIdentifier=str(uuid.uuid4()),
        )
        assert ("access_token" in result) == (expected == 200)
        if verifier != PKCE:
            assert "PKCE client challenge failed" in result["message"], result
    print("SSO accepted a signed RS256 token and rejected an invalid signature and PKCE verifier", flush=True)


def check_duo(vault, provider):
    email = "duo@vaultwarden.test"
    headers, token = vault.setup(email, "duo")
    vault.request(
        "POST",
        "/api/two-factor/duo",
        headers=headers,
        data={
            "host": f"localhost:{provider.server_port}",
            "clientId": "local-duo-client",
            "clientSecret": DUO_SECRET.decode(),
            "userVerificationToken": token,
        },
    )
    device = str(uuid.uuid4())
    for code, expected in (("duo-bad", 400), ("duo-good", 200)):
        required = vault.password(email, device, expected=400)["TwoFactorProviders2"]["2"]["AuthUrl"]
        provider.duo_challenge = duo_claims(query(required)["request"])
        state = provider.duo_challenge["state"]
        result = vault.password(
            email, device, expected=expected, twoFactorProvider=2, twoFactorToken=f"{code}|{state}"
        )
        assert ("access_token" in result) == (expected == 200)
    print("Duo accepted valid HMAC responses and rejected an invalid token signature", flush=True)


def check_yubico(vault):
    email = "yubi@vaultwarden.test"
    headers, token = vault.setup(email, "yubikey")
    vault.request(
        "POST",
        "/api/two-factor/yubikey",
        headers=headers,
        data={"key1": "c" * 44, "nfc": False, "userVerificationToken": token},
    )
    device = str(uuid.uuid4())
    for otp, expected in (("c" * 43 + "r", 400), ("c" * 43 + "v", 200)):
        result = vault.password(email, device, expected=expected, twoFactorProvider=3, twoFactorToken=otp)
        assert ("access_token" in result) == (expected == 200)
    print("Yubico OTP accepted a signed verification response and rejected an invalid MAC", flush=True)


def cbor(value):
    """Encode the small CBOR subset needed by the software authenticator fixture."""

    def header(major, size):
        return bytes([major << 5 | size]) if size < 24 else bytes([major << 5 | 24, size])

    if isinstance(value, int):
        return header(0, value) if value >= 0 else header(1, -1 - value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return header(3, len(encoded)) + encoded
    if isinstance(value, dict):
        return header(5, len(value)) + b"".join(cbor(key) + cbor(element) for key, element in value.items())
    raise TypeError(type(value))


def check_webauthn(vault):
    email = "webauthn@vaultwarden.test"
    headers, token = vault.setup(email, "webauthn")
    options = vault.request(
        "POST", "/api/two-factor/get-webauthn-challenge", headers=headers, data={"userVerificationToken": token}
    )["options"]
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    cose = cbor({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")})
    credential_id = uuid.uuid4().bytes
    identity = {"id": b64url(credential_id), "rawId": b64url(credential_id), "type": "public-key"}
    rp_hash = hashlib.sha256(b"vaultwarden.test").digest()
    registration = rp_hash + b"\x41" + b"\0" * 20 + len(credential_id).to_bytes(2, "big") + credential_id + cose
    client = json_bytes(
        {"type": "webauthn.create", "challenge": options["challenge"], "origin": DOMAIN, "crossOrigin": False}
    )
    device_response = {
        **identity,
        "response": {
            "attestationObject": b64url(cbor({"fmt": "none", "attStmt": {}, "authData": registration})),
            "clientDataJson": b64url(client),
        },
    }
    vault.request(
        "POST",
        "/api/two-factor/webauthn",
        headers=headers,
        data={"id": 1, "name": "Local ES256 key", "deviceResponse": device_response, "userVerificationToken": token},
    )
    device = str(uuid.uuid4())
    for signer, expected in ((ec.generate_private_key(ec.SECP256R1()), 400), (key, 200)):
        challenge = vault.password(email, device, expected=400)["TwoFactorProviders2"]["7"]["challenge"]
        client = json_bytes({"type": "webauthn.get", "challenge": challenge, "origin": DOMAIN, "crossOrigin": False})
        authenticator_data = rp_hash + b"\x01" + (1).to_bytes(4, "big")
        signature = signer.sign(authenticator_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        assertion = {
            **identity,
            "extensions": {},
            "response": {
                "authenticatorData": b64url(authenticator_data),
                "clientDataJson": b64url(client),
                "signature": b64url(signature),
            },
        }
        result = vault.password(
            email, device, expected=expected, twoFactorProvider=7, twoFactorToken=json.dumps(assertion)
        )
        assert ("access_token" in result) == (expected == 200)
    print("WebAuthn enrolled an ES256 software key, accepted its assertion and rejected a different key", flush=True)


def main(binary):
    with tempfile.TemporaryDirectory(prefix="vaultwarden-fips-auth-") as temp:
        directory = Path(temp)
        ca, leaf, key = issue_certificates(directory)
        with ThreadingHTTPServer(("127.0.0.1", 0), Provider) as provider:
            provider.oidc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            provider.bad_oidc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            provider.yubi_nonces = set()
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.load_cert_chain(leaf, key)
            provider.socket = tls.wrap_socket(provider.socket, server_side=True)
            threading.Thread(target=provider.serve_forever, daemon=True).start()
            host = f"localhost:{provider.server_port}"
            data = directory / "data"
            data.mkdir()
            env = dict(
                os.environ,
                ENV_FILE="/dev/null",
                DOMAIN=DOMAIN,
                DATA_FOLDER=str(data),
                ROCKET_ADDRESS="127.0.0.1",
                ROCKET_PORT="18080",
                WEB_VAULT_ENABLED="false",
                SIGNUPS_ALLOWED="true",
                LOGIN_RATELIMIT_MAX_BURST="50",
                HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS="false",
                SSL_CERT_FILE=str(ca),
                SSO_ENABLED="true",
                SSO_PKCE="true",
                SSO_AUTHORITY=f"https://{host}/oidc",
                SSO_CLIENT_ID="local-oidc-client",
                SSO_CLIENT_SECRET="local-oidc-secret",
                SSO_SIGNUPS_MATCH_EMAIL="true",
                SSO_AUTH_ONLY_NOT_SESSION="true",
                DUO_HOST=host,
                DUO_SKEY=DUO_SECRET.decode(),
                DUO_IKEY="local-duo-client",
                YUBICO_SERVER=f"https://{host}/yubico",
                YUBICO_CLIENT_ID="123",
                YUBICO_SECRET_KEY=base64.b64encode(YUBICO_SECRET).decode(),
            )
            assert "AWS-LC FIPS mode active" in subprocess.check_output([binary, "--version"], env=env, text=True)
            log = directory / "server.log"
            with log.open("w") as output:
                server = subprocess.Popen([binary], env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                vault = Vaultwarden(18080)
                for _ in range(100):
                    assert server.poll() is None, "Vaultwarden exited at startup"
                    with contextlib.suppress(OSError):
                        vault.request("GET", "/alive")
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Vaultwarden failed to start")
                check_sso(vault, provider)
                check_webauthn(vault)
                check_duo(vault, provider)
                check_yubico(vault)
            except Exception:
                print(log.read_text(), file=sys.stderr)
                raise
            finally:
                if server.poll() is None:
                    server.terminate()
                    server.wait(timeout=15)
                provider.shutdown()


if __name__ == "__main__":
    main(sys.argv[1])
