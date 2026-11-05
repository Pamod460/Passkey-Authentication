#!/usr/bin/env python3
"""Smoke test a real site running passkey_authentication.

Checks the public endpoints, then (with --user/--password) runs a full passkey
registration and login against the site with a software authenticator, and deletes
the test passkey again.

    pip install "webauthn>=2.5,<3" cbor2 cryptography
    python scripts/smoke_test.py https://erp.example.com
    python scripts/smoke_test.py https://erp.example.com --user test@example.com --password '...'

Use a test account that may sign in with a password and has no two-factor
authentication. The account gets the usual "new passkey added" email.
Exit code 0 means every check passed.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "/api/method/passkey_authentication.passkey_authentication.api."
RESULTS = []


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def report(ok, title, detail=""):
    RESULTS.append(ok)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {title}" + (f": {detail}" if detail else ""))
    return ok


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def request(self, path, data=None, method=None):
        url = self.base + path
        headers = {"Accept": "application/json"}
        body = None
        if data is not None:
            body = urllib.parse.urlencode(
                {k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in data.items()}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.csrf:
            headers["X-Frappe-CSRF-Token"] = self.csrf
        req = urllib.request.Request(url, data=body, headers=headers, method=method or ("POST" if body else "GET"))
        try:
            with self.opener.open(req, timeout=30) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def call(self, method, **data):
        status, _h, raw = self.request(API + method, data or {}, method="POST")
        try:
            return json.loads(raw).get("message") or {}
        except ValueError:
            return {"success": False, "message": f"HTTP {status}: {raw[:200]!r}"}

    def load_csrf(self):
        _s, _h, raw = self.request("/app")
        m = re.search(rb'csrf_token\s*=\s*"([^"]+)"', raw)
        self.csrf = m.group(1).decode() if m else None


class SoftAuthenticator:
    """Minimal ES256 'none'-attestation authenticator, for testing only."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0

    def create(self, options, origin):
        import cbor2
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(options["rp"]["id"].encode()).digest() + bytes([0x45])
                     + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", 32) + self.cred_id + cose)
        cd = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att), "transports": ["internal"]},
                "authenticatorAttachment": "platform", "clientExtensionResults": {}}

    def get(self, options, origin):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.count += 1
        auth_data = hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        cd = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        sig = self.key.sign(auth_data + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig)},
                "authenticatorAttachment": "platform", "clientExtensionResults": {}}


def check_public(client, host):
    parsed = urllib.parse.urlparse(client.base)
    report(parsed.scheme == "https" or host in ("localhost", "127.0.0.1"), "Site uses HTTPS", client.base)

    for path in ("/.well-known/webauthn", "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association"):
        status, headers, raw = client.request(path)
        try:
            json.loads(raw)
            parsed_ok = True
        except ValueError:
            parsed_ok = False
        ctype = headers.get("Content-Type", "") if headers else ""
        report(status == 200 and parsed_ok and "json" in ctype, f"GET {path}",
               f"HTTP {status}, {ctype or 'no content type'}")

    status = client.call("get_status")
    report(bool(status.get("enabled")), "Passkeys enabled", json.dumps(status))
    opts = client.call("authentication_options")
    rp_id = (opts.get("options") or {}).get("rpId")
    ok = bool(rp_id) and (host == rp_id or host.endswith("." + rp_id))
    report(ok, "Login options RP ID matches this host", f"rpId={rp_id}, host={host}" if opts.get("success")
           else opts.get("message", ""))
    return rp_id


def check_ceremonies(client, user, password, origin):
    status, _h, raw = client.request("/api/method/login", {"usr": user, "pwd": password}, method="POST")
    if not report(status == 200, "Password login for the test user", f"HTTP {status} {raw[:120]!r}"):
        return
    client.load_csrf()
    report(bool(client.csrf), "CSRF token found on /app")

    auth = SoftAuthenticator()
    opts = client.call("registration_options")
    if not report(opts.get("success"), "Registration options", opts.get("message", "")):
        return
    res = client.call("verify_registration", credential=auth.create(opts["options"], origin))
    if not report(res.get("success"), "Passkey registered", res.get("message", "")):
        return
    credential_name = res.get("credential_name")

    client.request("/api/method/logout")
    client.csrf = None
    opts = client.call("authentication_options", user_email=user)
    if report(opts.get("success"), "Login options for the test user", opts.get("message", "")):
        res = client.call("verify_authentication", credential=auth.get(opts["options"], origin),
                          session_token=opts["session_token"])
        report(res.get("success"), "Passkey login", res.get("message", ""))
        _s, _h, raw = client.request("/api/method/frappe.auth.get_logged_user")
        try:
            logged = json.loads(raw).get("message")
        except ValueError:
            logged = None
        report(logged == user, "Session belongs to the test user", str(logged))

    # Clean up (needs a session: the passkey login, or the password if that failed).
    if not client.call("list_credentials").get("success"):
        client.request("/api/method/login", {"usr": user, "pwd": password}, method="POST")
    client.load_csrf()
    res = client.call("delete_credential", credential_name=credential_name)
    report(res.get("success"), "Test passkey deleted", res.get("message", ""))
    client.request("/api/method/logout")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("site", help="Site URL, e.g. https://erp.example.com")
    parser.add_argument("--user", help="Test account for the full registration/login run")
    parser.add_argument("--password", help="Password of the test account")
    args = parser.parse_args()

    client = Client(args.site)
    parsed = urllib.parse.urlparse(client.base)
    host = (parsed.hostname or "").lower()
    origin = f"{parsed.scheme}://{parsed.netloc}"
    check_public(client, host)
    if args.user and args.password:
        try:
            import cbor2  # noqa: F401
            import cryptography  # noqa: F401
        except ImportError:
            report(False, "Ceremony test needs: pip install cbor2 cryptography")
        else:
            check_ceremonies(client, args.user, args.password, origin)
    else:
        print("(Skipping registration/login: pass --user and --password to run it.)")

    failed = RESULTS.count(False)
    print(f"\n{len(RESULTS) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
