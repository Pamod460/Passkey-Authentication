"""Challenge management for WebAuthn operations (Redis cache, one-time use).

Every ceremony is bound to a random, single-use session token so challenges are
never shared between concurrent attempts and cannot be consumed or overwritten
by someone else who only knows an email address.
"""
import json
import os

import frappe

from .serialization import base64url_decode, base64url_encode

_PREFIX = "passkey_challenge:"


def _cache():
    c = frappe.cache
    # v15 exposes frappe.cache() as a function, newer versions a RedisWrapper object.
    if callable(c) and not hasattr(c, "set_value"):
        c = c()
    return c


def _get_ttl() -> int:
    try:
        s = frappe.get_single("Passkey Settings")
        if s.challenge_timeout:
            return int(s.challenge_timeout)
    except Exception:
        pass
    return 120


def generate_challenge() -> bytes:
    return os.urandom(32)


def _store(kind: str, token: str, payload: dict) -> None:
    _cache().set_value(f"{_PREFIX}{kind}:{token}", json.dumps(payload), expires_in_sec=_get_ttl())


def _pop(kind: str, token: str):
    """Return the stored payload (and delete it), or None."""
    if not token or not isinstance(token, str) or len(token) > 128:
        return None
    key = f"{_PREFIX}{kind}:{token}"
    cache = _cache()
    raw = cache.get_value(key)
    if not raw:
        return None
    cache.delete_value(key)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def new_token() -> str:
    return base64url_encode(os.urandom(18))


# -- registration (bound to the logged-in user) ------------------------------

def store_registration_challenge(user_email: str, challenge: bytes) -> None:
    _store("reg", base64url_encode(user_email.encode("utf-8")), {"c": base64url_encode(challenge)})


def get_and_clear_registration_challenge(user_email: str):
    data = _pop("reg", base64url_encode(user_email.encode("utf-8")))
    return base64url_decode(data["c"]) if data else None


# -- authentication (bound to a one-time session token) ----------------------

def store_authentication_challenge(challenge: bytes, user_email: str = None, kind: str = "auth") -> str:
    """`kind` keeps login ("auth") and step-up ("stepup") tokens in separate namespaces."""
    token = new_token()
    _store(kind, token, {"c": base64url_encode(challenge), "u": user_email})
    return token


def get_and_clear_authentication_challenge(token: str, kind: str = "auth"):
    """Return (challenge_bytes, user_email_or_None) or (None, None)."""
    data = _pop(kind, token)
    if not data:
        return None, None
    return base64url_decode(data["c"]), data.get("u")
