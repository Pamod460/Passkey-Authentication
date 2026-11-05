"""Base64URL encoding/decoding utilities for WebAuthn."""
import base64


def base64url_encode(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("input must be a string")
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def base64url_to_hex(s: str) -> str:
    return base64url_decode(s).hex()


def hex_to_base64url(hex_str: str) -> str:
    return base64url_encode(bytes.fromhex(hex_str))
