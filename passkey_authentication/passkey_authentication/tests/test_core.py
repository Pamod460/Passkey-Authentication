"""Unit tests for pure helpers (no bench required)."""
import unittest

try:
    import frappe  # noqa: F401
    HAS_FRAPPE = True
except ImportError:
    HAS_FRAPPE = False


class TestBase64URL(unittest.TestCase):
    def test_roundtrip(self):
        from passkey_authentication.passkey_authentication.serialization import base64url_decode, base64url_encode
        for data in [b"", b"hello", b"\x00\x01\x02", b"\xff\xfe", b"x" * 100, bytes(range(256))]:
            self.assertEqual(data, base64url_decode(base64url_encode(data)))

    def test_no_padding_or_unsafe_chars(self):
        from passkey_authentication.passkey_authentication.serialization import base64url_encode
        for n in range(0, 20):
            self.assertNotIn("=", base64url_encode(b"\xfb" * n))
        enc = base64url_encode(bytes(range(256)))
        self.assertNotIn("+", enc)
        self.assertNotIn("/", enc)

    def test_hex_conversion(self):
        from passkey_authentication.passkey_authentication.serialization import base64url_to_hex, hex_to_base64url
        h = "deadbeef0123456789abcdef"
        self.assertEqual(h, base64url_to_hex(hex_to_base64url(h)))

    def test_type_errors(self):
        from passkey_authentication.passkey_authentication.serialization import base64url_decode, base64url_encode
        with self.assertRaises(TypeError):
            base64url_encode("not bytes")
        with self.assertRaises(TypeError):
            base64url_decode(123)


@unittest.skipUnless(HAS_FRAPPE, "frappe not available (covered in test_flow)")
class TestRpId(unittest.TestCase):
    def test_valid(self):
        from passkey_authentication.passkey_authentication.security import validate_rp_id
        for rp_id in ["erp.example.com", "localhost", "127.0.0.1", "sub.domain.com"]:
            self.assertTrue(validate_rp_id(rp_id), rp_id)

    def test_invalid(self):
        from passkey_authentication.passkey_authentication.security import validate_rp_id
        for rp_id in ["", "https://erp.example.com", "erp.example.com/path", "erp.example.com:8000", "intranet"]:
            self.assertFalse(validate_rp_id(rp_id), rp_id)


if __name__ == "__main__":
    unittest.main()
