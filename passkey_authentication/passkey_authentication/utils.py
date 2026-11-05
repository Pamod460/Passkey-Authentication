"""Utility functions for passkey authentication."""
import base64
import secrets

import frappe

HANDLE_FIELD = "custom_passkey_user_handle"


def generate_user_handle() -> str:
    """Opaque random WebAuthn user handle (32 random bytes, base64url)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def generate_user_handle_on_insert(doc, method=None):
    if not doc.name or doc.name in ("Guest",):
        return
    if not frappe.db.get_value("User", doc.name, HANDLE_FIELD):
        frappe.db.set_value("User", doc.name, HANDLE_FIELD, generate_user_handle(),
                            update_modified=False)


def get_webauthn_user_handle(user_email: str) -> str:
    handle = frappe.db.get_value("User", user_email, HANDLE_FIELD)
    if not handle:
        handle = generate_user_handle()
        frappe.db.set_value("User", user_email, HANDLE_FIELD, handle, update_modified=False)
    return handle
