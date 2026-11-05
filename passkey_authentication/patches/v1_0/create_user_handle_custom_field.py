"""Patch: create the user-handle custom field and back-fill handles."""
import frappe

from passkey_authentication.passkey_authentication.setup import ensure_custom_field
from passkey_authentication.passkey_authentication.utils import HANDLE_FIELD, generate_user_handle


def execute():
    ensure_custom_field()
    frappe.clear_cache(doctype="User")
    users = frappe.get_all(
        "User",
        filters=[[HANDLE_FIELD, "is", "not set"], ["name", "not in", ["Guest", "Administrator"]]],
        pluck="name",
    )
    for user in users:
        frappe.db.set_value("User", user, HANDLE_FIELD, generate_user_handle(), update_modified=False)
