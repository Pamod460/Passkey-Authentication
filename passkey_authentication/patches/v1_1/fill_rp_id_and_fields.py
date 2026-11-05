"""Existing installs: add the new User custom fields and fill a blank RP ID from the site host."""
import frappe

from passkey_authentication.passkey_authentication.setup import ensure_custom_field, fill_rp_id


def execute():
    ensure_custom_field()
    settings = frappe.get_single("Passkey Settings")
    if fill_rp_id(settings):
        settings.save(ignore_permissions=True)
