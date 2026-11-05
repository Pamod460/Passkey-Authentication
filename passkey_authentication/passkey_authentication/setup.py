"""Post-install setup."""
import frappe

MODULE = "Passkey Authentication"


def after_install():
    ensure_custom_field()
    _create_default_settings()


def ensure_custom_field():
    if frappe.db.exists("Custom Field", {"dt": "User", "fieldname": "custom_passkey_user_handle"}):
        return
    frappe.get_doc({
        "doctype": "Custom Field",
        "dt": "User",
        "fieldname": "custom_passkey_user_handle",
        "fieldtype": "Data",
        "label": "Passkey User Handle",
        "hidden": 1,
        "read_only": 1,
        "no_copy": 1,
        "description": "Internal WebAuthn user handle.",
        "module": MODULE,
    }).insert(ignore_permissions=True)


def _create_default_settings():
    # Single doctype: just save defaults (field defaults from the doctype apply).
    settings = frappe.get_single("Passkey Settings")
    if not settings.rp_name:
        settings.rp_name = "ERPNext"
    settings.save(ignore_permissions=True)
