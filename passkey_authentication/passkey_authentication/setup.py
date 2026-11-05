"""Post-install setup."""
import frappe

MODULE = "Passkey Authentication"

USER_FIELDS = [
    {
        "fieldname": "custom_passkey_user_handle",
        "fieldtype": "Data",
        "label": "Passkey User Handle",
        "description": "Internal WebAuthn user handle.",
    },
    {
        "fieldname": "custom_passkey_required_since",
        "fieldtype": "Datetime",
        "label": "Passkey Required Since",
        "description": "When this user first had to enrol a passkey (start of the grace period).",
    },
]


def after_install():
    ensure_custom_field()
    _create_default_settings()


def ensure_custom_field():
    for field in USER_FIELDS:
        if frappe.db.exists("Custom Field", {"dt": "User", "fieldname": field["fieldname"]}):
            continue
        frappe.get_doc({
            "doctype": "Custom Field",
            "dt": "User",
            "hidden": 1,
            "read_only": 1,
            "no_copy": 1,
            "module": MODULE,
            **field,
        }).insert(ignore_permissions=True)


def guess_rp_id() -> str:
    """The site's own host name, when it is a usable RP ID."""
    from .security import site_host
    return site_host()


def fill_rp_id(settings) -> bool:
    """Set RP ID from the site host when it is blank. Returns True when it changed."""
    if settings.rp_id:
        return False
    rp_id = guess_rp_id()
    if not rp_id:
        return False
    settings.rp_id = rp_id
    return True


def _create_default_settings():
    # Single doctype: just save defaults (field defaults from the doctype apply).
    settings = frappe.get_single("Passkey Settings")
    if not settings.rp_name:
        settings.rp_name = "ERPNext"
    fill_rp_id(settings)
    settings.save(ignore_permissions=True)
