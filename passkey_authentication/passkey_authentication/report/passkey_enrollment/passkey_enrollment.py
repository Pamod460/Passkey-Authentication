"""Which users have passkeys, which must enrol, and who is overdue."""
from datetime import timedelta

import frappe
from frappe import _

from passkey_authentication.passkey_authentication.enforcement import REQUIRED_SINCE_FIELD, required_roles

STATUSES = ("Enrolled", "Not enrolled", "In grace period", "Overdue")


def execute(filters=None):
    filters = frappe._dict(filters or {})
    return _columns(), _rows(filters)


def _columns():
    return [
        {"fieldname": "user", "label": _("User"), "fieldtype": "Link", "options": "User", "width": 220},
        {"fieldname": "full_name", "label": _("Full Name"), "fieldtype": "Data", "width": 180},
        {"fieldname": "status", "label": _("Status"), "fieldtype": "Data", "width": 130},
        {"fieldname": "required", "label": _("Passkey Required"), "fieldtype": "Check", "width": 110},
        {"fieldname": "deadline", "label": _("Enrol By"), "fieldtype": "Datetime", "width": 160},
        {"fieldname": "active_passkeys", "label": _("Active Passkeys"), "fieldtype": "Int", "width": 110},
        {"fieldname": "last_passkey_use", "label": _("Last Passkey Use"), "fieldtype": "Datetime", "width": 160},
        {"fieldname": "recovery_codes", "label": _("Recovery Codes Left"), "fieldtype": "Int", "width": 120},
    ]


def _rows(filters):
    user_filters = {"user_type": "System User", "name": ["not in", ["Guest"]]}
    if not filters.get("include_disabled"):
        user_filters["enabled"] = 1
    users = frappe.get_all("User", filters=user_filters, fields=["name", "full_name"], order_by="name")

    passkeys = {r.user: r for r in frappe.db.sql(
        """select user, count(*) as active, max(last_used_at) as last_used
           from `tabPasskey Credential` where enabled = 1 and revoked = 0 group by user""", as_dict=True)}
    codes = {r.user: r.n for r in frappe.db.sql(
        """select user, count(*) as n from `tabPasskey Recovery Code` where used = 0 group by user""",
        as_dict=True)}

    settings = frappe.get_single("Passkey Settings")
    roles = required_roles(settings)
    required_users = set()
    if roles:
        required_users = set(frappe.get_all("Has Role", filters={"role": ["in", list(roles)], "parenttype": "User"},
                                            pluck="parent"))
    if filters.get("role"):
        role_users = set(frappe.get_all("Has Role", filters={"role": filters.role, "parenttype": "User"},
                                        pluck="parent"))
        users = [u for u in users if u.name in role_users]

    since = {}
    if required_users:
        since = {r.name: r.get(REQUIRED_SINCE_FIELD) for r in frappe.get_all(
            "User", filters={"name": ["in", list(required_users)]}, fields=["name", REQUIRED_SINCE_FIELD])}
    try:
        grace = max(0, int(settings.get("enrollment_grace_days") or 0))
    except (TypeError, ValueError):
        grace = 14
    now = frappe.utils.now_datetime()

    rows = []
    for u in users:
        pk = passkeys.get(u.name)
        required = bool(settings.enabled and u.name in required_users and u.name != "Administrator")
        deadline = None
        if pk:
            status = "Enrolled"
        elif required:
            started = since.get(u.name)
            if started:
                deadline = frappe.utils.get_datetime(started) + timedelta(days=grace)
                status = "Overdue" if deadline <= now else "In grace period"
            else:
                status = "In grace period"  # grace starts at their next login
        else:
            status = "Not enrolled"
        if filters.get("status") and filters.status != status:
            continue
        rows.append({
            "user": u.name, "full_name": u.full_name, "status": status, "required": 1 if required else 0,
            "deadline": deadline, "active_passkeys": pk.active if pk else 0,
            "last_passkey_use": pk.last_used if pk else None, "recovery_codes": codes.get(u.name, 0),
        })
    return rows
