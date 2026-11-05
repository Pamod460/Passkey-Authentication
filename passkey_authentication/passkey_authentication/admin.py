"""Admin tools: revoke other users' passkeys, reset recovery codes, enrolment summary.

All endpoints require the System Manager role.
"""
import frappe
from frappe import _

from .audit import log_event


def _require_admin():
    frappe.only_for("System Manager")


def _names(value) -> list:
    if isinstance(value, str):
        value = frappe.parse_json(value) if value.strip().startswith("[") else [value]
    return [v for v in (value or []) if isinstance(v, str) and v]


def revoke(names: list, reason: str = None) -> int:
    admin = frappe.session.user
    now = frappe.utils.now()
    by_user = {}
    for name in names:
        row = frappe.db.get_value("Passkey Credential", name, ["user", "revoked", "nickname"], as_dict=True)
        if not row or row.revoked:
            continue
        frappe.db.set_value("Passkey Credential", name,
                            {"revoked": 1, "enabled": 0, "revoked_by": admin, "revoked_at": now})
        note = f"Revoked by {admin}" + (f": {reason}" if reason else "")
        log_event(row.user, name, "revocation", True, note)
        by_user.setdefault(row.user, []).append(row.nickname or name)
    for user, nicknames in by_user.items():
        _notify_revoked(user, nicknames)
    return sum(len(v) for v in by_user.values())


def _notify_revoked(user: str, nicknames: list) -> None:
    try:
        esc = frappe.utils.escape_html
        frappe.sendmail(
            recipients=[user],
            subject=_("Passkeys on your account were revoked"),
            message=_("An administrator revoked these passkeys on your account: {0}. "
                      "They no longer work for signing in.").format(", ".join(esc(n) for n in nicknames)),
        )
    except Exception:
        frappe.log_error(title="Passkey Notification Error", message=frappe.get_traceback())


@frappe.whitelist(methods=["POST"])
def revoke_credentials(names=None, reason=None):
    """Revoke the given Passkey Credential records (bulk action in the list view)."""
    _require_admin()
    count = revoke(_names(names), (reason or "").strip()[:200] or None)
    return {"success": True, "revoked": count,
            "message": _("{0} passkey(s) revoked.").format(count)}


@frappe.whitelist(methods=["POST"])
def revoke_user_passkeys(user=None, reason=None):
    """Revoke every active passkey of one user (e.g. a lost device or someone leaving)."""
    _require_admin()
    if not user:
        return {"success": False, "message": _("User is required.")}
    names = frappe.get_all("Passkey Credential", filters={"user": user, "revoked": 0}, pluck="name")
    count = revoke(names, (reason or "").strip()[:200] or None)
    return {"success": True, "revoked": count,
            "message": _("{0} passkey(s) revoked.").format(count)}


@frappe.whitelist(methods=["POST"])
def reset_recovery_codes(user=None):
    """Delete a user's unused recovery codes."""
    _require_admin()
    if not user:
        return {"success": False, "message": _("User is required.")}
    names = frappe.get_all("Passkey Recovery Code", filters={"user": user, "used": 0}, pluck="name")
    for name in names:
        frappe.delete_doc("Passkey Recovery Code", name, ignore_permissions=True)
    log_event(user, None, "recovery_codes", True, f"Unused codes deleted by {frappe.session.user}")
    return {"success": True, "message": _("{0} unused recovery code(s) deleted.").format(len(names))}


@frappe.whitelist(methods=["GET", "POST"])
def user_passkey_summary(user=None):
    """Counts shown on the User form."""
    _require_admin()
    if not user:
        return {"success": False, "message": _("User is required.")}
    from .enforcement import enrollment_state
    settings = frappe.get_single("Passkey Settings")
    return {
        "success": True,
        "active": frappe.db.count("Passkey Credential", {"user": user, "enabled": 1, "revoked": 0}),
        "total": frappe.db.count("Passkey Credential", {"user": user}),
        "recovery_codes": frappe.db.count("Passkey Recovery Code", {"user": user, "used": 0}),
        "enrollment": enrollment_state(user, settings, start_grace=False),
    }
