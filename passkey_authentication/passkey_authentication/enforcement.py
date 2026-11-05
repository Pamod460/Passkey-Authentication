"""Require passkeys for users with certain roles.

Rules (Administrator is always exempt):
- A user with a required role who has an active passkey cannot sign in with a password.
- A user with a required role and no passkey may still use a password, so nobody is
  locked out. Their grace period starts the first time this is noticed; after it ends
  the desk shows a dialog they cannot dismiss until they add a passkey.
"""
from datetime import timedelta

import frappe

REQUIRED_SINCE_FIELD = "custom_passkey_required_since"
EXEMPT_USERS = ("Guest", "Administrator")
REMINDER_DAYS = (7, 3, 1)


def required_roles(settings) -> set:
    rows = (settings.get("required_roles") if hasattr(settings, "get") else None) or []
    roles = set()
    for row in rows:
        role = row.get("role") if isinstance(row, dict) else getattr(row, "role", None)
        if role:
            roles.add(role)
    return roles


def is_required(user: str, settings) -> bool:
    if not user or user in EXEMPT_USERS or not settings.enabled:
        return False
    roles = required_roles(settings)
    if not roles:
        return False
    try:
        return bool(roles.intersection(frappe.get_roles(user)))
    except Exception:
        return False


def has_active_passkey(user: str) -> bool:
    return bool(frappe.db.exists("Passkey Credential", {"user": user, "enabled": 1, "revoked": 0}))


def _grace_days(settings) -> int:
    try:
        return max(0, int(settings.get("enrollment_grace_days") if hasattr(settings, "get") else 14))
    except (TypeError, ValueError):
        return 14


def enrollment_state(user: str, settings, start_grace: bool = True) -> dict:
    """{required, has_passkey, deadline (str|None), days_left, overdue} for one user."""
    state = {"required": False, "has_passkey": False, "deadline": None, "days_left": None, "overdue": False}
    if not is_required(user, settings):
        return state
    state["required"] = True
    if has_active_passkey(user):
        state["has_passkey"] = True
        return state

    since = frappe.db.get_value("User", user, REQUIRED_SINCE_FIELD)
    now = frappe.utils.now_datetime()
    if not since:
        if not start_grace:
            return state
        since = now
        frappe.db.set_value("User", user, REQUIRED_SINCE_FIELD, since, update_modified=False)
    deadline = frappe.utils.get_datetime(since) + timedelta(days=_grace_days(settings))
    remaining = deadline - now
    state["deadline"] = str(deadline)
    state["days_left"] = max(0, remaining.days + (1 if remaining.seconds else 0)) if remaining.total_seconds() > 0 else 0
    state["overdue"] = remaining.total_seconds() <= 0
    return state


def password_login_error(user: str, settings):
    """Message when this user may not sign in with a password, else None."""
    if not user or user in EXEMPT_USERS or not settings.enabled:
        return None
    if not has_active_passkey(user):
        return None
    if not settings.password_fallback_enabled or is_required(user, settings):
        return frappe._("Password login is disabled. Please sign in with your passkey.")
    return None


def send_enrollment_reminders():
    """Daily: remind users with a required role and no passkey before their grace period ends."""
    try:
        settings = frappe.get_single("Passkey Settings")
        if not settings.enabled or not settings.get("send_enrollment_reminders"):
            return
        roles = required_roles(settings)
        if not roles:
            return
        users = frappe.get_all("Has Role", filters={"role": ["in", list(roles)], "parenttype": "User"},
                               pluck="parent")
        for user in sorted(set(users)):
            if user in EXEMPT_USERS or not frappe.db.get_value("User", user, "enabled"):
                continue
            state = enrollment_state(user, settings, start_grace=True)
            if not state["required"] or state["has_passkey"]:
                continue
            if state["days_left"] in REMINDER_DAYS:
                _send_reminder(user, state["days_left"])
    except Exception:
        frappe.log_error(title="Passkey Reminder Error", message=frappe.get_traceback())


def _send_reminder(user: str, days_left: int):
    url = frappe.utils.get_url("/app/passkey-settings")
    frappe.sendmail(
        recipients=[user],
        subject=frappe._("Add a passkey to your account within {0} day(s)").format(days_left),
        message=frappe._(
            "Your role requires signing in with a passkey. Please add one within {0} day(s): "
            "<a href=\"{1}\">{1}</a>"
        ).format(days_left, url),
    )
