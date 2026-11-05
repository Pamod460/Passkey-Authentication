"""One-time recovery codes for users who lose all their passkeys.

Codes are shown once, stored only as keyed hashes, used at most once, rate limited
per user and per IP, and the user is emailed whenever one is used. A recovery login
skips the "passkey only" rule (like a passkey login does), so users of passkey-only
sites can get back in and add a new passkey without an admin.
"""
import hashlib
import hmac
import secrets

import frappe
from frappe import _

from .audit import log_event
from .security import (
    check_rate_limit, get_client_ip, is_authentication_blocked, record_authentication_failure,
)
from .session import has_recent_stepup

DOCTYPE = "Passkey Recovery Code"
# Crockford-style alphabet without look-alikes (0/O, 1/I/L, U).
ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_LENGTH = 10  # ~49 bits per code
GENERIC_FAILURE = "Invalid email or recovery code."


def _settings():
    return frappe.get_single("Passkey Settings")


def _enabled(settings) -> bool:
    return bool(settings.enabled and settings.get("allow_recovery_codes"))


def normalize(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _secret() -> bytes:
    return (frappe.local.conf.get("encryption_key") or frappe.local.site or "passkey").encode()


def hash_code(code: str) -> str:
    return hmac.new(_secret(), normalize(code).encode(), hashlib.sha256).hexdigest()


def new_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _i in range(CODE_LENGTH))
    return f"{raw[:5]}-{raw[5:]}"


def remaining(user: str) -> int:
    return frappe.db.count(DOCTYPE, filters={"user": user, "used": 0})


def _count(settings) -> int:
    try:
        n = int(settings.get("recovery_code_count") or 10)
    except (TypeError, ValueError):
        n = 10
    return min(max(n, 4), 20)


def generate(user: str) -> dict:
    """Replace the user's unused codes with a new set and return them (shown once)."""
    settings = _settings()
    if not _enabled(settings):
        return {"success": False, "message": _("Recovery codes are not enabled.")}
    if not has_recent_stepup(user):
        has_passkeys = bool(frappe.db.exists("Passkey Credential", {"user": user, "enabled": 1, "revoked": 0}))
        return {"success": False, "stepup_required": True, "has_passkeys": has_passkeys,
                "message": _("Please confirm your identity first.")}
    if not check_rate_limit(f"recovery_gen:{user}", 5, 3600):
        return {"success": False, "message": _("Too many attempts. Please try again later.")}

    for name in frappe.get_all(DOCTYPE, filters={"user": user, "used": 0}, pluck="name"):
        frappe.delete_doc(DOCTYPE, name, ignore_permissions=True)

    codes = [new_code() for _i in range(_count(settings))]
    for code in codes:
        frappe.get_doc({"doctype": DOCTYPE, "user": user, "code_hash": hash_code(code), "used": 0}).insert(
            ignore_permissions=True)
    log_event(user, None, "recovery_codes", True)
    _notify(user, _("New recovery codes were created for your account"),
            _("A new set of passkey recovery codes was created for your account from IP {0}. "
              "Any older unused codes no longer work.<br><br>If this was not you, sign in, "
              "create new codes and review your passkeys."))
    return {"success": True, "codes": codes, "remaining": len(codes)}


def _match(user: str, code: str):
    wanted = hash_code(code)
    rows = frappe.get_all(DOCTYPE, filters={"user": user, "used": 0}, fields=["name", "code_hash"])
    found = None
    for row in rows:
        # Compare against every row so timing does not depend on the position of the match.
        if hmac.compare_digest(row.code_hash or "", wanted):
            found = row.name
    return found


def login(user_email: str, code: str, create_session: bool = True) -> dict:
    settings = _settings()
    if not _enabled(settings):
        return {"success": False, "message": _("Recovery codes are not enabled.")}
    user_email = (user_email or "").strip()
    if not user_email or not normalize(code):
        return {"success": False, "message": _("Email and recovery code are required.")}

    ip = get_client_ip()
    if is_authentication_blocked(ip) or not check_rate_limit(f"recovery:{user_email.lower()}", 5, 900):
        return {"success": False, "message": _("Too many attempts. Please try again later.")}

    user = frappe.db.get_value("User", {"name": user_email}, "name") or frappe.db.get_value(
        "User", {"email": user_email}, "name")
    name = _match(user, code) if user else None
    if not name or user in ("Guest", "Administrator") or not frappe.db.get_value("User", user, "enabled"):
        record_authentication_failure(ip)
        log_event(user or "Guest", None, "recovery", False, "Wrong recovery code")
        return {"success": False, "message": _(GENERIC_FAILURE)}

    frappe.db.set_value(DOCTYPE, name, {"used": 1, "used_at": frappe.utils.now(), "used_ip": ip})
    log_event(user, None, "recovery", True)
    left = remaining(user)
    _notify(user, _("A recovery code was used to sign in"),
            _("Someone signed in to your account with a recovery code from IP {0}. "
              "If this was not you, sign in, revoke unknown passkeys and create new recovery codes."))

    if not create_session:
        return {"success": True, "user": user, "remaining": left}

    from .session import create_session_after_passkey_login
    session = create_session_after_passkey_login(user)
    if not session["success"]:
        return {"success": False, "message": session.get("message") or _("Sign-in failed.")}
    return {"success": True, "message": _("Signed in. Please add a new passkey now."), "user": user,
            "remaining": left, "full_name": session.get("full_name", "")}


def _notify(user: str, subject: str, message: str) -> None:
    try:
        frappe.sendmail(recipients=[user], subject=subject,
                        message=message.format(frappe.utils.escape_html(get_client_ip())))
    except Exception:
        frappe.log_error(title="Passkey Notification Error", message=frappe.get_traceback())
