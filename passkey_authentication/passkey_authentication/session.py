"""Session management for passkey authentication."""
import frappe
from frappe import _

from .challenges import _cache

# How long a fresh login or an explicit identity confirmation allows sensitive
# actions (adding a passkey) without asking again.
STEPUP_WINDOW_SECONDS = 300
_STEPUP_PREFIX = "passkey_stepup:"


def _session_id():
    """Cookie session id, or a per-token id for OAuth Bearer requests.

    For Bearer requests frappe.set_user() sets sid to the username, which would let one
    confirmation unlock every token the user holds; bind it to the presented token instead.
    """
    req = getattr(frappe, "request", None)
    headers = getattr(req, "headers", None) if req else None
    auth = headers.get("Authorization", "") if headers else ""
    if isinstance(auth, str) and auth[:7].lower() == "bearer " and auth[7:].strip():
        import hashlib
        return "bearer:" + hashlib.sha256(auth[7:].strip().encode()).hexdigest()
    return getattr(frappe.session, "sid", None)


def mark_stepup(user_email: str) -> None:
    """Record that the user of the *current* session just re-confirmed their identity."""
    sid = _session_id()
    if not sid or sid == "Guest":
        return
    _cache().set_value(f"{_STEPUP_PREFIX}{sid}", user_email, expires_in_sec=STEPUP_WINDOW_SECONDS)


def _session_is_fresh() -> bool:
    data = getattr(frappe.session, "data", None) or {}
    creation = data.get("creation") if hasattr(data, "get") else None
    if not creation:
        return False
    try:
        age = (frappe.utils.now_datetime() - frappe.utils.get_datetime(creation)).total_seconds()
    except Exception:
        return False
    return 0 <= age <= STEPUP_WINDOW_SECONDS


def has_recent_stepup(user_email: str) -> bool:
    """True if this session was created in the last few minutes (any login method)
    or the user confirmed their identity (password or passkey) in it recently."""
    if _session_is_fresh():
        return True
    sid = _session_id()
    if not sid or sid == "Guest":
        return False
    stored = _cache().get_value(f"{_STEPUP_PREFIX}{sid}")
    if isinstance(stored, bytes):
        stored = stored.decode("utf-8")
    return stored == user_email


def create_session_after_passkey_login(user_email: str) -> dict:
    try:
        enabled, full_name = frappe.db.get_value("User", user_email, ["enabled", "full_name"])
    except Exception:
        return {"success": False, "message": _("User account not found.")}
    if not enabled:
        return {"success": False, "message": _("User account is disabled.")}

    try:
        # Mark this login as passkey-based so the on_login hook lets it through.
        frappe.flags.passkey_login = True
        login_manager = frappe.auth.LoginManager()
        login_manager.user = user_email
        # post_login runs the standard on_login hooks, IP / login-hour restrictions
        # and creates the session + cookies.
        login_manager.post_login()
        frappe.local.login_manager = login_manager
        return {"success": True, "message": _("Login successful."), "user": user_email,
                "full_name": full_name or user_email}
    except Exception:
        frappe.log_error(title="Passkey Session Error", message=frappe.get_traceback())
        return {"success": False, "message": _("Authentication failed.")}


def on_login(login_manager=None):
    """`on_login` hook: block password logins that the passkey rules forbid.

    - "passkey only" (Allow Password Login off): users who have an active passkey;
    - roles in "Require Passkeys For Roles": users who have an active passkey.
    Users without a passkey are never blocked here, so nobody is locked out, and
    Administrator is exempt.
    """
    if getattr(frappe.flags, "passkey_login", False):
        return
    user = getattr(login_manager, "user", None) or frappe.session.user
    if not user or user in ("Guest", "Administrator"):
        return
    try:
        settings = frappe.get_single("Passkey Settings")
    except Exception:
        return
    from .enforcement import enrollment_state, password_login_error
    error = password_login_error(user, settings)
    if error:
        frappe.throw(error, frappe.AuthenticationError)
    # Start the grace period for users who must enrol.
    try:
        enrollment_state(user, settings, start_grace=True)
    except Exception:
        frappe.log_error(title="Passkey Enrolment Error", message=frappe.get_traceback())
