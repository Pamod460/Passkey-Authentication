"""JSON API for client apps (Flutter, Angular, native iOS/Android...).

Flow for an app registered as a *Passkey Client App*:

1. ``POST /api/method/passkey_authentication.passkey_authentication.client_api.config``  -> RP ID and status
2. ``POST /api/method/passkey_authentication.passkey_authentication.client_api.login_options``  -> WebAuthn request
   options + ``session_token``; the app passes ``options`` to the platform passkey API.
3. ``POST /api/method/passkey_authentication.passkey_authentication.client_api.login``  with the credential JSON and
   ``session_token`` -> ``access_token`` / ``refresh_token``.
4. Call any Frappe API with ``Authorization: Bearer <access_token>``.
5. ``refresh`` rotates tokens, ``logout`` revokes them.

Adding a passkey from an app reuses ``passkey_authentication.passkey_authentication.api`` (registration_options /
verify_registration, after stepup_options / verify_stepup or confirm_password) with the
Bearer token.

Every endpoint accepts a JSON body (Content-Type: application/json) or form fields.
"""
import frappe
from frappe import _

from . import client_apps, client_tokens
from .authentication import get_authentication_options as _auth_options
from .authentication import verify_authentication as _verify_auth
from .enforcement import password_login_error
from .security import (
    check_rate_limit, get_client_ip, get_rp_id, is_authentication_blocked,
    record_authentication_failure,
)

UNKNOWN_CLIENT = {"success": False, "message": "Unknown or disabled client app."}


def _client(client_id):
    return client_apps.get_app_by_client_id((client_id or "").strip())


def _as_dict(value):
    if isinstance(value, str):
        try:
            value = frappe.parse_json(value)
        except Exception:
            return None
    return value if isinstance(value, dict) else None


def _user_info(user: str) -> dict:
    info = frappe.db.get_value("User", user, ["full_name", "user_image"], as_dict=True) or {}
    return {"user": user, "full_name": info.get("full_name") or user,
            "user_image": info.get("user_image")}


def _login_restrictions_error(user: str):
    """Apply Frappe's per-user IP allow-list and login-hours rules (as a cookie login would)."""
    try:
        validate_ip = getattr(frappe.auth, "validate_ip_address", None)
        if validate_ip:
            validate_ip(user)
        login_manager_cls = getattr(frappe.auth, "LoginManager", None)
        validate_hour = getattr(login_manager_cls, "validate_hour", None)
        if validate_hour:
            validate_hour(frappe._dict(user=user))
    except Exception as e:
        return str(e) or "Login not allowed."
    return None


def _issue(app, user: str) -> dict:
    error = _login_restrictions_error(user)
    if error:
        return {"success": False, "message": error}
    tokens = client_tokens.issue_tokens(app, user)
    return {"success": True, "message": _("Authentication successful."), **_user_info(user), **tokens}


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
def config(client_id=None):
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    settings = frappe.get_single("Passkey Settings")
    return {
        "success": True,
        "enabled": bool(settings.enabled),
        "rp_id": get_rp_id(settings),
        "rp_name": settings.rp_name or "ERPNext",
        "discoverable": bool(settings.allow_discoverable_credentials),
        "password_allowed": bool(settings.password_fallback_enabled),
        "app_name": app.app_name,
    }


@frappe.whitelist(allow_guest=True, methods=["POST"])
def login_options(client_id=None, user_email=None):
    if not _client(client_id):
        return UNKNOWN_CLIENT
    return _auth_options((user_email or "").strip() or None)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def login(client_id=None, credential=None, session_token=None):
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    credential = _as_dict(credential)
    if not credential or not session_token:
        return {"success": False, "message": _("Credential data is required.")}
    result = _verify_auth(credential, session_token, create_session=False)
    if not result.get("success"):
        return result
    return _issue(app, result["user"])


@frappe.whitelist(allow_guest=True, methods=["POST"])
def password_login(client_id=None, usr=None, pwd=None):
    """Bootstrap for users who have no passkey yet (respects the 'passkey only' setting).

    Refused for users with two-factor authentication; they must sign in on the website.
    """
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    usr, pwd = (usr or "").strip(), pwd or ""
    if not usr or not pwd:
        return {"success": False, "message": _("Username and password are required.")}

    ip = get_client_ip()
    if is_authentication_blocked(ip) or not check_rate_limit(f"client_pwd:{usr.lower()}", 5, 300):
        return {"success": False, "message": _("Too many attempts. Please try again later.")}

    failure = {"success": False, "message": _("Incorrect username or password.")}
    try:
        from frappe.utils.password import check_password
        tracker = None
        get_tracker = getattr(frappe.auth, "get_login_attempt_tracker", None)
        if get_tracker:
            tracker = get_tracker(usr)
        try:
            user = check_password(usr, pwd) or usr
        except frappe.AuthenticationError:
            if tracker:
                tracker.add_failure_attempt()
            record_authentication_failure(ip)
            return failure
        if tracker:
            tracker.add_success_attempt()
    except Exception as e:
        # Account locked by the login-attempt tracker, etc.
        return {"success": False, "message": str(e) or failure["message"]}

    if user in ("Guest", "Administrator") or not frappe.db.get_value("User", user, "enabled"):
        return failure

    settings = frappe.get_single("Passkey Settings")
    blocked = password_login_error(user, settings)
    if blocked:
        return {"success": False, "message": blocked}

    try:
        from frappe.twofactor import should_run_2fa
        if should_run_2fa(user):
            return {"success": False, "two_factor_required": True,
                    "message": _("Two-factor authentication is enabled for this account. Please sign in on the website.")}
    except ImportError:
        pass

    return _issue(app, user)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def refresh(client_id=None, refresh_token=None):
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    result = client_tokens.refresh_tokens(app, refresh_token)
    if not result.get("success"):
        return result
    error = _login_restrictions_error(result["user"])
    if error:
        client_tokens.revoke_all(app, result["user"])
        return {"success": False, "message": error}
    return {**result, **_user_info(result["user"])}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def recovery_login(client_id=None, user_email=None, code=None):
    """Sign in with a one-time recovery code (user lost every passkey); returns tokens."""
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    from . import recovery
    result = recovery.login(user_email, code, create_session=False)
    if not result.get("success"):
        return result
    issued = _issue(app, result["user"])
    if issued.get("success"):
        issued["recovery_codes_remaining"] = result.get("remaining")
    return issued


@frappe.whitelist(allow_guest=True, methods=["POST"])
def logout(client_id=None, refresh_token=None):
    app = _client(client_id)
    if not app:
        return UNKNOWN_CLIENT
    client_tokens.revoke_refresh_token(app, refresh_token)
    # Same answer whether or not the token existed.
    return {"success": True, "message": _("Signed out.")}


@frappe.whitelist(methods=["GET", "POST"])
def me():
    user = frappe.session.user
    if not user or user == "Guest":
        return {"success": False, "message": _("Authentication required.")}
    passkeys = frappe.db.count("Passkey Credential", filters={"user": user, "enabled": 1, "revoked": 0})
    return {"success": True, **_user_info(user), "passkey_count": passkeys}
