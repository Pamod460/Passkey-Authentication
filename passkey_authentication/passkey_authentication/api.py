"""API endpoints for WebAuthn/Passkey authentication.

Called from the browser as ``passkey_authentication.passkey_authentication.api.<method>`` via frappe.call,
so all inputs arrive as form fields (nested objects as JSON strings).
"""
import frappe
from frappe import _

from .audit import log_event
from .enforcement import enrollment_state
from .authenticators import authenticator_name
from .authentication import get_authentication_options as _auth_options
from .authentication import get_stepup_options as _stepup_options
from .authentication import verify_authentication as _verify_auth
from .authentication import verify_stepup as _verify_stepup
from .registration import get_registration_options as _reg_options
from .registration import verify_registration_response as _verify_reg
from .security import check_rate_limit
from .session import mark_stepup

NOT_AUTHENTICATED = {"success": False, "message": "Authentication required."}


def _logged_in_user():
    user = frappe.session.user
    return None if (not user or user == "Guest") else user


def _as_dict(value):
    if isinstance(value, str):
        value = frappe.parse_json(value)
    return value if isinstance(value, dict) else None


# -- registration ------------------------------------------------------------

@frappe.whitelist(methods=["POST"])
def registration_options():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    return _reg_options(user)


@frappe.whitelist(methods=["POST"])
def verify_registration(credential=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    credential = _as_dict(credential)
    if not credential:
        return {"success": False, "message": _("Credential data is required.")}
    return _verify_reg(user, credential)


# -- step-up: re-confirm identity before adding a passkey --------------------

@frappe.whitelist(methods=["POST"])
def confirm_password(password=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    if not password:
        return {"success": False, "message": _("Password is required.")}
    if not check_rate_limit(f"stepup_pwd:{user}", 5, 300):
        return {"success": False, "message": _("Too many attempts. Please try again later.")}
    try:
        from frappe.utils.password import check_password
        check_password(user, password)
    except frappe.AuthenticationError:
        log_event(user, None, "verification", False, "Wrong password")
        return {"success": False, "message": _("Incorrect password.")}
    log_event(user, None, "verification", True)
    mark_stepup(user)
    return {"success": True, "message": _("Identity confirmed.")}


@frappe.whitelist(methods=["POST"])
def stepup_options():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    return _stepup_options(user)


@frappe.whitelist(methods=["POST"])
def verify_stepup(credential=None, session_token=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    credential = _as_dict(credential)
    if not credential or not session_token:
        return {"success": False, "message": _("Credential data is required.")}
    return _verify_stepup(user, credential, session_token)


# -- authentication (guest) --------------------------------------------------

@frappe.whitelist(allow_guest=True, methods=["POST"])
def authentication_options(user_email=None):
    return _auth_options((user_email or "").strip() or None)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def verify_authentication(credential=None, session_token=None):
    credential = _as_dict(credential)
    if not credential or not session_token:
        return {"success": False, "message": _("Credential data is required.")}
    return _verify_auth(credential, session_token)


# -- management --------------------------------------------------------------

@frappe.whitelist(methods=["GET", "POST"])
def list_credentials():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    credentials = frappe.get_all(
        "Passkey Credential",
        filters={"user": user, "revoked": 0},
        fields=["name", "nickname", "device_type", "authenticator_attachment", "backed_up",
                "enabled", "created_at", "last_used_at", "aaguid", "authenticator_name"],
        order_by="created_at desc",
    )
    settings = frappe.get_single("Passkey Settings")
    for cred in credentials:
        # Rows from before names were stored, or names added later in settings.
        cred["authenticator_name"] = authenticator_name(
            cred.get("aaguid"), cred.get("authenticator_attachment"), settings) or cred.get("authenticator_name") or ""
    return {"success": True, "credentials": credentials}


def _owned_credential(user, credential_name):
    if not credential_name:
        return None
    return frappe.db.get_value("Passkey Credential", {"name": credential_name, "user": user}, "name")


@frappe.whitelist(methods=["POST"])
def rename_credential(credential_name=None, nickname=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    nickname = (nickname or "").strip()[:64]
    if not credential_name or not nickname:
        return {"success": False, "message": _("Credential name and nickname are required.")}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": _("Credential not found.")}
    frappe.db.set_value("Passkey Credential", credential_name, "nickname", nickname)
    return {"success": True, "message": _("Passkey renamed.")}


@frappe.whitelist(methods=["POST"])
def revoke_credential(credential_name=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    if not credential_name:
        return {"success": False, "message": _("Credential name is required.")}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": _("Credential not found.")}
    frappe.db.set_value("Passkey Credential", credential_name,
                        {"revoked": 1, "enabled": 0, "revoked_by": user, "revoked_at": frappe.utils.now()})
    log_event(user, credential_name, "revocation", True)
    return {"success": True, "message": _("Passkey revoked.")}


@frappe.whitelist(methods=["POST"])
def delete_credential(credential_name=None):
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    if not credential_name:
        return {"success": False, "message": _("Credential name is required.")}
    if not _owned_credential(user, credential_name):
        return {"success": False, "message": _("Credential not found.")}
    frappe.delete_doc("Passkey Credential", credential_name, ignore_permissions=True)
    log_event(user, credential_name, "deletion", True)
    return {"success": True, "message": _("Passkey deleted.")}


@frappe.whitelist(allow_guest=True, methods=["GET", "POST"])
def get_status():
    enabled = False
    password_allowed = True
    conditional_ui = False
    discoverable = False
    try:
        settings = frappe.get_single("Passkey Settings")
        enabled = bool(settings.enabled)
        if enabled:
            password_allowed = bool(settings.password_fallback_enabled)
            conditional_ui = bool(settings.enable_conditional_ui and settings.allow_discoverable_credentials)
            discoverable = bool(settings.allow_discoverable_credentials)
    except Exception:
        pass
    passkey_count = 0
    enrollment = None
    recovery = False
    user = _logged_in_user()
    if user:
        passkey_count = frappe.db.count("Passkey Credential",
                                        filters={"user": user, "enabled": 1, "revoked": 0})
        if enabled:
            try:
                enrollment = enrollment_state(user, settings)
            except Exception:
                frappe.log_error(title="Passkey Enrolment Error", message=frappe.get_traceback())
    if enabled:
        recovery = bool(settings.get("allow_recovery_codes"))
    return {"success": True, "enabled": enabled, "passkey_count": passkey_count,
            "password_allowed": password_allowed, "conditional_ui": conditional_ui,
            "discoverable": discoverable, "enrollment": enrollment, "recovery_codes": recovery}


# -- recovery codes ----------------------------------------------------------

@frappe.whitelist(methods=["GET", "POST"])
def recovery_codes_status():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    from . import recovery
    settings = frappe.get_single("Passkey Settings")
    return {"success": True, "enabled": recovery._enabled(settings), "remaining": recovery.remaining(user)}


@frappe.whitelist(methods=["POST"])
def generate_recovery_codes():
    user = _logged_in_user()
    if not user:
        return NOT_AUTHENTICATED
    from . import recovery
    return recovery.generate(user)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def recovery_login(user_email=None, code=None):
    from . import recovery
    return recovery.login(user_email, code)

