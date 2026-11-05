"""WebAuthn registration flow."""
import json

import frappe

from .audit import log_event
from .challenges import (
    generate_challenge, get_and_clear_registration_challenge, store_registration_challenge,
)
from .security import (
    check_registration_rate_limit, check_secure_context, get_client_ip, get_expected_origins,
    get_rp_id, get_user_agent,
)
from .serialization import base64url_decode, base64url_encode
from .session import has_recent_stepup
from .utils import get_webauthn_user_handle

try:
    import webauthn  # noqa: F401
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False


def _settings():
    return frappe.get_single("Passkey Settings")


def _stepup_required(user_email: str):
    """Adding a passkey grants lasting access, so a hijacked session must not be able to do it.

    Returns an error dict when the user has to re-confirm their identity first, else None.
    """
    if has_recent_stepup(user_email):
        return None
    has_passkeys = bool(frappe.db.count("Passkey Credential",
                                        filters={"user": user_email, "enabled": 1, "revoked": 0}))
    return {"success": False, "stepup_required": True, "has_passkeys": has_passkeys,
            "message": "Please confirm your identity before adding a passkey."}


def get_registration_options(user_email: str) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = _settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}
    if not check_registration_rate_limit(user_email):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    rp_id = get_rp_id(settings)
    insecure = check_secure_context(settings, rp_id)
    if insecure:
        return {"success": False, "message": insecure}

    stepup = _stepup_required(user_email)
    if stepup:
        return stepup

    user = frappe.db.get_value("User", user_email, ["name", "full_name", "enabled"], as_dict=True)
    if not user:
        return {"success": False, "message": "User not found."}
    if not user.enabled:
        return {"success": False, "message": "User account is disabled."}

    existing = frappe.get_all("Passkey Credential",
                              filters={"user": user_email, "enabled": 1, "revoked": 0},
                              pluck="credential_id")
    max_creds = settings.max_credentials_per_user or 10
    if len(existing) >= max_creds:
        return {"success": False, "message": f"Maximum number of passkeys ({max_creds}) reached."}

    user_handle = get_webauthn_user_handle(user_email)
    challenge = generate_challenge()
    store_registration_challenge(user_email, challenge)

    exclude = [{"id": cid, "type": "public-key"} for cid in existing]
    options = {
        "rp": {"name": settings.rp_name or "ERPNext", "id": rp_id},
        "user": {
            "id": base64url_encode(user_handle.encode("utf-8")),
            "name": user_email,
            "displayName": user.full_name or user_email,
        },
        "challenge": base64url_encode(challenge),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": (settings.challenge_timeout or 120) * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": settings.require_user_verification or "preferred",
        },
    }
    if exclude:
        options["excludeCredentials"] = exclude
    return {"success": True, "options": options}


def _attachment(value) -> str:
    return value if value in ("platform", "cross-platform") else ""


def verify_registration_response(user_email: str, credential_json: dict) -> dict:
    if not WEBAUTHN_AVAILABLE:
        return {"success": False, "message": "WebAuthn library not available."}

    settings = _settings()
    if not settings.enabled:
        return {"success": False, "message": "Passkey authentication is disabled."}
    if not check_registration_rate_limit(user_email):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    expected_challenge = get_and_clear_registration_challenge(user_email)
    if not expected_challenge:
        return {"success": False, "message": "Registration challenge expired. Please try again."}

    stepup = _stepup_required(user_email)
    if stepup:
        return stepup

    rp_id = get_rp_id(settings)
    insecure = check_secure_context(settings, rp_id)
    if insecure:
        return {"success": False, "message": insecure}

    try:
        from webauthn import verify_registration_response as webauthn_verify_reg
        from webauthn.helpers import parse_registration_credential_json

        credential = parse_registration_credential_json(credential_json)
        verification = webauthn_verify_reg(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=get_expected_origins(settings, rp_id),
            require_user_verification=(settings.require_user_verification == "required"),
        )

        credential_id = base64url_encode(verification.credential_id)
        if frappe.db.exists("Passkey Credential", {"credential_id": credential_id}):
            log_event(user_email, None, "registration", False, "Credential already registered")
            return {"success": False, "message": "This passkey is already registered."}

        response = credential_json.get("response") or {}
        transports = response.get("transports")
        transports = [t for t in transports if isinstance(t, str)] if isinstance(transports, list) else []
        attachment = _attachment(credential_json.get("authenticatorAttachment"))
        device_type = getattr(verification.credential_device_type, "value", str(verification.credential_device_type))

        cred_doc = frappe.get_doc({
            "doctype": "Passkey Credential",
            "user": user_email,
            "credential_id": credential_id,
            "public_key": base64url_encode(verification.credential_public_key),
            "user_handle": get_webauthn_user_handle(user_email),
            "sign_count": verification.sign_count,
            "transports": json.dumps(transports),
            "device_type": attachment,
            "backed_up": 1 if verification.credential_backed_up else 0,
            "backup_eligible": 1 if device_type == "multi_device" else 0,
            "authenticator_attachment": attachment or "none",
            "aaguid": str(verification.aaguid or ""),
            "user_verified": 1 if verification.user_verified else 0,
            "nickname": _suggest_nickname(user_email),
            "enabled": 1,
            "revoked": 0,
            "created_ip": get_client_ip(),
            "user_agent": get_user_agent(),
            "origin": get_expected_origins(settings, rp_id)[0],
            "rp_id": rp_id,
        })
        cred_doc.insert(ignore_permissions=True)
        log_event(user_email, cred_doc.name, "registration", True)
        _notify_new_passkey(user_email, cred_doc.nickname)
        return {"success": True, "message": "Passkey registered successfully.",
                "credential_name": cred_doc.name, "nickname": cred_doc.nickname}

    except Exception as e:
        frappe.log_error(title="Passkey Registration Error", message=f"User: {user_email}\n{frappe.get_traceback()}")
        log_event(user_email, None, "registration", False, str(e))
        return {"success": False, "message": "Passkey registration failed. Please try again."}


def _suggest_nickname(user_email: str) -> str:
    ua = get_user_agent().lower()
    if "windows" in ua:
        if "edg/" in ua:
            return "Windows Edge Passkey"
        if "chrome" in ua:
            return "Windows Chrome Passkey"
        return "Windows Passkey"
    if "iphone" in ua or "ipad" in ua:
        return "iOS Passkey"
    if "android" in ua:
        return "Android Passkey"
    if "macintosh" in ua or "macos" in ua:
        return "Mac Passkey"
    if "linux" in ua:
        return "Linux Passkey"
    count = frappe.db.count("Passkey Credential", filters={"user": user_email, "enabled": 1})
    return f"Passkey {count + 1}"


def _notify_new_passkey(user_email: str, nickname: str) -> None:
    """Tell the account owner a passkey was added, so an unexpected one gets noticed."""
    try:
        frappe.sendmail(
            recipients=[user_email],
            subject=frappe._("A new passkey was added to your account"),
            message=frappe._(
                "A passkey named <b>{0}</b> was just added to your account from IP {1}.<br><br>"
                "If this was not you, open Passkeys in your account, revoke it, and change your password."
            ).format(frappe.utils.escape_html(nickname or ""), frappe.utils.escape_html(get_client_ip())),
        )
    except Exception:
        frappe.log_error(title="Passkey Notification Error", message=frappe.get_traceback())
