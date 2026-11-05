"""WebAuthn authentication (login) flow."""
import hashlib
import hmac
import json

import frappe

from .audit import log_event
from .challenges import (
    generate_challenge, get_and_clear_authentication_challenge, store_authentication_challenge,
)
from .security import (
    check_authentication_options_rate_limit, check_secure_context, get_client_ip,
    get_expected_origins, get_rp_id, is_authentication_blocked, record_authentication_failure,
)
from .serialization import base64url_decode, base64url_encode
from .session import create_session_after_passkey_login, mark_stepup

try:
    import webauthn  # noqa: F401
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

GENERIC_FAILURE = "Passkey authentication failed."


def _settings():
    return frappe.get_single("Passkey Settings")


def _decoy_credential_id(user_email: str) -> str:
    """Stable fake credential id so unknown users / users without passkeys look identical."""
    secret = (frappe.local.conf.get("encryption_key") or frappe.local.site or "passkey").encode()
    return base64url_encode(hmac.new(secret, user_email.lower().encode(), hashlib.sha256).digest())


def _allow_credentials(user_email: str) -> list:
    credentials = frappe.get_all(
        "Passkey Credential",
        filters={"user": user_email, "enabled": 1, "revoked": 0},
        fields=["credential_id", "transports"],
    )
    allow = []
    for cred in credentials:
        entry = {"id": cred.credential_id, "type": "public-key"}
        try:
            transports = json.loads(cred.transports or "[]")
            if transports:
                entry["transports"] = transports
        except (json.JSONDecodeError, TypeError):
            pass
        allow.append(entry)
    return allow


def _preflight(settings):
    """Common checks; returns (rp_id, error_dict_or_None)."""
    if not WEBAUTHN_AVAILABLE:
        return None, {"success": False, "message": "WebAuthn library not available."}
    if not settings.enabled:
        return None, {"success": False, "message": "Passkey authentication is disabled."}
    rp_id = get_rp_id(settings)
    insecure = check_secure_context(settings, rp_id)
    if insecure:
        return None, {"success": False, "message": insecure}
    return rp_id, None


def _base_options(settings, rp_id, challenge) -> dict:
    return {
        "rpId": rp_id,
        "challenge": base64url_encode(challenge),
        "timeout": (settings.challenge_timeout or 120) * 1000,
        "userVerification": settings.require_user_verification or "preferred",
    }


def get_authentication_options(user_email: str = None) -> dict:
    settings = _settings()
    rp_id, error = _preflight(settings)
    if error:
        return error
    if not check_authentication_options_rate_limit(get_client_ip()):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    challenge = generate_challenge()
    options = _base_options(settings, rp_id, challenge)

    if user_email:
        user_email = user_email.strip()
        allow = _allow_credentials(user_email)
        if not allow:
            # Do not reveal whether the account exists / has passkeys.
            allow = [{"id": _decoy_credential_id(user_email), "type": "public-key"}]
        options["allowCredentials"] = allow
        token = store_authentication_challenge(challenge, user_email)
    else:
        if not settings.allow_discoverable_credentials:
            return {"success": False, "message": "Discoverable credentials are not enabled."}
        token = store_authentication_challenge(challenge, None)

    return {"success": True, "options": options, "session_token": token}


def _verify_assertion(credential_json: dict, expected_challenge: bytes, expected_user, settings,
                      rp_id: str, ip: str, operation: str):
    """Verify an assertion against a stored credential. Returns (cred, error_dict)."""
    try:
        from webauthn.helpers import parse_authentication_credential_json
        credential = parse_authentication_credential_json(credential_json)
    except Exception as e:
        log_event(expected_user, None, operation, False, f"Malformed response: {e}")
        return None, {"success": False, "message": "Invalid authentication response."}

    credential_id = base64url_encode(credential.raw_id)
    filters = {"credential_id": credential_id, "enabled": 1, "revoked": 0}
    if expected_user:
        filters["user"] = expected_user
    cred = frappe.db.get_value(
        "Passkey Credential", filters,
        ["name", "user", "public_key", "sign_count", "user_handle"], as_dict=True,
    )
    if not cred:
        log_event(expected_user, None, operation, False, "Credential not found")
        return None, {"success": False, "message": GENERIC_FAILURE}

    user = cred.user
    # Discoverable flow: the authenticator-reported user handle must match what we issued.
    # Some clients send an empty userHandle instead of omitting it; treat that as absent.
    returned_handle = credential.response.user_handle or None
    if returned_handle is not None and cred.user_handle and returned_handle != cred.user_handle.encode("utf-8"):
        log_event(user, cred.name, operation, False, "User handle mismatch")
        return None, {"success": False, "message": GENERIC_FAILURE}

    if not frappe.db.get_value("User", user, "enabled"):
        log_event(user, cred.name, operation, False, "User disabled")
        return None, {"success": False, "message": GENERIC_FAILURE}

    current_count = cred.sign_count or 0
    try:
        from webauthn import verify_authentication_response as webauthn_verify_auth

        verification = webauthn_verify_auth(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=get_expected_origins(settings, rp_id),
            credential_public_key=base64url_decode(cred.public_key),
            credential_current_sign_count=current_count,
            require_user_verification=(settings.require_user_verification == "required"),
        )
    except Exception as e:
        reason = str(e)
        if "sign count" in reason.lower():
            # Counter did not advance: possible cloned authenticator. Reject and record it.
            frappe.log_error(title="Passkey Sign Count Violation",
                             message=f"User: {user}, credential: {cred.name}, {reason}")
            reason = f"Possible cloned authenticator: {reason}"
        else:
            frappe.log_error(title="Passkey Verification Error", message=f"User: {user}\n{reason}")
        log_event(user, cred.name, operation, False, reason, sign_count_before=current_count)
        return None, {"success": False, "message": GENERIC_FAILURE}

    new_count = verification.new_sign_count or 0
    updates = {"last_used_at": frappe.utils.now(), "last_used_ip": ip}
    if new_count > 0:
        updates["sign_count"] = new_count
    frappe.db.set_value("Passkey Credential", cred.name, updates, update_modified=False)
    log_event(user, cred.name, operation, True,
              sign_count_before=current_count, sign_count_after=new_count)
    return cred, None


def verify_authentication(credential_json: dict, session_token: str, create_session: bool = True) -> dict:
    """Verify a login assertion. With create_session=False (token clients) no cookie
    session is created; the caller issues its own credentials for the returned user."""
    settings = _settings()
    rp_id, error = _preflight(settings)
    if error:
        return error

    ip = get_client_ip()
    if is_authentication_blocked(ip):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    result = _verify_login(credential_json, session_token, settings, rp_id, ip, create_session)
    if not result.get("success"):
        record_authentication_failure(ip)
    return result


def _verify_login(credential_json, session_token, settings, rp_id, ip, create_session=True) -> dict:
    expected_challenge, expected_user = get_and_clear_authentication_challenge(session_token)
    if not expected_challenge:
        return {"success": False, "message": "Authentication challenge expired. Please try again.",
                "expired": True}

    cred, error = _verify_assertion(credential_json, expected_challenge, expected_user, settings,
                                    rp_id, ip, "authentication")
    if error:
        return error

    if not create_session:
        return {"success": True, "message": "Authentication successful.", "user": cred.user,
                "credential_name": cred.name}

    session = create_session_after_passkey_login(cred.user)
    if not session["success"]:
        return {"success": False, "message": session.get("message", "Session creation failed.")}
    return {"success": True, "message": "Authentication successful.", "user": cred.user,
            "full_name": session.get("full_name", "")}


# -- step-up (re-confirm identity of the logged-in user) ----------------------

def get_stepup_options(user_email: str) -> dict:
    settings = _settings()
    rp_id, error = _preflight(settings)
    if error:
        return error
    if not check_authentication_options_rate_limit(get_client_ip()):
        return {"success": False, "message": "Too many attempts. Please try again later."}
    allow = _allow_credentials(user_email)
    if not allow:
        return {"success": False, "message": "You have no passkey to confirm with."}
    challenge = generate_challenge()
    options = _base_options(settings, rp_id, challenge)
    options["allowCredentials"] = allow
    token = store_authentication_challenge(challenge, user_email, kind="stepup")
    return {"success": True, "options": options, "session_token": token}


def verify_stepup(user_email: str, credential_json: dict, session_token: str) -> dict:
    settings = _settings()
    rp_id, error = _preflight(settings)
    if error:
        return error
    ip = get_client_ip()
    if is_authentication_blocked(ip):
        return {"success": False, "message": "Too many attempts. Please try again later."}

    expected_challenge, expected_user = get_and_clear_authentication_challenge(session_token, kind="stepup")
    if not expected_challenge or expected_user != user_email:
        record_authentication_failure(ip)
        return {"success": False, "message": "Confirmation expired. Please try again."}

    cred, error = _verify_assertion(credential_json, expected_challenge, user_email, settings,
                                    rp_id, ip, "verification")
    if error:
        record_authentication_failure(ip)
        return error
    mark_stepup(user_email)
    return {"success": True, "message": "Identity confirmed."}
