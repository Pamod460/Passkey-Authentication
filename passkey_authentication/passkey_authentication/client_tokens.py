"""Bearer tokens for client apps, stored as standard Frappe *OAuth Bearer Token* rows.

Because they are ordinary OAuth bearer tokens, an app can send
``Authorization: Bearer <access_token>`` to any Frappe/ERPNext API and Frappe
authenticates it natively. Refresh tokens rotate on every use; presenting an
already-rotated refresh token revokes every token of that user for that app
(reuse means it was probably stolen).
"""
import datetime
import secrets

import frappe
from frappe import _

TOKEN_DOCTYPE = "OAuth Bearer Token"
DEFAULT_ACCESS_SECONDS = 3600
DEFAULT_REFRESH_DAYS = 30


def _now():
    return frappe.utils.now_datetime()


def _to_datetime(value):
    if isinstance(value, datetime.datetime):
        return value
    return frappe.utils.get_datetime(value)


def _stored(token: str) -> str:
    """How Frappe stores a token: hashed on newer versions, raw on v16."""
    try:
        from frappe.integrations.doctype.oauth_bearer_token.oauth_bearer_token import get_oauth_token_hash
    except ImportError:
        return token
    return get_oauth_token_hash(token)


def _access_seconds(app) -> int:
    value = int(app.access_token_lifetime or DEFAULT_ACCESS_SECONDS)
    return max(60, min(value, 86400))


def _refresh_days(app) -> int:
    value = int(app.refresh_token_lifetime_days or DEFAULT_REFRESH_DAYS)
    return max(1, min(value, 365))


def issue_tokens(app, user: str) -> dict:
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    expires_in = _access_seconds(app)
    scopes = frappe.db.get_value("OAuth Client", app.oauth_client, "scopes") or "all"
    frappe.get_doc({
        "doctype": TOKEN_DOCTYPE,
        "client": app.oauth_client,
        "user": user,
        "scopes": scopes,
        "access_token": access_token,  # the doctype hashes it on insert where supported
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "expiration_time": _now() + datetime.timedelta(seconds=expires_in),
        "status": "Active",
    }).insert(ignore_permissions=True)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": refresh_token,
        "refresh_expires_in": _refresh_days(app) * 86400,
        "scope": scopes,
    }


def _find_by_refresh(app, refresh_token):
    if not refresh_token or not isinstance(refresh_token, str) or len(refresh_token) > 256:
        return None
    return frappe.db.get_value(
        TOKEN_DOCTYPE,
        {"refresh_token": _stored(refresh_token), "client": app.oauth_client},
        ["name", "user", "status", "creation"], as_dict=True,
    )


def revoke_all(app, user: str) -> None:
    frappe.db.set_value(TOKEN_DOCTYPE, {"user": user, "client": app.oauth_client, "status": "Active"},
                        "status", "Revoked", update_modified=False)


def refresh_tokens(app, refresh_token: str) -> dict:
    row = _find_by_refresh(app, refresh_token)
    if not row:
        return {"success": False, "message": _("Invalid refresh token.")}
    if row.status != "Active":
        # A rotated refresh token came back: treat it as stolen and end every session of this app.
        revoke_all(app, row.user)
        frappe.log_error(title="Passkey Client Refresh Token Reuse",
                         message=f"User: {row.user}, client: {app.oauth_client}")
        return {"success": False, "message": _("Invalid refresh token.")}

    age = (_now() - _to_datetime(row.creation)).total_seconds()
    frappe.db.set_value(TOKEN_DOCTYPE, row.name, "status", "Revoked", update_modified=False)
    if age > _refresh_days(app) * 86400:
        return {"success": False, "message": _("Refresh token expired. Please sign in again.")}
    if not frappe.db.get_value("User", row.user, "enabled"):
        return {"success": False, "message": _("User account is disabled.")}
    return {"success": True, "user": row.user, **issue_tokens(app, row.user)}


def revoke_refresh_token(app, refresh_token: str) -> bool:
    row = _find_by_refresh(app, refresh_token)
    if not row:
        return False
    frappe.db.set_value(TOKEN_DOCTYPE, row.name, "status", "Revoked", update_modified=False)
    return True
