"""Registered client apps (Flutter, Angular, native...) that use this site's passkeys.

Each enabled *Passkey Client App* contributes:
- the WebAuthn origins its assertions arrive from (web origins, Android
  ``android:apk-key-hash:...`` origins, and ``https://<rp_id>`` for iOS apps),
- entries in ``/.well-known/assetlinks.json`` (Android),
  ``/.well-known/apple-app-site-association`` (iOS) and
  ``/.well-known/webauthn`` (Related Origin Requests for other web domains).
"""
import re

import frappe

from .serialization import base64url_encode

DOCTYPE = "Passkey Client App"

FINGERPRINT_RE = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
IOS_APP_ID_RE = re.compile(r"^[A-Z0-9]{10}\.[A-Za-z0-9.\-]+$")
ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
WEB_ORIGIN_RE = re.compile(r"^(https://[A-Za-z0-9.\-]+(:\d+)?|http://(localhost|127\.0\.0\.1)(:\d+)?)$")

_FIELDS = ["name", "app_name", "client_id", "oauth_client", "web_origins", "android_package_name",
           "android_sha256_fingerprints", "ios_app_ids", "access_token_lifetime",
           "refresh_token_lifetime_days"]


def split_lines(value) -> list:
    """One entry per line (commas and whitespace also separate entries)."""
    return [v.strip() for v in re.split(r"[\s,]+", value or "") if v.strip()]


def normalize_fingerprint(value: str) -> str:
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    return ":".join(hex_only[i:i + 2] for i in range(0, len(hex_only), 2))


def android_origin(fingerprint: str) -> str:
    """WebAuthn origin Android's Credential Manager reports for an app signed with this cert."""
    raw = bytes.fromhex(normalize_fingerprint(fingerprint).replace(":", ""))
    return "android:apk-key-hash:" + base64url_encode(raw)


def get_enabled_apps() -> list:
    try:
        return frappe.get_all(DOCTYPE, filters={"enabled": 1}, fields=_FIELDS)
    except Exception:
        # Table missing (app not migrated yet) or similar: behave as if none are configured.
        return []


def get_app_by_client_id(client_id):
    if not client_id or not isinstance(client_id, str) or len(client_id) > 140:
        return None
    for app in get_enabled_apps():
        if app.client_id and app.client_id == client_id:
            return app
    return None


def app_origins(app, rp_id: str) -> list:
    origins = [o.rstrip("/") for o in split_lines(app.web_origins)]
    for fp in split_lines(app.android_sha256_fingerprints):
        if FINGERPRINT_RE.match(normalize_fingerprint(fp)):
            origins.append(android_origin(fp))
    if split_lines(app.ios_app_ids) and rp_id:
        # iOS (ASAuthorization) reports the associated domain as the origin.
        origins.append(f"https://{rp_id}")
    return origins


def get_client_origins(rp_id: str) -> list:
    seen, out = set(), []
    for app in get_enabled_apps():
        for origin in app_origins(app, rp_id):
            if origin not in seen:
                seen.add(origin)
                out.append(origin)
    return out


# -- .well-known documents ----------------------------------------------------

def assetlinks() -> list:
    statements = []
    for app in get_enabled_apps():
        package = (app.android_package_name or "").strip()
        fps = [normalize_fingerprint(f) for f in split_lines(app.android_sha256_fingerprints)]
        fps = [f for f in fps if FINGERPRINT_RE.match(f)]
        if package and fps:
            statements.append({
                "relation": ["delegate_permission/common.handle_all_urls",
                             "delegate_permission/common.get_login_creds"],
                "target": {"namespace": "android_app", "package_name": package,
                           "sha256_cert_fingerprints": fps},
            })
    return statements


def apple_app_site_association() -> dict:
    apps = []
    for app in get_enabled_apps():
        for app_id in split_lines(app.ios_app_ids):
            if app_id not in apps:
                apps.append(app_id)
    return {"webcredentials": {"apps": apps}}


def related_origins() -> dict:
    origins = []
    for app in get_enabled_apps():
        for origin in split_lines(app.web_origins):
            origin = origin.rstrip("/")
            if origin.startswith("https://") and origin not in origins:
                origins.append(origin)
    return {"origins": origins}
