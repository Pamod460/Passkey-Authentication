"""Friendly names for passkey providers and security keys, looked up by AAGUID.

``aaguid_names.json`` is a names-only snapshot of the community list at
github.com/passkeydeveloper/passkey-authenticator-aaguids (deprecated upstream in
favour of the FIDO Metadata Service, so the snapshot is bundled instead of fetched).
Admins can add or override names in Passkey Settings > Extra Authenticator Names.
Some browsers (notably Firefox) replace the AAGUID with zeros when no attestation is
requested; those passkeys fall back to a generic name.
"""
import json
import os

import frappe

ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"
_BUILTIN = None


def _builtin() -> dict:
    global _BUILTIN
    if _BUILTIN is None:
        path = os.path.join(os.path.dirname(__file__), "aaguid_names.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _BUILTIN = {k.lower(): v for k, v in json.load(fh).items()}
        except (OSError, ValueError):
            _BUILTIN = {}
    return _BUILTIN


def _custom(settings=None) -> dict:
    try:
        settings = settings or frappe.get_single("Passkey Settings")
        raw = settings.get("custom_aaguid_names") if hasattr(settings, "get") else None
        data = json.loads(raw) if raw else {}
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in data.items() if v}


def authenticator_name(aaguid, attachment=None, settings=None) -> str:
    """Display name for an AAGUID, or a generic one from the attachment type."""
    key = (str(aaguid or "")).strip().lower()
    if key and key != ZERO_AAGUID:
        name = _custom(settings).get(key) or _builtin().get(key)
        if name:
            return name
    if attachment == "cross-platform":
        return "Security key"
    if attachment == "platform":
        return "This device"
    return ""
