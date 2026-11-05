import json

import frappe
from frappe import _
from frappe.model.document import Document

from passkey_authentication.passkey_authentication.security import validate_rp_id


class PasskeySettings(Document):
    def validate(self):
        if self.rp_id:
            self.rp_id = self.rp_id.strip()
            if not validate_rp_id(self.rp_id):
                frappe.throw(_("RP ID must be a bare domain such as erp.example.com (no scheme, port or path)."))

        if self.allowed_origins:
            try:
                origins = json.loads(self.allowed_origins)
            except json.JSONDecodeError:
                frappe.throw(_("Allowed Origins must be valid JSON."))
            if not isinstance(origins, list):
                frappe.throw(_("Allowed Origins must be a JSON array."))
            for origin in origins:
                if not isinstance(origin, str) or not origin.startswith(("https://", "http://")):
                    frappe.throw(_("Each allowed origin must be a string starting with https:// or http://."))

        if self.challenge_timeout and not 30 <= self.challenge_timeout <= 600:
            frappe.throw(_("Challenge timeout must be between 30 and 600 seconds."))
        if self.max_credentials_per_user and not 1 <= self.max_credentials_per_user <= 50:
            frappe.throw(_("Max credentials per user must be between 1 and 50."))
        if self.log_retention_days and self.log_retention_days < 0:
            frappe.throw(_("Log retention cannot be negative."))
        if self.enrollment_grace_days and self.enrollment_grace_days < 0:
            frappe.throw(_("Grace period cannot be negative."))
        if self.recovery_code_count and not 4 <= self.recovery_code_count <= 20:
            frappe.throw(_("Codes per set must be between 4 and 20."))
        for row in self.get("required_roles") or []:
            if row.role in ("Guest", "All"):
                frappe.throw(_("Role {0} cannot require passkeys: it includes users who cannot sign in "
                               "or every user.").format(row.role))
        if self.get("custom_aaguid_names"):
            try:
                names = json.loads(self.custom_aaguid_names)
            except json.JSONDecodeError:
                frappe.throw(_("Extra Authenticator Names must be valid JSON."))
            if not isinstance(names, dict):
                frappe.throw(_("Extra Authenticator Names must be a JSON object of AAGUID: name."))


def has_permission(doc, user=None, ptype=None):
    user = user or frappe.session.user
    return "System Manager" in frappe.get_roles(user)


def get_settings():
    return frappe.get_single("Passkey Settings")
