import json

import frappe
from frappe.model.document import Document

from passkey_authentication.passkey_authentication.security import validate_rp_id


class PasskeySettings(Document):
    def validate(self):
        if self.rp_id:
            self.rp_id = self.rp_id.strip()
            if not validate_rp_id(self.rp_id):
                frappe.throw("RP ID must be a bare domain such as erp.example.com (no scheme, port or path).")

        if self.allowed_origins:
            try:
                origins = json.loads(self.allowed_origins)
            except json.JSONDecodeError:
                frappe.throw("Allowed Origins must be valid JSON.")
            if not isinstance(origins, list):
                frappe.throw("Allowed Origins must be a JSON array.")
            for origin in origins:
                if not isinstance(origin, str) or not origin.startswith(("https://", "http://")):
                    frappe.throw("Each allowed origin must be a string starting with https:// or http://.")

        if self.challenge_timeout and not 30 <= self.challenge_timeout <= 600:
            frappe.throw("Challenge timeout must be between 30 and 600 seconds.")
        if self.max_credentials_per_user and not 1 <= self.max_credentials_per_user <= 50:
            frappe.throw("Max credentials per user must be between 1 and 50.")
        if self.log_retention_days and self.log_retention_days < 0:
            frappe.throw("Log retention cannot be negative.")


def has_permission(doc, user=None, ptype=None):
    user = user or frappe.session.user
    return "System Manager" in frappe.get_roles(user)


def get_settings():
    return frappe.get_single("Passkey Settings")
