import frappe
from frappe.model.document import Document

from passkey_authentication.passkey_authentication.client_apps import (
    ANDROID_PACKAGE_RE, FINGERPRINT_RE, IOS_APP_ID_RE, WEB_ORIGIN_RE, normalize_fingerprint, split_lines,
)


class PasskeyClientApp(Document):
    def validate(self):
        origins = [o.rstrip("/") for o in split_lines(self.web_origins)]
        for origin in origins:
            if not WEB_ORIGIN_RE.match(origin):
                frappe.throw(f"Invalid web origin '{origin}'. Use https://host[:port] with no path "
                             "(http:// is allowed only for localhost).")
        self.web_origins = "\n".join(origins)

        fingerprints = [normalize_fingerprint(f) for f in split_lines(self.android_sha256_fingerprints)]
        for fp in fingerprints:
            if not FINGERPRINT_RE.match(fp):
                frappe.throw(f"Invalid SHA-256 fingerprint '{fp}'. Expected 32 hex bytes like AB:CD:...")
        self.android_sha256_fingerprints = "\n".join(fingerprints)
        if self.android_package_name:
            self.android_package_name = self.android_package_name.strip()
            if not ANDROID_PACKAGE_RE.match(self.android_package_name):
                frappe.throw("Invalid Android package name.")
        if bool(self.android_package_name) != bool(fingerprints):
            frappe.throw("Android needs both the package name and at least one signing fingerprint.")

        app_ids = split_lines(self.ios_app_ids)
        for app_id in app_ids:
            if not IOS_APP_ID_RE.match(app_id):
                frappe.throw(f"Invalid iOS app ID '{app_id}'. Use TEAMID.bundle.id (10-character Team ID).")
        self.ios_app_ids = "\n".join(app_ids)

        if self.access_token_lifetime and not 60 <= self.access_token_lifetime <= 86400:
            frappe.throw("Access token lifetime must be between 60 and 86400 seconds.")
        if self.refresh_token_lifetime_days and not 1 <= self.refresh_token_lifetime_days <= 365:
            frappe.throw("Refresh token lifetime must be between 1 and 365 days.")

    def on_update(self):
        if self.has_value_changed("enabled") and not self.enabled:
            # Disabling an app signs everyone out of it.
            frappe.db.set_value("OAuth Bearer Token", {"client": self.oauth_client, "status": "Active"},
                                "status", "Revoked", update_modified=False)
