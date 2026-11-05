app_name = "passkey_authentication"
app_title = "Passkey Authentication"
app_publisher = "RJPK Jayasundara"
app_description = "Production-ready WebAuthn/Passkey authentication for Frappe/ERPNext"
app_email = "109800446+Pamod460@users.noreply.github.com"
app_license = "MIT"

# --------------------------------------------------------------------------
# Includes
# --------------------------------------------------------------------------
# Desk: shared helpers + the after-login "set up a passkey" prompt
# (the management page ships its own JS in page/my_passkeys/).
app_include_css = "/assets/passkey_authentication/css/passkey.css"
app_include_js = [
    "/assets/passkey_authentication/js/passkey_utils.js",
    "/assets/passkey_authentication/js/passkey_registration_popup.js",
]

# Website (login page): helpers + the "Sign in with Passkey" button.
web_include_css = "/assets/passkey_authentication/css/passkey.css"
web_include_js = [
    "/assets/passkey_authentication/js/passkey_utils.js",
    "/assets/passkey_authentication/js/passkey_login.js",
]

# Desk forms: passkey admin buttons on the User form.
doctype_js = {"User": "public/js/user_passkeys.js"}

# --------------------------------------------------------------------------
# Doc Events
# --------------------------------------------------------------------------
doc_events = {
    "User": {
        "after_insert": "passkey_authentication.passkey_authentication.utils.generate_user_handle_on_insert",
    }
}

# --------------------------------------------------------------------------
# Login hook (enforces "passkey only" when password login is disabled)
# --------------------------------------------------------------------------
on_login = "passkey_authentication.passkey_authentication.session.on_login"

# --------------------------------------------------------------------------
# Client apps: serves /.well-known/assetlinks.json, apple-app-site-association
# and webauthn (related origins) from Passkey Client App records.
# --------------------------------------------------------------------------
page_renderer = ["passkey_authentication.passkey_authentication.well_known.WellKnownRenderer"]

# --------------------------------------------------------------------------
# Scheduler Events
# --------------------------------------------------------------------------
scheduler_events = {
    "daily": [
        "passkey_authentication.passkey_authentication.tasks.cleanup_old_logs",
        "passkey_authentication.passkey_authentication.enforcement.send_enrollment_reminders",
    ],
}

# --------------------------------------------------------------------------
# Permission Hooks
# --------------------------------------------------------------------------
has_permission = {
    "Passkey Credential": "passkey_authentication.passkey_authentication.doctype.passkey_credential.passkey_credential.has_permission",
    "Passkey Authentication Log": "passkey_authentication.passkey_authentication.doctype.passkey_authentication_log.passkey_authentication_log.has_permission",
    "Passkey Settings": "passkey_authentication.passkey_authentication.doctype.passkey_settings.passkey_settings.has_permission",
    "Passkey Recovery Code": "passkey_authentication.passkey_authentication.doctype.passkey_recovery_code.passkey_recovery_code.has_permission",
}

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
fixtures = [
    {"dt": "Custom Field", "filters": [["module", "=", "Passkey Authentication"]]},
]

# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------
after_install = "passkey_authentication.passkey_authentication.setup.after_install"
