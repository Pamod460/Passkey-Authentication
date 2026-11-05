"""Setup check: finds the configuration problems that break passkeys on a real site.

Run it from Passkey Settings > Run Setup Check, or from a terminal:
``bench --site <site> execute passkey_authentication.passkey_authentication.diagnostics.print_report``
"""
from urllib.parse import urlparse

import frappe
from frappe import _

from .security import host_matches_rp_id, parse_allowed_origins, site_host, validate_rp_id

OK, WARN, ERROR, INFO = "ok", "warning", "error", "info"


def _add(out, status, title, detail=""):
    out.append({"status": status, "title": title, "detail": detail})


def _site_url_host():
    try:
        url = frappe.utils.get_url()
    except Exception:
        return "", ""
    parsed = urlparse(url)
    return (parsed.hostname or "").lower(), parsed.scheme


def collect_checks(request_host: str = None) -> list:
    out = []
    settings = frappe.get_single("Passkey Settings")

    # Library ------------------------------------------------------------------
    try:
        import webauthn
        _add(out, OK, _("WebAuthn library installed"), getattr(webauthn, "__version__", ""))
    except ImportError:
        _add(out, ERROR, _("WebAuthn library missing"),
             _("Run: bench pip install 'webauthn>=2.5,<3' and restart."))

    if not settings.enabled:
        _add(out, WARN, _("Passkey authentication is disabled"), _("Tick Enable Passkey Authentication."))

    # RP ID --------------------------------------------------------------------
    host, scheme = _site_url_host()
    request_host = (request_host or "").split(":")[0].lower()
    rp_id = (settings.rp_id or "").strip().lower()
    if not rp_id:
        guess = site_host()
        if guess:
            _add(out, WARN, _("RP ID is empty"),
                 _("The site's host name {0} is used. Set RP ID explicitly so it never changes.").format(guess))
            rp_id = guess
        else:
            _add(out, ERROR, _("RP ID is empty"),
                 _("The browser's Host header is used, which a client controls. Set RP ID to your domain."))
            rp_id = request_host
    elif not validate_rp_id(rp_id):
        _add(out, ERROR, _("RP ID is not a valid domain"), _("Use a bare domain such as erp.example.com."))
    else:
        _add(out, OK, _("RP ID is set"), rp_id)

    for label, h in ((_("Site URL"), host), (_("This browser's address"), request_host)):
        if not h or not rp_id:
            continue
        if host_matches_rp_id(h, rp_id):
            _add(out, OK, _("{0} matches the RP ID").format(label), h)
        else:
            _add(out, ERROR, _("{0} does not match the RP ID").format(label),
                 _("{0} is not {1} or a subdomain of it, so browsers will refuse passkeys there.").format(h, rp_id))

    # HTTPS --------------------------------------------------------------------
    local = rp_id in ("localhost", "127.0.0.1")
    if scheme == "https" or local:
        _add(out, OK, _("Site URL uses HTTPS") if not local else _("Local development host"), "")
    else:
        _add(out, ERROR if settings.enforce_https else WARN, _("Site URL is not HTTPS"),
             _("Passkeys need HTTPS. Set host_name in site_config.json to https://your-domain, "
               "and make sure nginx sends X-Forwarded-Proto."))

    # Allowed origins ----------------------------------------------------------
    raw = settings.allowed_origins
    origins = parse_allowed_origins(settings)
    if raw and not origins:
        _add(out, ERROR, _("Allowed Origins could not be read"), _("It must be a JSON array of URLs."))
    for origin in origins:
        parsed = urlparse(origin)
        if not host_matches_rp_id(parsed.hostname or "", rp_id):
            _add(out, WARN, _("Allowed origin outside the RP ID"),
                 _("{0} is not under {1}. Other domains need a Passkey Client App (Related Origin Requests).").format(
                     origin, rp_id))
        elif parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
            _add(out, WARN, _("Allowed origin is not HTTPS"), origin)

    # Redis --------------------------------------------------------------------
    try:
        from .challenges import _cache
        key = "passkey_setup_check"
        _cache().set_value(key, "1", expires_in_sec=30)
        value = _cache().get_value(key)
        _cache().delete_value(key)
        if value in ("1", b"1", 1):
            _add(out, OK, _("Redis cache works"), "")
        else:
            _add(out, ERROR, _("Redis cache did not return the stored value"), _("Challenges cannot be kept."))
    except Exception as e:
        _add(out, ERROR, _("Redis cache error"), str(e))

    # Email and scheduler ------------------------------------------------------
    try:
        if frappe.db.exists("Email Account", {"enable_outgoing": 1}):
            _add(out, OK, _("Outgoing email is set up"), "")
        else:
            _add(out, WARN, _("No outgoing email account"),
                 _("Users will not get new-passkey, revocation, recovery and reminder emails."))
    except Exception:
        pass
    try:
        from frappe.utils.scheduler import is_scheduler_disabled
        if is_scheduler_disabled():
            _add(out, WARN, _("Scheduler is disabled"),
                 _("Old log entries are not cleaned up and enrolment reminders are not sent."))
    except Exception:
        pass

    # Policy -------------------------------------------------------------------
    users = frappe.db.sql("""select count(distinct user) from `tabPasskey Credential`
                             where enabled = 1 and revoked = 0""")[0][0]
    _add(out, INFO, _("Users with a passkey"), str(users))
    if not settings.password_fallback_enabled:
        _add(out, INFO, _("Passkey-only mode is on"),
             _("Users with a passkey cannot use a password. Make sure recovery codes are allowed or "
               "an admin can revoke lost passkeys."))
    if settings.allow_discoverable_credentials and not settings.enable_conditional_ui:
        _add(out, INFO, _("Autofill (conditional UI) is off"), _("Users must press 'Sign in with Passkey'."))
    _two_factor_checks(out, settings)

    # Client apps --------------------------------------------------------------
    _client_app_checks(out, rp_id)
    return out


def _two_factor_checks(out, settings):
    try:
        enabled = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
    except Exception:
        return
    if not enabled:
        return
    satisfies = settings.get("passkey_satisfies_2fa")
    if satisfies is None or int(satisfies):
        if settings.require_user_verification != "required":
            _add(out, WARN, _("Two-factor users need user verification"),
                 _("Passkey logins without fingerprint/face/PIN are refused for two-factor users. "
                   "Set User Verification to 'required' so every passkey asks for it."))
        else:
            _add(out, OK, _("Passkeys count as two-factor authentication"), "")
    else:
        _add(out, INFO, _("Two-factor users cannot sign in with a passkey"),
             _("Tick 'Passkey With User Verification Counts As Two-Factor' to allow it."))


def _client_app_checks(out, rp_id):
    from . import client_apps
    apps = client_apps.get_enabled_apps()
    if not apps:
        return
    for app in apps:
        name = app.app_name or app.name
        web = client_apps.split_lines(app.web_origins)
        fps = client_apps.split_lines(app.android_sha256_fingerprints)
        ios = client_apps.split_lines(app.ios_app_ids)
        if not (web or fps or ios):
            _add(out, WARN, _("Client app {0} has no platform").format(name),
                 _("Add a web origin, an Android fingerprint or an iOS app ID."))
        if not app.client_id:
            _add(out, ERROR, _("Client app {0} has no OAuth client").format(name), "")
        for fp in fps:
            if not client_apps.FINGERPRINT_RE.match(client_apps.normalize_fingerprint(fp)):
                _add(out, ERROR, _("Client app {0}: bad Android fingerprint").format(name), fp)
        if fps and not app.android_package_name:
            _add(out, ERROR, _("Client app {0}: Android package name missing").format(name), "")
        for app_id in ios:
            if not client_apps.IOS_APP_ID_RE.match(app_id):
                _add(out, ERROR, _("Client app {0}: bad iOS app ID").format(name),
                     _("{0} should look like TEAMID1234.com.example.app").format(app_id))
    related = client_apps.related_origins().get("origins", [])
    if related:
        labels = {(urlparse(o).hostname or "").split(".")[-2] for o in related if urlparse(o).hostname}
        if len(labels) > 5:
            _add(out, WARN, _("Too many related origin domains"),
                 _("Browsers only honour 5 distinct domain labels in /.well-known/webauthn."))
    _add(out, INFO, _("Check the association files from outside"),
         _("Open https://{0}/.well-known/assetlinks.json and /.well-known/apple-app-site-association "
           "in a browser; both must return JSON over HTTPS without redirects.").format(rp_id))


def summary(checks: list) -> dict:
    return {s: sum(1 for c in checks if c["status"] == s) for s in (OK, WARN, ERROR, INFO)}


@frappe.whitelist(methods=["GET", "POST"])
def run_setup_check():
    frappe.only_for("System Manager")
    host = frappe.request.host if getattr(frappe, "request", None) else None
    checks = collect_checks(host)
    return {"success": True, "checks": checks, "summary": summary(checks)}


def print_report():
    """For bench execute."""
    checks = collect_checks()
    for c in checks:
        print(f"[{c['status'].upper():7}] {c['title']}" + (f" - {c['detail']}" if c["detail"] else ""))
    print(summary(checks))
