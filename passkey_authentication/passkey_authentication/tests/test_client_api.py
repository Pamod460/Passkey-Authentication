"""Client-app (Flutter / Angular / native) token flow, against the fake frappe from test_flow."""
import json
import sys
import unittest
from datetime import datetime, timedelta

from passkey_authentication.passkey_authentication.tests.test_flow import (
    EMAIL, HAVE_LIBS, HAVE_REAL_FRAPPE, ORIGIN, SoftAuthenticator, b64u, default_settings,
    install_fake_frappe,
)

CLIENT_ID = "flutter-client-123"
ANDROID_FP = ":".join(["AB"] * 32)
ANDROID_ORIGIN = "android:apk-key-hash:" + b64u(bytes([0xAB] * 32))
ANGULAR_ORIGIN = "https://portal.example.org"

try:
    import werkzeug  # noqa: F401  (always present in a bench)
    HAVE_WERKZEUG = True
except ImportError:  # pragma: no cover
    HAVE_WERKZEUG = False


@unittest.skipUnless(HAVE_LIBS, "webauthn / cbor2 / cryptography not installed")
@unittest.skipIf(HAVE_REAL_FRAPPE, "uses an in-memory fake frappe; run outside a bench")
class TestClientApi(unittest.TestCase):
    def setUp(self):
        self.frappe, self.state = install_fake_frappe()
        self.state.settings = default_settings()
        t = self.state.tables
        t["User"].append({"name": EMAIL, "enabled": 1, "full_name": "Alice",
                          "custom_passkey_user_handle": None})
        t["OAuth Client"] = [{"name": "oc1", "client_id": CLIENT_ID, "scopes": "all openid"}]
        t["OAuth Bearer Token"] = []
        t["Passkey Client App"] = [{
            "name": "Mobile", "app_name": "Mobile", "enabled": 1, "oauth_client": "oc1",
            "client_id": CLIENT_ID, "web_origins": ANGULAR_ORIGIN,
            "android_package_name": "lk.example.app", "android_sha256_fingerprints": ANDROID_FP,
            "ios_app_ids": "ABCDE12345.lk.example.app", "access_token_lifetime": 900,
            "refresh_token_lifetime_days": 30}]

        orig_get_doc = self.frappe.get_doc

        def get_doc(data):
            data.setdefault("creation", datetime.now())
            return orig_get_doc(data)
        self.frappe.get_doc = get_doc

        for m in [m for m in sys.modules if m.startswith("passkey_authentication.passkey_authentication") and ".tests" not in m]:
            del sys.modules[m]
        from passkey_authentication.passkey_authentication import api, client_api, client_apps
        self.api, self.client, self.apps = api, client_api, client_apps

    # -- helpers ----------------------------------------------------------------
    def register(self, origin=ORIGIN):
        self.frappe.session.user = EMAIL
        auth = SoftAuthenticator()
        opts = self.api.registration_options()
        self.assertTrue(opts["success"], opts)
        res = self.api.verify_registration(credential=json.dumps(auth.create(opts["options"], origin)))
        self.assertTrue(res["success"], res)
        self.frappe.session.user = "Guest"
        return auth

    def passkey_login(self, auth, origin=ORIGIN, email=None, client_id=CLIENT_ID):
        opts = self.client.login_options(client_id=client_id, user_email=email)
        self.assertTrue(opts["success"], opts)
        handle = self.state.tables["User"][0]["custom_passkey_user_handle"].encode()
        cred = auth.get(opts["options"], origin, user_handle=None if email else handle)
        return self.client.login(client_id=client_id, credential=json.dumps(cred),
                                 session_token=opts["session_token"])

    def token_row(self):
        return self.state.tables["OAuth Bearer Token"][-1]

    # -- origins / association files ---------------------------------------------
    def test_android_origin_from_fingerprint(self):
        self.assertEqual(self.apps.android_origin(ANDROID_FP.lower().replace(":", "")), ANDROID_ORIGIN)

    def test_expected_origins_include_client_apps(self):
        from passkey_authentication.passkey_authentication.security import get_expected_origins
        origins = get_expected_origins(self.state.settings, "erp.example.com")
        self.assertEqual(origins[0], ORIGIN)
        self.assertIn(ANDROID_ORIGIN, origins)
        self.assertIn(ANGULAR_ORIGIN, origins)
        self.assertEqual(len(origins), len(set(origins)))

    def test_disabled_app_contributes_nothing(self):
        self.state.tables["Passkey Client App"][0]["enabled"] = 0
        from passkey_authentication.passkey_authentication.security import get_expected_origins
        self.assertEqual(get_expected_origins(self.state.settings, "erp.example.com"), [ORIGIN])
        self.assertEqual(self.client.config(client_id=CLIENT_ID)["success"], False)

    def test_well_known_documents(self):
        links = self.apps.assetlinks()
        self.assertEqual(links[0]["target"]["package_name"], "lk.example.app")
        self.assertIn("delegate_permission/common.get_login_creds", links[0]["relation"])
        self.assertEqual(self.apps.apple_app_site_association(),
                         {"webcredentials": {"apps": ["ABCDE12345.lk.example.app"]}})
        self.assertEqual(self.apps.related_origins(), {"origins": [ANGULAR_ORIGIN]})

    @unittest.skipUnless(HAVE_WERKZEUG, "werkzeug not installed")
    def test_well_known_renderer(self):
        from passkey_authentication.passkey_authentication.well_known import WellKnownRenderer
        r = WellKnownRenderer("/.well-known/apple-app-site-association")
        self.assertTrue(r.can_render())
        resp = r.render()
        self.assertEqual(resp.mimetype, "application/json")
        self.assertIn("ABCDE12345.lk.example.app", resp.get_data(as_text=True))
        self.assertFalse(WellKnownRenderer("/login").can_render())

    # -- login -------------------------------------------------------------------
    def test_config(self):
        res = self.client.config(client_id=CLIENT_ID)
        self.assertTrue(res["success"])
        self.assertEqual(res["rp_id"], "erp.example.com")

    def test_unknown_client_rejected(self):
        self.assertFalse(self.client.login_options(client_id="nope")["success"])

    def test_android_passkey_login_issues_bearer_token(self):
        auth = self.register()  # created on the website, synced to the phone
        res = self.passkey_login(auth, origin=ANDROID_ORIGIN)
        self.assertTrue(res["success"], res)
        self.assertEqual(res["user"], EMAIL)
        self.assertEqual(res["token_type"], "Bearer")
        self.assertEqual(res["expires_in"], 900)
        row = self.token_row()
        self.assertEqual(row["client"], "oc1")
        self.assertEqual(row["user"], EMAIL)
        self.assertEqual(row["scopes"], "all openid")
        self.assertEqual(row["status"], "Active")
        self.assertEqual(self.state.sessions, [])  # no cookie session for token clients

    def test_angular_origin_login_with_email(self):
        auth = self.register()
        res = self.passkey_login(auth, origin=ANGULAR_ORIGIN, email=EMAIL)
        self.assertTrue(res["success"], res)

    def test_registration_from_android_app(self):
        auth = self.register(origin=ANDROID_ORIGIN)
        self.assertTrue(self.passkey_login(auth, origin=ANDROID_ORIGIN)["success"])

    def test_unregistered_origin_rejected(self):
        auth = self.register()
        res = self.passkey_login(auth, origin="android:apk-key-hash:" + b64u(bytes(32)))
        self.assertFalse(res["success"])
        self.assertEqual(self.state.tables["OAuth Bearer Token"], [])

    def test_failed_login_counts_toward_rate_limit(self):
        auth = self.register()
        self.state.settings.authentication_rate_limit = 2
        for _ in range(2):
            self.assertFalse(self.passkey_login(auth, origin="https://evil.example.net")["success"])
        res = self.passkey_login(auth, origin=ORIGIN)
        self.assertFalse(res["success"])
        self.assertIn("Too many", res["message"])

    # -- refresh / logout ----------------------------------------------------------
    def test_refresh_rotates_and_detects_reuse(self):
        auth = self.register()
        first = self.passkey_login(auth)
        second = self.client.refresh(client_id=CLIENT_ID, refresh_token=first["refresh_token"])
        self.assertTrue(second["success"], second)
        self.assertNotEqual(second["access_token"], first["access_token"])
        rows = self.state.tables["OAuth Bearer Token"]
        self.assertEqual([r["status"] for r in rows], ["Revoked", "Active"])
        # Replaying the old refresh token revokes everything for this user + app.
        replay = self.client.refresh(client_id=CLIENT_ID, refresh_token=first["refresh_token"])
        self.assertFalse(replay["success"])
        self.assertEqual({r["status"] for r in rows}, {"Revoked"})

    def test_refresh_expires(self):
        auth = self.register()
        first = self.passkey_login(auth)
        self.token_row()["creation"] = datetime.now() - timedelta(days=31)
        self.assertFalse(self.client.refresh(client_id=CLIENT_ID, refresh_token=first["refresh_token"])["success"])

    def test_refresh_refused_for_disabled_user(self):
        auth = self.register()
        first = self.passkey_login(auth)
        self.state.tables["User"][0]["enabled"] = 0
        self.assertFalse(self.client.refresh(client_id=CLIENT_ID, refresh_token=first["refresh_token"])["success"])

    def test_refresh_token_bound_to_client(self):
        auth = self.register()
        first = self.passkey_login(auth)
        self.state.tables["OAuth Client"].append({"name": "oc2", "client_id": "other", "scopes": "all"})
        self.state.tables["Passkey Client App"].append({
            "name": "Other", "app_name": "Other", "enabled": 1, "oauth_client": "oc2", "client_id": "other"})
        self.assertFalse(self.client.refresh(client_id="other", refresh_token=first["refresh_token"])["success"])

    def test_logout_revokes(self):
        auth = self.register()
        first = self.passkey_login(auth)
        self.assertTrue(self.client.logout(client_id=CLIENT_ID, refresh_token=first["refresh_token"])["success"])
        self.assertEqual(self.token_row()["status"], "Revoked")
        self.assertFalse(self.client.refresh(client_id=CLIENT_ID, refresh_token=first["refresh_token"])["success"])

    def test_me(self):
        self.register()
        self.frappe.session.user = EMAIL
        res = self.client.me()
        self.assertEqual((res["user"], res["passkey_count"]), (EMAIL, 1))
        self.frappe.session.user = "Guest"
        self.assertFalse(self.client.me()["success"])

    def test_stepup_is_bound_to_bearer_token(self):
        from passkey_authentication.passkey_authentication import session
        self.frappe.session.user = EMAIL
        self.frappe.session.sid = EMAIL  # what frappe.set_user() does for Bearer requests
        self.frappe.session.data = {}
        headers = self.frappe.request.headers
        headers["Authorization"] = "Bearer token-A"
        session.mark_stepup(EMAIL)
        self.assertTrue(session.has_recent_stepup(EMAIL))
        headers["Authorization"] = "Bearer token-B"
        self.assertFalse(session.has_recent_stepup(EMAIL))
        del headers["Authorization"]

    # -- password bootstrap ----------------------------------------------------------
    def test_password_login(self):
        self.state.passwords[EMAIL] = "s3cret"
        self.assertFalse(self.client.password_login(client_id=CLIENT_ID, usr=EMAIL, pwd="bad")["success"])
        res = self.client.password_login(client_id=CLIENT_ID, usr=EMAIL, pwd="s3cret")
        self.assertTrue(res["success"], res)
        self.assertTrue(res["access_token"])

    def test_password_login_blocked_in_passkey_only_mode(self):
        self.register()
        self.state.passwords[EMAIL] = "s3cret"
        self.state.settings.password_fallback_enabled = 0
        res = self.client.password_login(client_id=CLIENT_ID, usr=EMAIL, pwd="s3cret")
        self.assertFalse(res["success"])


if __name__ == "__main__":
    unittest.main()
