"""Setup check, RP ID fallback, admin tools, role enforcement, AAGUID names, 2FA and
recovery codes, against the fake frappe from test_flow."""
import json
import sys
import types
import unittest
import uuid
from datetime import datetime, timedelta

from passkey_authentication.passkey_authentication.tests.test_flow import (
    DD, EMAIL, HAVE_LIBS, HAVE_REAL_FRAPPE, ORIGIN, SoftAuthenticator, default_settings,
    install_fake_frappe,
)

GOOGLE_PM = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
ADMIN = "admin@example.com"


@unittest.skipUnless(HAVE_LIBS, "webauthn / cbor2 / cryptography not installed")
@unittest.skipIf(HAVE_REAL_FRAPPE, "uses an in-memory fake frappe; run outside a bench")
class FeatureTestCase(unittest.TestCase):
    def setUp(self):
        self.frappe, self.state = install_fake_frappe()
        f, state = self.frappe, self.state
        state.settings = default_settings()
        t = state.tables
        t["User"].append({"name": EMAIL, "email": EMAIL, "enabled": 1, "full_name": "Alice",
                          "custom_passkey_user_handle": None, "custom_passkey_required_since": None})
        t["User"].append({"name": ADMIN, "email": ADMIN, "enabled": 1, "full_name": "Admin"})
        t["Passkey Recovery Code"] = []
        t["Has Role"] = []
        self.roles = {EMAIL: ["Accounts User"], ADMIN: ["System Manager"]}
        f.get_roles = lambda user=None: self.roles.get(user or f.session.user, [])

        def only_for(roles):
            roles = [roles] if isinstance(roles, str) else roles
            if not set(roles).intersection(f.get_roles()):
                raise PermissionError("Not permitted")
        f.only_for = only_for
        f._dict = DD
        f.utils.get_url = lambda path=None: "https://erp.example.com" + (path or "")
        self.now = datetime.now()
        f.utils.now_datetime = lambda: self.now
        f.utils.get_datetime = lambda v: v if isinstance(v, datetime) else datetime.fromisoformat(str(v))
        f.session.data = DD(creation=self.now)
        self.tfa_users = set()
        tf = types.ModuleType("frappe.twofactor")
        tf.should_run_2fa = lambda user: user in self.tfa_users
        sys.modules["frappe.twofactor"] = tf

        for m in [m for m in sys.modules if m.startswith("passkey_authentication.passkey_authentication") and ".tests" not in m]:
            del sys.modules[m]
        from passkey_authentication.passkey_authentication import api
        self.api = api

    def tearDown(self):
        sys.modules.pop("frappe.twofactor", None)

    def as_user(self, user):
        self.frappe.session.user = user

    def register(self, auth=None):
        self.as_user(EMAIL)
        auth = auth or SoftAuthenticator()
        opts = self.api.registration_options()
        self.assertTrue(opts["success"], opts)
        res = self.api.verify_registration(credential=json.dumps(auth.create(opts["options"], ORIGIN)))
        self.assertTrue(res["success"], res)
        return auth, res

    def login(self, auth, email=EMAIL):
        self.as_user("Guest")
        opts = self.api.authentication_options(user_email=email)
        self.assertTrue(opts["success"], opts)
        return self.api.verify_authentication(credential=json.dumps(auth.get(opts["options"], ORIGIN)),
                                              session_token=opts["session_token"])

    def require_role(self, role="Accounts User", grace=14):
        self.state.settings.required_roles = [DD(role=role)]
        self.state.settings.enrollment_grace_days = grace
        for user, roles in self.roles.items():
            for r in roles:
                self.state.tables["Has Role"].append({"name": f"{user}-{r}", "parent": user, "role": r,
                                                      "parenttype": "User"})


class TestRpIdAndSetupCheck(FeatureTestCase):
    def test_rp_id_prefers_site_host_over_host_header(self):
        from passkey_authentication.passkey_authentication import security
        self.state.settings.rp_id = None
        self.frappe.local.conf.host_name = "https://erp.example.com:443"
        self.frappe.request.host = "evil.example.net"
        self.assertEqual(security.get_rp_id(self.state.settings), "erp.example.com")

    def test_rp_id_falls_back_to_site_name(self):
        from passkey_authentication.passkey_authentication import security
        self.state.settings.rp_id = None
        self.frappe.local.site = "erp.example.com"
        self.assertEqual(security.get_rp_id(self.state.settings), "erp.example.com")

    def test_fill_rp_id_on_install(self):
        from passkey_authentication.passkey_authentication import setup
        s = DD(rp_id=None)
        self.frappe.local.conf.host_name = "erp.example.com"
        self.assertTrue(setup.fill_rp_id(s))
        self.assertEqual(s.rp_id, "erp.example.com")
        self.assertFalse(setup.fill_rp_id(DD(rp_id="other.example.com")))

    def test_host_matches_rp_id(self):
        from passkey_authentication.passkey_authentication.security import host_matches_rp_id
        self.assertTrue(host_matches_rp_id("erp.example.com", "example.com"))
        self.assertTrue(host_matches_rp_id("ERP.example.com", "erp.example.com"))
        self.assertFalse(host_matches_rp_id("badexample.com", "example.com"))
        self.assertFalse(host_matches_rp_id("", "example.com"))

    def _checks(self, request_host):
        f = self.frappe
        f.db.sql = lambda *a, **k: [[1]]
        f.db.get_single_value = lambda dt, field: 0
        from passkey_authentication.passkey_authentication import diagnostics
        return {c["title"]: c for c in diagnostics.collect_checks(request_host)}

    def test_setup_check_flags_host_mismatch(self):
        checks = self._checks("erp.other.org")
        bad = [c for t, c in checks.items() if "does not match" in t]
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["status"], "error")
        self.assertEqual(checks["RP ID is set"]["status"], "ok")
        self.assertEqual(checks["Redis cache works"]["status"], "ok")

    def test_setup_check_warns_on_empty_rp_id(self):
        self.state.settings.rp_id = None
        self.frappe.local.conf.host_name = "erp.example.com"
        checks = self._checks("erp.example.com")
        self.assertEqual(checks["RP ID is empty"]["status"], "warning")

    def test_setup_check_requires_admin(self):
        from passkey_authentication.passkey_authentication import diagnostics
        self.as_user(EMAIL)
        with self.assertRaises(PermissionError):
            diagnostics.run_setup_check()


class TestAuthenticatorNames(FeatureTestCase):
    def test_known_aaguid_gets_name(self):
        _, res = self.register(SoftAuthenticator(aaguid=uuid.UUID(GOOGLE_PM).bytes))
        cred = self.state.tables["Passkey Credential"][0]
        self.assertEqual(cred["authenticator_name"], "Google Password Manager")
        self.assertEqual(res["nickname"], "Google Password Manager")
        listed = self.api.list_credentials()["credentials"][0]
        self.assertEqual(listed["authenticator_name"], "Google Password Manager")

    def test_second_passkey_from_same_provider_is_numbered(self):
        aaguid = uuid.UUID(GOOGLE_PM).bytes
        self.register(SoftAuthenticator(aaguid=aaguid))
        _, res = self.register(SoftAuthenticator(aaguid=aaguid))
        self.assertEqual(res["nickname"], "Google Password Manager 2")

    def test_zero_aaguid_falls_back(self):
        self.register()
        self.assertEqual(self.state.tables["Passkey Credential"][0]["authenticator_name"], "This device")

    def test_custom_names_override(self):
        from passkey_authentication.passkey_authentication.authenticators import authenticator_name
        aaguid = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
        self.state.settings.custom_aaguid_names = json.dumps({aaguid.upper(): "YubiKey 5"})
        self.assertEqual(authenticator_name(aaguid, "cross-platform", self.state.settings), "YubiKey 5")
        self.assertEqual(authenticator_name("11111111-1111-1111-1111-111111111111", "cross-platform",
                                            self.state.settings), "Security key")


class TestAdminTools(FeatureTestCase):
    def test_bulk_revoke_requires_admin(self):
        from passkey_authentication.passkey_authentication import admin
        self.register()
        name = self.state.tables["Passkey Credential"][0]["name"]
        self.as_user(EMAIL)
        with self.assertRaises(PermissionError):
            admin.revoke_credentials(names=json.dumps([name]))

    def test_bulk_revoke(self):
        from passkey_authentication.passkey_authentication import admin
        auth, _ = self.register()
        self.register()
        names = [c["name"] for c in self.state.tables["Passkey Credential"]]
        self.as_user(ADMIN)
        self.state.mails.clear()
        res = admin.revoke_credentials(names=json.dumps(names), reason="Laptop stolen")
        self.assertEqual(res["revoked"], 2)
        cred = self.state.tables["Passkey Credential"][0]
        self.assertEqual((cred["revoked"], cred["enabled"], cred["revoked_by"]), (1, 0, ADMIN))
        self.assertEqual(len(self.state.mails), 1)  # one email per user
        self.assertFalse(self.login(auth)["success"])
        # Revoking again does nothing.
        self.as_user(ADMIN)
        self.assertEqual(admin.revoke_credentials(names=json.dumps(names))["revoked"], 0)

    def test_revoke_all_for_user(self):
        from passkey_authentication.passkey_authentication import admin
        self.register()
        self.register()
        self.as_user(ADMIN)
        self.assertEqual(admin.revoke_user_passkeys(user=EMAIL)["revoked"], 2)
        summary = admin.user_passkey_summary(user=EMAIL)
        self.assertEqual((summary["active"], summary["total"]), (0, 2))


class TestRoleEnforcement(FeatureTestCase):
    def on_login(self, user=EMAIL):
        from passkey_authentication.passkey_authentication import session
        self.frappe.flags.passkey_login = False
        session.on_login(DD(user=user))

    def test_no_roles_means_no_enforcement(self):
        self.register()
        self.on_login()  # password fallback on, no required roles: allowed

    def test_required_role_with_passkey_blocks_password(self):
        self.require_role()
        self.register()
        with self.assertRaises(self.frappe.AuthenticationError):
            self.on_login()

    def test_required_role_without_passkey_starts_grace(self):
        from passkey_authentication.passkey_authentication.enforcement import enrollment_state
        self.require_role(grace=14)
        self.on_login()  # allowed: nobody is locked out
        user = self.state.tables["User"][0]
        self.assertEqual(user["custom_passkey_required_since"], self.now)
        state = enrollment_state(EMAIL, self.state.settings)
        self.assertEqual((state["required"], state["overdue"], state["days_left"]), (True, False, 14))
        self.now += timedelta(days=15)
        self.assertTrue(enrollment_state(EMAIL, self.state.settings)["overdue"])

    def test_other_roles_unaffected(self):
        self.require_role(role="Sales Manager")
        self.register()
        self.on_login()

    def test_administrator_exempt(self):
        from passkey_authentication.passkey_authentication.enforcement import is_required
        self.require_role(role="System Manager")
        self.roles["Administrator"] = ["System Manager"]
        self.assertFalse(is_required("Administrator", self.state.settings))
        self.assertTrue(is_required(ADMIN, self.state.settings))

    def test_status_reports_enrollment(self):
        self.require_role(grace=3)
        self.as_user(EMAIL)
        status = self.api.get_status()
        self.assertTrue(status["enrollment"]["required"])
        self.assertEqual(status["enrollment"]["days_left"], 3)

    def test_reminders(self):
        from passkey_authentication.passkey_authentication import enforcement
        self.require_role(grace=7)
        self.state.settings.send_enrollment_reminders = 1
        enforcement.send_enrollment_reminders()  # starts the grace period: 7 days left
        self.assertEqual([m["recipients"] for m in self.state.mails], [[EMAIL]])
        self.now += timedelta(days=2)  # 5 days left: no reminder
        enforcement.send_enrollment_reminders()
        self.assertEqual(len(self.state.mails), 1)


class TestTwoFactor(FeatureTestCase):
    def test_uv_passkey_counts_as_2fa(self):
        auth, _ = self.register(SoftAuthenticator(uv=True))
        self.tfa_users.add(EMAIL)
        self.assertTrue(self.login(auth)["success"])

    def test_passkey_without_uv_refused_for_2fa_user(self):
        auth, _ = self.register(SoftAuthenticator(uv=False))
        self.tfa_users.add(EMAIL)
        res = self.login(auth)
        self.assertFalse(res["success"])
        self.assertTrue(res["two_factor_required"])
        self.assertEqual(self.state.sessions, [])
        # Not counted as a failed attempt for the IP rate limit.
        self.assertFalse(any("fail" in k for k in self.frappe.cache.counters))

    def test_without_uv_fine_when_no_2fa(self):
        auth, _ = self.register(SoftAuthenticator(uv=False))
        self.assertTrue(self.login(auth)["success"])

    def test_setting_off_refuses_2fa_users(self):
        auth, _ = self.register(SoftAuthenticator(uv=True))
        self.tfa_users.add(EMAIL)
        self.state.settings.passkey_satisfies_2fa = 0
        self.assertFalse(self.login(auth)["success"])


class TestRecoveryCodes(FeatureTestCase):
    def setUp(self):
        super().setUp()
        self.state.settings.allow_recovery_codes = 1
        self.state.settings.recovery_code_count = 10

    def generate(self):
        self.as_user(EMAIL)
        res = self.api.generate_recovery_codes()
        self.assertTrue(res["success"], res)
        return res["codes"]

    def test_codes_are_hashed_and_single_use(self):
        codes = self.generate()
        self.assertEqual(len(codes), 10)
        stored = [r["code_hash"] for r in self.state.tables["Passkey Recovery Code"]]
        self.assertFalse(set(codes) & set(stored))
        self.as_user("Guest")
        res = self.api.recovery_login(user_email=EMAIL, code=codes[0].lower().replace("-", " "))
        self.assertTrue(res["success"], res)
        self.assertEqual(res["remaining"], 9)
        self.assertEqual(self.state.sessions, [EMAIL])
        self.assertFalse(self.api.recovery_login(user_email=EMAIL, code=codes[0])["success"])

    def test_wrong_code_and_wrong_user(self):
        codes = self.generate()
        self.as_user("Guest")
        self.assertFalse(self.api.recovery_login(user_email=EMAIL, code="AAAAA-AAAAA")["success"])
        self.assertFalse(self.api.recovery_login(user_email=ADMIN, code=codes[0])["success"])
        self.assertFalse(self.api.recovery_login(user_email="nobody@example.com", code=codes[0])["success"])

    def test_rate_limited_per_user(self):
        codes = self.generate()
        self.as_user("Guest")
        for _i in range(5):
            self.api.recovery_login(user_email=EMAIL, code="AAAAA-AAAAA")
        self.assertFalse(self.api.recovery_login(user_email=EMAIL, code=codes[0])["success"])

    def test_new_set_replaces_old(self):
        old = self.generate()
        new = self.generate()
        self.assertEqual(len(self.state.tables["Passkey Recovery Code"]), 10)
        self.as_user("Guest")
        self.assertFalse(self.api.recovery_login(user_email=EMAIL, code=old[0])["success"])
        self.assertTrue(self.api.recovery_login(user_email=EMAIL, code=new[0])["success"])

    def test_generate_needs_recent_login(self):
        self.frappe.session.data = DD(creation=self.now - timedelta(hours=1))
        self.as_user(EMAIL)
        res = self.api.generate_recovery_codes()
        self.assertTrue(res.get("stepup_required"))

    def test_works_in_passkey_only_mode(self):
        self.register()
        codes = self.generate()
        self.state.settings.password_fallback_enabled = 0
        self.as_user("Guest")
        self.assertTrue(self.api.recovery_login(user_email=EMAIL, code=codes[1])["success"])

    def test_disabled(self):
        self.state.settings.allow_recovery_codes = 0
        self.as_user(EMAIL)
        self.assertFalse(self.api.generate_recovery_codes()["success"])


if __name__ == "__main__":
    unittest.main()
