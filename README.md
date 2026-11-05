# passkey_authentication

WebAuthn/Passkey authentication for Frappe Framework / ERPNext 16.

## Install

```bash
bench get-app https://github.com/Pamod460/Passkey-Authentication
bench --site <site> install-app passkey_authentication
bench --site <site> migrate
bench build --app passkey_authentication
bench restart
```

On install, **RP ID** is filled from the site's host name. Open **Passkey Settings**, check it
(e.g. `erp.example.com`), and click **Run Setup Check**: it tests the RP ID against the site URL and
the address you opened, HTTPS, allowed origins, Redis, outgoing email, the scheduler, two-factor
settings and client apps. From a terminal:
`bench --site <site> execute passkey_authentication.passkey_authentication.diagnostics.print_report`.

Users add passkeys at `/app/my-passkeys` and sign in from the login page ("Sign in with Passkey",
or browser autofill when conditional UI is enabled).

## Features

- Passwordless login with biometrics, PIN, or security key; several passkeys per user
- Discoverable credentials (usernameless login) and conditional UI / autofill
- Server-side enforcement of user verification when set to *required*
- Challenges are single-use, short-lived and bound to a per-attempt session token
- Sign-count regression (possible cloned authenticator) is rejected and logged
- Rate limiting on failed verifications per IP (successful logins never count, so shared campus/office IPs
  are not locked out), plus a loose flood limit on login options; audit log with configurable retention
- Adding a passkey requires a recent login (last 5 minutes) or re-confirming identity with an existing passkey
  or the password, and the user is emailed whenever a passkey is added
- Users can always revoke or delete their own passkeys, including the last one (a lost key must be revocable)
- Optional "passkey only" mode: with *Allow Password Login* off, users who own an active passkey
  cannot sign in with a password (Administrator is exempt) — revoking their last passkey re-enables password login, so nobody is locked out

- Passkeys are named after their provider or device model (Google Password Manager, iCloud Keychain,
  Windows Hello, 1Password...) from the AAGUID; admins can add names in *Extra Authenticator Names*
- **Require passkeys by role** (*Passkey Enforcement*): users with those roles who have a passkey can't use a
  password; users without one get a grace period (default 14 days), reminder emails, and then a desk
  dialog they can't dismiss until they add one
- **Two-factor**: for users who must use Frappe 2FA, a passkey login with user verification
  (fingerprint, face or PIN) counts as two factors and skips the OTP; one without it is refused
- **Recovery codes**: users create one-time codes on their Passkeys page and can use one on the login
  page ("Lost your passkey?") to get back in and add a new passkey; codes are stored hashed and the user
  is emailed when one is used
- **Admin tools**: bulk *Revoke* in the Passkey Credential list, *Passkeys* buttons on the User form
  (view, revoke all, delete recovery codes), and the *Passkey Enrollment* report (who is enrolled,
  in their grace period or overdue)

## Notes

- Origins: if *Allowed Origins* is empty, the origin is derived from RP ID (and the request port for localhost).
  Set it explicitly (JSON array) when serving from several hostnames.
- Behind nginx, the right-most `X-Forwarded-For` / `X-Real-IP` is trusted only when the direct peer is a private/loopback address.

- Conditional UI (autofill) re-requests a fresh challenge shortly before *Challenge Timeout* expires,
  so a login page left open for a while keeps working.
- After login, `redirect-to` is followed only when it resolves to the same origin.

## Other apps (Flutter, Angular, native)

Register each app as a **Passkey Client App** (web origin, Android package + signing fingerprint,
or iOS Team ID + bundle ID, linked to an OAuth Client). Apps then sign users in with the platform
passkey prompt through `passkey_authentication.passkey_authentication.client_api` and receive OAuth Bearer tokens that work
on every Frappe API. The site serves `/.well-known/assetlinks.json`, `apple-app-site-association`
and `webauthn` from those records. Setup and Flutter / Angular code: [docs/CLIENT_APPS.md](docs/CLIENT_APPS.md).

## Translations

All user-facing strings go through `_()` / `__()`. To start a translation, run
`bench generate-pot-file --app passkey_authentication`, then create
`passkey_authentication/locale/<lang>.po` from the template (e.g. with Poedit) and send a pull request.

## Smoke test against a real site

```bash
pip install "webauthn>=2.5,<3" cbor2 cryptography
python scripts/smoke_test.py https://erp.example.com                      # public checks only
python scripts/smoke_test.py https://erp.example.com --user test@example.com --password '...'
```

With a test account it registers a passkey with a software authenticator, signs in with it, and deletes
it again. Use an account that may sign in with a password and has no two-factor authentication.

## Tests

```bash
python -m unittest passkey_authentication.passkey_authentication.tests.test_core passkey_authentication.passkey_authentication.tests.test_flow \
    passkey_authentication.passkey_authentication.tests.test_client_api \
    passkey_authentication.passkey_authentication.tests.test_features
```
The tests simulate registration and login with a software authenticator against a stubbed `frappe`;
they need `webauthn`, `cbor2` and `cryptography` but no bench. GitHub Actions runs them on every push
and pull request (`.github/workflows/ci.yml`), plus pyflakes, a JavaScript syntax check and a JSON check.
