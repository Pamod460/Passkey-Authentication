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

Then open **Passkey Settings** and set **RP ID** (e.g. `erp.example.com`). Users add passkeys at `/app/passkey-settings`
and sign in from the login page ("Sign in with Passkey", or browser autofill when conditional UI is enabled).

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

## Tests

```bash
python -m unittest passkey_authentication.passkey_authentication.tests.test_core passkey_authentication.passkey_authentication.tests.test_flow \
    passkey_authentication.passkey_authentication.tests.test_client_api
```
`test_flow` simulates registration and login with a software authenticator against a stubbed `frappe`;
it needs `webauthn` and `cryptography` but no bench.
