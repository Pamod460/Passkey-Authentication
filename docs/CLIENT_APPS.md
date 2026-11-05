# Using passkeys from other apps (Flutter, Angular, native)

`passkey_authentication` can act as the passkey sign-in service for your other apps. The app shows the
platform's own passkey prompt, the ERP verifies it, and the app gets an OAuth **Bearer token**
that works on every Frappe/ERPNext API (`Authorization: Bearer <access_token>`).

Passkeys are bound to the ERP's **RP ID** (e.g. `erp.example.com`), so a passkey a user
created on the ERP website works in the apps too (through iCloud Keychain, Google Password
Manager, etc.), and the other way round.

```
App                                  ERP (passkey_authentication)
 |-- login_options(client_id) -------->|  challenge + session_token
 |   [native passkey prompt]           |
 |-- login(credential, session_token) ->|  verifies signature, origin, sign count
 |<-- access_token + refresh_token -----|  (stored as OAuth Bearer Token)
 |-- any /api/... with Bearer token --->|
 |-- refresh(refresh_token) ----------->|  rotates both tokens
```

## 1. Server setup (once per app)

1. **OAuth Client**: in Desk, create an *OAuth Client* for the app (Integrations > OAuth Client).
   Set *Scopes* to `all` (full API access as the user) and any redirect URI (unused here).
   Use a separate OAuth Client per app, used only for this.
2. **Passkey Client App**: create one and link that OAuth Client. Fill in what applies:

   | Platform | Field | Example |
   |---|---|---|
   | Angular / Flutter web | Web Origins | `https://portal.example.com` |
   | Android | Package Name | `com.example.app` |
   | Android | SHA-256 Fingerprints | `AB:CD:...` (one per line: debug key, upload key **and** Play app-signing key) |
   | iOS | App IDs | `ABCDE12345.com.example.app` (Team ID + bundle ID) |

   The **Client ID** shown on the record is what the app sends as `client_id`.
3. The ERP now serves, from these records:
   - `https://<rp_id>/.well-known/assetlinks.json` (Android)
   - `https://<rp_id>/.well-known/apple-app-site-association` (iOS)
   - `https://<rp_id>/.well-known/webauthn` (Related Origin Requests for web apps on other domains)

   Check them in a browser. They must be served over HTTPS with no redirect. If your nginx
   or CDN intercepts `/.well-known/`, forward these three paths to Frappe.
4. **CORS** (browser apps on another origin only):
   `bench --site <site> set-config allow_cors '["https://portal.example.com"]' --parse`

Getting the Android fingerprint:
```bash
# debug key
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android | grep SHA256
# release: Play Console > Test and release > App integrity > App signing key certificate
```

## 2. API

All endpoints are `POST /api/method/passkey_authentication.passkey_authentication.client_api.<name>` with a JSON body.
Frappe wraps the result as `{"message": {...}}`; every result has `success` (true/false) and a
`message` you can show to the user.

| Endpoint | Body | Returns |
|---|---|---|
| `config` | `client_id` | `rp_id`, `rp_name`, `discoverable`, `password_allowed` |
| `login_options` | `client_id`, optional `user_email` | `options` (WebAuthn request JSON), `session_token` |
| `login` | `client_id`, `credential` (WebAuthn JSON), `session_token` | tokens + `user`, `full_name` |
| `password_login` | `client_id`, `usr`, `pwd` | tokens (refused in passkey-only mode for users who have a passkey, and for 2FA users) |
| `recovery_login` | `client_id`, `user_email`, `code` | tokens + `recovery_codes_remaining` (one-time recovery code, for users who lost every passkey) |
| `refresh` | `client_id`, `refresh_token` | new tokens (the old refresh token stops working) |
| `logout` | `client_id`, `refresh_token` | revokes that token pair |
| `me` | (Bearer) | `user`, `full_name`, `user_image`, `passkey_count` |

Token response:
```json
{"success": true, "user": "alice@example.com", "full_name": "Alice",
 "access_token": "...", "token_type": "Bearer", "expires_in": 3600,
 "refresh_token": "...", "refresh_expires_in": 2592000, "scope": "all"}
```

**Adding a passkey from an app** uses the same endpoints as the website, with the Bearer token:
1. Confirm identity: `passkey_authentication.passkey_authentication.api.confirm_password` (`password`), or
   `api.stepup_options` then `api.verify_stepup` (`credential`, `session_token`) with an existing passkey.
2. `api.registration_options` -> pass `options` to the platform's create-passkey call.
3. `api.verify_registration` with `credential`.

`login` can also fail with `two_factor_required: true`: the user must use Frappe two-factor
authentication and the passkey did not verify them (no fingerprint, face or PIN). Ask for a
passkey with user verification, or send them to the website.

A working sample app is in [examples/flutter_passkey_demo](../examples/flutter_passkey_demo).

Security notes:
- Refresh tokens rotate on every use. If an old refresh token is used again, every token of that
  user for that app is revoked (it was probably copied). Store tokens in secure storage
  (Keychain / Android Keystore via `flutter_secure_storage`; in a browser, memory or an
  HttpOnly cookie on your own backend).
- Disabling a Passkey Client App revokes all of its tokens. A disabled user can't refresh, and
  Frappe rejects their access tokens.
- Revoking a passkey does not end sessions already signed in with it. To force sign-out,
  revoke the user's rows in *OAuth Bearer Token*.

## 3. Flutter (Android + iOS)

Package: [`passkeys`](https://pub.dev/packages/passkeys) (tested against 2.23). Its request/response
types read and write the same WebAuthn JSON the ERP uses, so no field mapping is needed.

Platform setup:
- **Android**: `minSdkVersion 28` or higher. Add the app's package and signing fingerprint(s) to the Passkey Client App.
- **iOS**: in Xcode, *Signing & Capabilities > Associated Domains*: `webcredentials:erp.example.com`.
  Add `TEAMID.bundle.id` to the Passkey Client App.

```dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';

const erp = 'https://erp.example.com';
const clientId = 'YOUR_CLIENT_ID';
final _authenticator = PasskeyAuthenticator();

Future<Map<String, dynamic>> _call(String method, Map<String, dynamic> body,
    {String? accessToken}) async {
  final res = await http.post(
    Uri.parse('$erp/api/method/$method'),
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      if (accessToken != null) 'Authorization': 'Bearer $accessToken',
    },
    body: jsonEncode(body),
  );
  final data = (jsonDecode(res.body)['message'] ?? {}) as Map<String, dynamic>;
  if (data['success'] != true) throw Exception(data['message'] ?? 'Request failed');
  return data;
}

/// Sign in with a passkey. Leave [email] empty to let the user pick any passkey.
Future<Map<String, dynamic>> signInWithPasskey({String? email}) async {
  final start = await _call('passkey_authentication.passkey_authentication.client_api.login_options',
      {'client_id': clientId, if (email != null) 'user_email': email});

  final request = AuthenticateRequestType.fromJson(
      start['options'] as Map<String, dynamic>,
      mediation: MediationType.Optional);
  final response = await _authenticator.authenticate(request);

  return _call('passkey_authentication.passkey_authentication.client_api.login', {
    'client_id': clientId,
    'session_token': start['session_token'],
    'credential': response.toJson(),
  }); // -> access_token, refresh_token, user, full_name ...
}

Future<Map<String, dynamic>> refresh(String refreshToken) =>
    _call('passkey_authentication.passkey_authentication.client_api.refresh',
        {'client_id': clientId, 'refresh_token': refreshToken});

/// Add a passkey for the signed-in user (after password confirmation).
Future<void> addPasskey(String accessToken, String password) async {
  await _call('passkey_authentication.passkey_authentication.api.confirm_password', {'password': password},
      accessToken: accessToken);
  final start = await _call('passkey_authentication.passkey_authentication.api.registration_options', {},
      accessToken: accessToken);
  final request =
      RegisterRequestType.fromJson(start['options'] as Map<String, dynamic>);
  final response = await _authenticator.register(request);
  await _call('passkey_authentication.passkey_authentication.api.verify_registration',
      {'credential': response.toJson()},
      accessToken: accessToken);
}
```

Then call ERP APIs with the token, e.g.
`GET $erp/api/resource/ToDo` with `Authorization: Bearer <access_token>`, and call `refresh`
when you get a 401/403 or shortly before `expires_in` runs out.

For **Flutter web**, add the web app's origin under *Web Origins* and follow the Angular notes below.

## 4. Angular (or any browser app)

Where the Angular app is hosted matters, because browsers only allow passkeys for an RP ID that
matches the page's domain:

| Angular app is served from | What happens |
|---|---|
| The ERP itself (same host) | Works everywhere, nothing extra needed. |
| Another domain or subdomain (`portal.example.com`, `app.other.lk`) | Works through **Related Origin Requests**: the browser checks `https://<rp_id>/.well-known/webauthn`, which lists your *Web Origins*. Supported in Chrome/Edge 128+ and Safari 18+, but not every browser yet (check Firefox). At most 5 distinct site names. |
| Need every browser on a different domain | Use the redirect option in section 5. |

(Changing the RP ID to a parent domain such as `example.com` would also work for subdomains, but
it invalidates every passkey already registered, so only do that before users enroll.)

Using [`@simplewebauthn/browser`](https://simplewebauthn.dev/docs/packages/browser) v11 or later:

```ts
// passkey.service.ts
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, map } from 'rxjs';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';

const ERP = 'https://erp.example.com';
const CLIENT_ID = 'YOUR_CLIENT_ID';

@Injectable({ providedIn: 'root' })
export class PasskeyAuthService {
  private http = inject(HttpClient);

  private call<T = any>(method: string, body: object, accessToken?: string): Promise<T> {
    const headers: Record<string, string> = accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
    return firstValueFrom(
      this.http.post<{ message: any }>(`${ERP}/api/method/${method}`, body, { headers }).pipe(
        map((r) => {
          if (!r.message?.success) throw new Error(r.message?.message ?? 'Request failed');
          return r.message as T;
        }),
      ),
    );
  }

  async signIn(email?: string) {
    const start = await this.call('passkey_authentication.passkey_authentication.client_api.login_options',
      { client_id: CLIENT_ID, user_email: email });
    const credential = await startAuthentication({ optionsJSON: start.options });
    return this.call('passkey_authentication.passkey_authentication.client_api.login',
      { client_id: CLIENT_ID, session_token: start.session_token, credential });
  }

  refresh(refreshToken: string) {
    return this.call('passkey_authentication.passkey_authentication.client_api.refresh',
      { client_id: CLIENT_ID, refresh_token: refreshToken });
  }

  logout(refreshToken: string) {
    return this.call('passkey_authentication.passkey_authentication.client_api.logout',
      { client_id: CLIENT_ID, refresh_token: refreshToken });
  }

  async addPasskey(accessToken: string, password: string) {
    await this.call('passkey_authentication.passkey_authentication.api.confirm_password', { password }, accessToken);
    const start = await this.call('passkey_authentication.passkey_authentication.api.registration_options', {}, accessToken);
    const credential = await startRegistration({ optionsJSON: start.options });
    return this.call('passkey_authentication.passkey_authentication.api.verify_registration', { credential }, accessToken);
  }
}
```

Add an `HttpInterceptor` that sets `Authorization: Bearer <access_token>` on ERP requests and
calls `refresh` once on a 401/403.

## 5. Alternative: redirect to the ERP login (works in every browser)

Frappe is already an OAuth 2 provider. A web app on any domain can send users to
`https://erp.example.com/api/method/frappe.integrations.oauth2.authorize` (Authorization Code
with PKCE, using the OAuth Client from step 1). The user signs in on the ERP login page with
**Sign in with Passkey**, and the app exchanges the code at
`frappe.integrations.oauth2.get_token`. Libraries such as `angular-oauth2-oidc` or
`flutter_appauth` handle this. The passkey prompt then runs on the ERP's own domain, so no
association files or related origins are needed. The trade-off is a browser redirect instead
of an in-app prompt.

## 6. Troubleshooting

- **"Passkey authentication failed" only from the app**: the origin isn't registered. On Android
  the origin is `android:apk-key-hash:<base64url of the signing cert SHA-256>`; check that the
  fingerprint of the key that signed *this* build (debug vs Play signing) is listed.
- **Android: "no credentials available" / RP ID errors**: open
  `https://<rp_id>/.well-known/assetlinks.json` and confirm it lists your package, and that the
  site has a valid certificate. Google caches this file, so allow a few minutes after changes.
- **iOS: "application is not associated with domain"**: check the Associated Domains entry and
  `/.well-known/apple-app-site-association`. Apple fetches it through its CDN, which can take a while.
  For development builds, `webcredentials:erp.example.com?mode=developer` skips the CDN.
- **Angular on another domain: "The RP ID is invalid for this domain"**: the browser doesn't support
  Related Origin Requests, or the origin isn't in *Web Origins*. Use section 5.
- **`stepup_required` when adding a passkey**: call `confirm_password` (or `stepup_options` /
  `verify_stepup`) first. The confirmation lasts 5 minutes.
