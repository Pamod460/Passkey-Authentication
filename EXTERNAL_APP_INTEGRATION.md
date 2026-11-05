# External App Integration Guide

> **For Flutter, Angular or native apps, use the token API in [docs/CLIENT_APPS.md](docs/CLIENT_APPS.md).**
> It registers each app as a *Passkey Client App* and returns OAuth Bearer tokens. This page describes the
> lower-level browser-session endpoints.

How to authenticate users in Flutter, React Native, or any external app
using the `passkey_authentication` WebAuthn/Passkey API for ERPNext.

## Base URL

All endpoints use the standard Frappe API path:

```
https://<your-site>/api/method/passkey_authentication.passkey_authentication.api.<method>
```

Responses are JSON. Send `Content-Type: application/json` for request bodies.

---

## Quick Start (Flutter)

### 1. Check if passkeys are enabled

```http
GET /api/method/passkey_authentication.passkey_authentication.api.get_status
```

**Response:**
```json
{
  "message": {
    "success": true,
    "enabled": true,
    "passkey_count": 0,
    "password_allowed": true
  }
}
```

### 2. Get authentication options

**Discoverable flow** (no email needed — user picks from device passkeys):

```http
POST /api/method/passkey_authentication.passkey_authentication.api.authentication_options
Content-Type: application/json

{
  "user_email": ""
}
```

**Non-discoverable flow** (know the user's email):

```http
POST /api/method/passkey_authentication.passkey_authentication.api.authentication_options
Content-Type: application/json

{
  "user_email": "user@example.com"
}
```

**Response:**
```json
{
  "message": {
    "success": true,
    "options": {
      "rpId": "erp-test.cmb.ac.lk",
      "challenge": "a1b2c3d4...",
      "timeout": 120000,
      "userVerification": "preferred"
    },
    "session_token": "xYz123..."
  }
}
```

Save `session_token` (next to `options`). It is required for verify and works once. The `options` fields map directly to the WebAuthn `PublicKeyCredentialRequestOptions`.

### 3. Call the platform WebAuthn API

Decode `challenge` from base64url to bytes, then call the native WebAuthn API.

**Flutter sketch** (for a complete, working version with the `passkeys` package, see [docs/CLIENT_APPS.md](docs/CLIENT_APPS.md)):

```dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:passkeys/authenticator.dart';

Future<PasskeyAssertion?> getPasskeyAssertion(Map<String, dynamic> options) async {
  // Decode challenge from base64url
  final challenge = base64Url.decode(options['challenge']);

  final assertionOptions = PublicKeyCredentialRequestOptions(
    challenge: Uint8List.fromList(challenge),
    rpId: options['rpId'],
    timeout: Duration(milliseconds: options['timeout']),
    userVerification: options['userVerification'],
  );

  final credential = await navigator.credentials.get(assertionOptions);
  return credential;
}
```

**Flutter example using `flutter_webauthn` package:**

```dart
import 'package:flutter_webauthn/flutter_webauthn.dart';

// Convert options to platform format and call WebAuthn API
final assertion = await WebAuthnPlatform.instance.login(
  publicKey: PublicKeyCredentialRequestOptions(
    challenge: base64Url.decode(options['challenge']),
    rpId: options['rpId'],
    allowCredentials: [], // empty for discoverable
    userVerification: UserVerificationRequirement.preferred,
  ),
);
```

**Flutter example using `fido2` package:**

```dart
import 'package:fido2/fido2.dart';

final result = await Fido2.getAssertion(
  challenge: base64Url.decode(options['challenge']),
  rpId: options['rpId'],
  timeout: Duration(milliseconds: options['timeout']),
);
```

### 4. Send the assertion back to verify

Encode the raw assertion fields to base64url, then POST:

```http
POST /api/method/passkey_authentication.passkey_authentication.api.verify_authentication
Content-Type: application/json

{
  "credential": {
    "id": "abc123...",
    "rawId": "abc123...",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url...",
      "authenticatorData": "base64url...",
      "signature": "base64url...",
      "userHandle": "base64url..."
    }
  },
  "session_token": "xYz123..."
}
```

**Success response:**
```json
{
  "message": {
    "success": true,
    "message": "Authentication successful.",
    "user": "user@example.com",
    "full_name": "John Doe"
  }
}
```

### 5. Use the session

The response sets an `sid` cookie. For subsequent authenticated API calls,
include this cookie in your HTTP requests:

```dart
final response = await http.get(
  Uri.parse('https://erp-test.cmb.ac.lk/api/method/frappe.client.get_count'),
  headers: {
    'Cookie': 'sid=$sessionCookie',
  },
);
```

---

## Complete Flutter Example

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

class FrappePasskeyAuth {
  final String baseUrl;
  String? _sessionCookie;

  FrappePasskeyAuth(this.baseUrl);

  /// Step 1: Get passkey status
  Future<Map<String, dynamic>> getStatus() async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/method/passkey_authentication.passkey_authentication.api.get_status'),
    );
    return json.decode(response.body)['message'];
  }

  /// Step 2: Get authentication options
  Future<Map<String, dynamic>> getAuthOptions({String? userEmail}) async {
    final response = await http.post(
      Uri.parse('$baseUrl/api/method/passkey_authentication.passkey_authentication.api.authentication_options'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'user_email': userEmail ?? ''}),
    );
    return json.decode(response.body)['message'];
  }

  /// Step 3+4: Get assertion from native WebAuthn and verify
  Future<Map<String, dynamic>> authenticate({
    required Map<String, dynamic> credential,
    String? sessionToken,
  }) async {
    final body = <String, dynamic>{
      'credential': json.encode(credential), // send as JSON string
      if (sessionToken != null) 'session_token': sessionToken,
    };

    final response = await http.post(
      Uri.parse('$baseUrl/api/method/passkey_authentication.passkey_authentication.api.verify_authentication'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    );

    // Capture session cookie
    final setCookie = response.headers['set-cookie'];
    if (setCookie != null) {
      final match = RegExp(r'sid=([^;]+)').firstMatch(setCookie);
      if (match != null) _sessionCookie = match.group(1);
    }

    return json.decode(response.body)['message'];
  }

  /// Use session for authenticated requests
  Future<Map<String, dynamic>> authenticatedGet(String method) async {
    final response = await http.get(
      Uri.parse('$baseUrl/api/method/$method'),
      headers: {'Cookie': 'sid=$_sessionCookie'},
    );
    return json.decode(response.body);
  }
}
```

---

## Passkey Registration (for external apps)

Registration requires an **existing session** (user must be logged in first).

### 1. Get registration options

```http
POST /api/method/passkey_authentication.passkey_authentication.api.registration_options
Cookie: sid=<session-cookie>
```

**Response:**
```json
{
  "message": {
    "success": true,
    "options": {
      "rp": {"name": "ERPNext", "id": "erp-test.cmb.ac.lk"},
      "user": {"id": "base64url-handle", "name": "user@example.com", "displayName": "John Doe"},
      "challenge": "base64url-challenge",
      "pubKeyCredParams": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257}
      ],
      "timeout": 120000,
      "attestation": "none",
      "authenticatorSelection": {
        "residentKey": "preferred",
        "userVerification": "preferred"
      }
    }
  }
}
```

### 2. Create credential via native WebAuthn

Pass the options to `navigator.credentials.create()` equivalent on the platform.

### 3. Verify and store the credential

```http
POST /api/method/passkey_authentication.passkey_authentication.api.verify_registration
Cookie: sid=<session-cookie>
Content-Type: application/json

{
  "credential": {
    "id": "...",
    "rawId": "...",
    "type": "public-key",
    "attestationObject": "base64url...",
    "clientDataJSON": "base64url..."
  }
}
```

---

## API Reference

### Guest-accessible endpoints (no login required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `get_status` | Check if passkeys are enabled |
| POST | `authentication_options` | Get WebAuthn challenge for login |
| POST | `verify_authentication` | Verify passkey assertion and create session |

### Authenticated endpoints (require `sid` cookie)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `registration_options` | Get WebAuthn options for new passkey |
| POST | `verify_registration` | Verify and store new passkey |
| POST | `list_credentials` | List user's registered passkeys |
| POST | `rename_credential` | Rename a passkey |
| POST | `revoke_credential` | Disable a passkey |
| POST | `delete_credential` | Permanently delete a passkey |

### Field formats

All `challenge`, `rawId`, `clientDataJSON`, `authenticatorData`, `signature`,
`userHandle`, and `attestationObject` fields use **base64url encoding without
padding** (`-` and `_` instead of `+` and `/`, no `=` padding).

---

## Important Notes

1. **RP ID**: Must match the domain. If your ERPNext is at `erp-test.cmb.ac.lk`,
   the RP ID is `erp-test.cmb.ac.lk`. For Flutter desktop apps, the RP ID
   must match the domain the app is served from (for web) or the configured
   relying party (for native).

2. **Origin validation**: The server validates that the WebAuthn origin matches
   the configured RP ID. If using a different origin (e.g., a Flutter web app
   at a different domain), add the origin to `Passkey Settings > Allowed Origins`.

3. **Discoverable credentials**: Enabled by default. When enabled, users can
   log in without entering their email first — the device presents saved passkeys.

4. **Session cookies**: After successful authentication, the `sid` cookie is
   set in the response. Store it and send it on subsequent requests. The cookie
   is `HttpOnly` and `Secure`.

5. **CSRF tokens**: For POST requests that modify data (not authentication),
   Frappe requires a CSRF token. After login, extract it from:
   ```json
   {"message": {"csrf_token": "..."}}
   ```
   Or read the `sid` cookie value — the CSRF token is the session SID itself.

---

## Error responses

All endpoints return errors in this format:

```json
{
  "message": {
    "success": false,
    "message": "Human-readable error description"
  }
}
```

Common errors:

| Error | Cause |
|-------|-------|
| `Passkey authentication is disabled.` | Admin disabled passkeys in Settings |
| `Authentication challenge expired.` | Challenge older than timeout (default 120s) |
| `Passkey authentication failed.` | Invalid signature or wrong credential |
| `User account is disabled.` | ERPNext user account is disabled |
| `Too many attempts.` | Rate limit hit (per IP) |
