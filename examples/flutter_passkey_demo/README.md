# Flutter passkey demo

A small Android/iOS app that signs in to a Frappe/ERPNext site running
`passkey_authentication`: passkey login, first login with a password, recovery-code login,
adding a passkey on the phone, listing passkeys, token refresh and sign-out.

> Not yet run on a real device. Please report what you find.

## 1. Server

1. Create an **OAuth Client** on the site and copy its *Client ID*.
2. Create a **Passkey Client App** linked to it, with
   - Android: package `com.example.flutter_passkey_demo` (or yours) and the SHA-256 fingerprint
     of your signing key (`keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android`);
   - iOS: `TEAMID.com.example.flutterPasskeyDemo`.
3. Run **Passkey Settings > Run Setup Check** and fix any errors.
4. Check that `https://<site>/.well-known/assetlinks.json` and `/.well-known/apple-app-site-association`
   list your app.

## 2. App

```bash
cd examples/flutter_passkey_demo
flutter create --platforms=android,ios --org com.example .   # generates the platform folders
flutter pub get
```

Edit `erpUrl` and `clientId` at the top of `lib/main.dart`.

- **Android**: in `android/app/build.gradle` set `minSdk = 28` (Credential Manager). Use a device or
  emulator with a Google account and a screen lock.
- **iOS**: in Xcode, *Runner > Signing & Capabilities*, pick your team and add *Associated Domains*
  `webcredentials:<your site host>` (append `?mode=developer` while developing).
  iOS 16+ only.

```bash
flutter run
```

See [docs/CLIENT_APPS.md](../../docs/CLIENT_APPS.md) for the API and troubleshooting.
