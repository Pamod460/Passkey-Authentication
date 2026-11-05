// Sample app for passkey_authentication. Set the two constants below, then see README.md.
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'erp_client.dart';

const erpUrl = 'https://erp.example.com'; // your site, must match the RP ID
const clientId = 'YOUR_OAUTH_CLIENT_ID'; // OAuth Client linked to the Passkey Client App

void main() => runApp(const DemoApp());

class DemoApp extends StatelessWidget {
  const DemoApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Passkey demo',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        home: const HomePage(),
      );
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final client = ErpClient(baseUrl: erpUrl, clientId: clientId);
  final storage = const FlutterSecureStorage();
  final email = TextEditingController();
  final secret = TextEditingController();
  Session? session;
  List<dynamic> passkeys = [];
  bool busy = false;

  @override
  void initState() {
    super.initState();
    _restore();
  }

  Future<void> _restore() async {
    final refresh = await storage.read(key: 'refresh_token');
    final user = await storage.read(key: 'user');
    if (refresh == null || user == null) return;
    await _run(() async {
      _setSession(await client.refresh(Session('', refresh, user, user)));
    });
  }

  Future<void> _setSession(Session? s) async {
    session = s;
    if (s == null) {
      await storage.deleteAll();
      passkeys = [];
    } else {
      await storage.write(key: 'refresh_token', value: s.refreshToken);
      await storage.write(key: 'user', value: s.user);
      passkeys = await client.listPasskeys(s);
    }
    if (mounted) setState(() {});
  }

  Future<void> _run(Future<void> Function() action) async {
    setState(() => busy = true);
    try {
      await action();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  void _toast(String text) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  @override
  Widget build(BuildContext context) {
    final s = session;
    return Scaffold(
      appBar: AppBar(title: const Text('Passkey demo')),
      body: AbsorbPointer(
        absorbing: busy,
        child: ListView(padding: const EdgeInsets.all(16), children: [
          if (busy) const LinearProgressIndicator(),
          if (s == null) ..._signedOut() else ..._signedIn(s),
        ]),
      ),
    );
  }

  List<Widget> _signedOut() => [
        FilledButton.icon(
          icon: const Icon(Icons.key),
          label: const Text('Sign in with a passkey'),
          onPressed: () => _run(() async =>
              _setSession(await client.signInWithPasskey(email: email.text.trim()))),
        ),
        const SizedBox(height: 24),
        TextField(
            controller: email,
            keyboardType: TextInputType.emailAddress,
            decoration: const InputDecoration(labelText: 'Email (optional for passkeys)')),
        TextField(
            controller: secret,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password or recovery code')),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(
            child: OutlinedButton(
              child: const Text('Password'),
              onPressed: () => _run(() async => _setSession(
                  await client.signInWithPassword(email.text.trim(), secret.text))),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: OutlinedButton(
              child: const Text('Recovery code'),
              onPressed: () => _run(() async => _setSession(
                  await client.signInWithRecoveryCode(email.text.trim(), secret.text))),
            ),
          ),
        ]),
      ];

  List<Widget> _signedIn(Session s) => [
        ListTile(
          leading: const Icon(Icons.person),
          title: Text(s.fullName),
          subtitle: Text(s.user),
        ),
        FilledButton.icon(
          icon: const Icon(Icons.add),
          label: const Text('Add a passkey on this phone'),
          onPressed: () => _run(() async {
            final name = await client.addPasskey(s, password: secret.text);
            _toast('Added $name');
            await _setSession(s);
          }),
        ),
        const SizedBox(height: 16),
        Text('Your passkeys', style: Theme.of(context).textTheme.titleMedium),
        for (final p in passkeys)
          ListTile(
            leading: const Icon(Icons.key),
            title: Text('${p['nickname'] ?? 'Passkey'}'),
            subtitle: Text('${p['authenticator_name'] ?? ''}'),
          ),
        const SizedBox(height: 16),
        OutlinedButton(
          child: const Text('Sign out'),
          onPressed: () => _run(() async {
            await client.logout(s);
            await _setSession(null);
          }),
        ),
      ];
}
