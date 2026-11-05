// Talks to passkey_authentication's client API on a Frappe/ERPNext site.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';

const _clientApi = 'passkey_authentication.passkey_authentication.client_api';
const _api = 'passkey_authentication.passkey_authentication.api';

class ErpException implements Exception {
  ErpException(this.message, [this.data = const {}]);
  final String message;
  final Map<String, dynamic> data;
  @override
  String toString() => message;
}

class Session {
  Session(this.accessToken, this.refreshToken, this.user, this.fullName);
  factory Session.fromJson(Map<String, dynamic> j) => Session(
      j['access_token'] as String,
      j['refresh_token'] as String,
      j['user'] as String,
      (j['full_name'] ?? j['user']) as String);
  final String accessToken;
  final String refreshToken;
  final String user;
  final String fullName;
}

class ErpClient {
  ErpClient({required this.baseUrl, required this.clientId});

  final String baseUrl;
  final String clientId;
  final _authenticator = PasskeyAuthenticator();

  Future<Map<String, dynamic>> _call(String method, Map<String, dynamic> body,
      {String? accessToken}) async {
    final res = await http.post(
      Uri.parse('$baseUrl/api/method/$method'),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        if (accessToken != null) 'Authorization': 'Bearer $accessToken',
      },
      body: jsonEncode(body),
    );
    Map<String, dynamic> data;
    try {
      data = (jsonDecode(res.body)['message'] ?? {}) as Map<String, dynamic>;
    } catch (_) {
      throw ErpException('HTTP ${res.statusCode} from $method');
    }
    if (data['success'] != true) {
      throw ErpException((data['message'] ?? 'Request failed') as String, data);
    }
    return data;
  }

  /// RP ID, whether passkeys and passwords are allowed, app name.
  Future<Map<String, dynamic>> config() =>
      _call('$_clientApi.config', {'client_id': clientId});

  /// Sign in with a passkey. Leave [email] empty to let the user pick any passkey.
  Future<Session> signInWithPasskey({String? email}) async {
    final start = await _call('$_clientApi.login_options', {
      'client_id': clientId,
      if (email != null && email.isNotEmpty) 'user_email': email,
    });
    final request = AuthenticateRequestType.fromJson(
        start['options'] as Map<String, dynamic>,
        mediation: MediationType.Optional);
    final response = await _authenticator.authenticate(request);
    final out = await _call('$_clientApi.login', {
      'client_id': clientId,
      'session_token': start['session_token'],
      'credential': response.toJson(),
    });
    return Session.fromJson(out);
  }

  /// First sign-in for users who have no passkey yet.
  Future<Session> signInWithPassword(String email, String password) async =>
      Session.fromJson(await _call('$_clientApi.password_login',
          {'client_id': clientId, 'usr': email, 'pwd': password}));

  /// The user lost every passkey: sign in once with a recovery code.
  Future<Session> signInWithRecoveryCode(String email, String code) async =>
      Session.fromJson(await _call('$_clientApi.recovery_login',
          {'client_id': clientId, 'user_email': email, 'code': code}));

  Future<Session> refresh(Session s) async => Session.fromJson(await _call(
      '$_clientApi.refresh',
      {'client_id': clientId, 'refresh_token': s.refreshToken}));

  Future<void> logout(Session s) => _call('$_clientApi.logout',
      {'client_id': clientId, 'refresh_token': s.refreshToken});

  Future<Map<String, dynamic>> me(Session s) =>
      _call('$_clientApi.me', {}, accessToken: s.accessToken);

  Future<List<dynamic>> listPasskeys(Session s) async =>
      (await _call('$_api.list_credentials', {}, accessToken: s.accessToken))[
          'credentials'] as List<dynamic>;

  /// Add a passkey for the signed-in user. A token from a sign-in in the last
  /// five minutes is enough; otherwise pass [password] to confirm it's them.
  Future<String> addPasskey(Session s, {String? password}) async {
    if (password != null && password.isNotEmpty) {
      await _call('$_api.confirm_password', {'password': password},
          accessToken: s.accessToken);
    }
    final start = await _call('$_api.registration_options', {},
        accessToken: s.accessToken);
    final request =
        RegisterRequestType.fromJson(start['options'] as Map<String, dynamic>);
    final response = await _authenticator.register(request);
    final out = await _call('$_api.verify_registration',
        {'credential': response.toJson()},
        accessToken: s.accessToken);
    return (out['nickname'] ?? 'Passkey') as String;
  }
}
