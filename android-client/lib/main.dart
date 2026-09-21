import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'switch_addons.dart' show Addon;
import 'ui/store_screen.dart';
import 'ui/theme.dart';

// RomStore Android client — talks to the RomStore server and installs ROMs
// directly into the on-device emulator tree at /storage/emulated/0/ROMs.

const kRomsRoot = '/storage/emulated/0/ROMs';
const kConfigDir = '$kRomsRoot/.romstore';
const kConfigFile = '$kConfigDir/config.json';
// Games installed or removed since Cocoon last rescanned. Kept on disk so
// closing the app does not lose track of what still has to reach the library.
const kPendingFile = '$kConfigDir/cocoon-pending.json';

// Carries romstore://shop?platform=nds in from the launcher tile.
const kLinkChannel = MethodChannel('romstore/link');

String? platformFromLink(String? link) {
  if (link == null || link.isEmpty) return null;
  final uri = Uri.tryParse(link);
  if (uri == null || uri.scheme != 'romstore') return null;
  final p = uri.queryParameters['platform'] ?? uri.queryParameters['system'];
  return (p == null || p.isEmpty) ? null : p.toLowerCase();
}

void main() {
  runApp(const RomStoreApp());
}

class AppConfig {
  String serverUrl;
  String username;
  String cookie; // session cookie, e.g. connect.sid=...

  AppConfig({this.serverUrl = 'http://192.168.2.70:1567', this.username = '', this.cookie = ''});

  static AppConfig load() {
    try {
      final f = File(kConfigFile);
      if (f.existsSync()) {
        final j = jsonDecode(f.readAsStringSync());
        return AppConfig(
          serverUrl: j['serverUrl'] ?? 'http://192.168.2.70:1567',
          username: j['username'] ?? '',
          cookie: j['cookie'] ?? '',
        );
      }
    } catch (_) {}
    return AppConfig();
  }

  void save() {
    Directory(kConfigDir).createSync(recursive: true);
    File(kConfigFile).writeAsStringSync(jsonEncode({
      'serverUrl': serverUrl,
      'username': username,
      'cookie': cookie,
    }));
  }
}

class Api {
  final AppConfig config;
  final HttpClient _client = HttpClient()..connectionTimeout = const Duration(seconds: 10);

  Api(this.config);

  Uri _uri(String path, [Map<String, String>? query]) =>
      Uri.parse(config.serverUrl).replace(path: path, queryParameters: query);

  Future<HttpClientResponse> _send(String method, String path,
      {Map<String, String>? query, Object? body}) async {
    final req = await _client.openUrl(method, _uri(path, query));
    if (config.cookie.isNotEmpty) req.headers.set('cookie', config.cookie);
    if (body != null) {
      req.headers.contentType = ContentType.json;
      req.add(utf8.encode(jsonEncode(body)));
    }
    return req.close();
  }

  Future<bool> login(String username, String password) async {
    final res = await _send('POST', '/api/auth/login',
        body: {'username': username, 'password': password});
    if (res.statusCode != 200) return false;
    final setCookies = res.headers['set-cookie'];
    if (setCookies != null && setCookies.isNotEmpty) {
      config.cookie = setCookies.map((c) => c.split(';').first).join('; ');
    }
    config.username = username;
    config.save();
    await res.drain();
    return true;
  }

  Future<bool> checkSession() async {
    if (config.cookie.isEmpty) return false;
    try {
      final res = await _send('GET', '/api/games');
      final ok = res.statusCode == 200;
      await res.drain();
      return ok;
    } catch (_) {
      return false;
    }
  }

  Future<List<Game>> games() async {
    final res = await _send('GET', '/api/games');
    if (res.statusCode != 200) throw Exception('games: HTTP ${res.statusCode}');
    final data = jsonDecode(await res.transform(utf8.decoder).join());
    return (data as List).map((j) => Game.fromJson(j)).toList();
  }

  String artworkUrl(String artworkPath) =>
      _uri('/api/artwork', {'path': artworkPath}).toString();

  // Same image the grid shows, as bytes, so it can be written into the ES-DE
  // media folder Cocoon reads.
  Future<List<int>> artworkBytes(String artworkPath) async {
    final res = await _send('GET', '/api/artwork', query: {'path': artworkPath});
    if (res.statusCode != 200) {
      await res.drain();
      throw Exception('artwork $artworkPath: HTTP ${res.statusCode}');
    }
    final bytes = <int>[];
    await for (final c in res) {
      bytes.addAll(c);
    }
    return bytes;
  }

  Map<String, String> get authHeaders =>
      config.cookie.isEmpty ? {} : {'cookie': config.cookie};

  Future<List<Map>> saves() async {
    final res = await _send('GET', '/api/saves');
    if (res.statusCode != 200) throw Exception('saves: HTTP ${res.statusCode}');
    final data = jsonDecode(await res.transform(utf8.decoder).join());
    return (data as List).cast<Map>();
  }

  Future<List<int>> downloadSaveBytes(String relPath) async {
    final res = await _send('GET', '/api/download', query: {'type': 'saves', 'path': relPath});
    if (res.statusCode != 200) {
      await res.drain();
      throw Exception('save download $relPath: HTTP ${res.statusCode}');
    }
    final chunks = <int>[];
    await for (final c in res) {
      chunks.addAll(c);
    }
    return chunks;
  }

  Future<Map> uploadSaveBytes(String relPath, List<int> bytes) async {
    const boundary = '----romstore-sync-boundary';
    final name = relPath.split('/').last;
    final head = utf8.encode('--$boundary\r\n'
        'Content-Disposition: form-data; name="relPath"\r\n\r\n$relPath\r\n'
        '--$boundary\r\n'
        'Content-Disposition: form-data; name="file"; filename="$name"\r\n'
        'Content-Type: application/octet-stream\r\n\r\n');
    final tail = utf8.encode('\r\n--$boundary--\r\n');
    final req = await _client.openUrl('POST', _uri('/api/saves/upload'));
    if (config.cookie.isNotEmpty) req.headers.set('cookie', config.cookie);
    req.headers.set('content-type', 'multipart/form-data; boundary=$boundary');
    req.contentLength = head.length + bytes.length + tail.length;
    req.add(head);
    req.add(bytes);
    req.add(tail);
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) throw Exception('save upload $relPath: HTTP ${res.statusCode} $body');
    return jsonDecode(body);
  }

  // The URL the background download service fetches. It carries the session
  // cookie separately, so nothing secret ends up in the job description.
  String downloadUrl(String relPath, {String type = 'roms'}) =>
      _uri('/api/download', {'type': type, 'path': relPath}).toString();

  // Streams the ROM to its place in the on-device tree, reporting progress 0..1.
  // Still used for add-on files, which are installed inline while the app is
  // open rather than queued.
  Future<void> download(Game g, void Function(double) onProgress) =>
      downloadRelPath(g.relPath, onProgress);

  Future<void> downloadRelPath(String relPath, void Function(double) onProgress) async {
    final res =
        await _send('GET', '/api/download', query: {'type': 'roms', 'path': relPath});
    if (res.statusCode != 200) {
      await res.drain();
      throw Exception('download: HTTP ${res.statusCode}');
    }
    final total = res.contentLength;
    final target = File('$kRomsRoot/$relPath');
    target.parent.createSync(recursive: true);
    final tmp = File('${target.path}.part');
    final sink = tmp.openWrite();
    var received = 0;
    try {
      await for (final chunk in res) {
        sink.add(chunk);
        received += chunk.length;
        if (total > 0) onProgress(received / total);
      }
      await sink.close();
      if (target.existsSync()) target.deleteSync();
      tmp.renameSync(target.path);
    } catch (e) {
      await sink.close();
      if (tmp.existsSync()) tmp.deleteSync();
      rethrow;
    }
  }
}

class Game {
  final String name;
  final String originalName;
  final String system;
  final String systemName;
  final String relPath;
  final String size;
  final int? sizeBytes; // exact length, so a download can show a real percentage
  final String? artworkPath;
  final bool isDlc;
  // Scraped on the server, republished to Cocoon through ES-DE so the device
  // never has to scrape anything itself.
  final String description;
  final int? releaseDate; // epoch seconds, as IGDB reports it
  // Switch only: the newest update plus every DLC the server holds for this
  // base game, in install order. Empty for everything else.
  final List<Addon> addons;

  Game(this.name, this.originalName, this.system, this.systemName, this.relPath,
      this.size, this.artworkPath, this.isDlc,
      {this.sizeBytes,
      this.description = '',
      this.releaseDate,
      this.addons = const []});

  factory Game.fromJson(Map<String, dynamic> j) => Game(
        j['name'] ?? '?',
        j['originalName'] ?? '',
        j['system'] ?? '?',
        j['systemName'] ?? j['system'] ?? '?',
        j['relPath'] ?? '',
        j['size'] ?? '',
        j['artworkPath'],
        j['isDlc'] == true,
        sizeBytes: j['sizeBytes'] is int ? j['sizeBytes'] : null,
        description: j['description'] ?? '',
        releaseDate: j['releaseDate'] is int ? j['releaseDate'] : null,
        addons: (j['addons'] is List)
            ? (j['addons'] as List).whereType<Map>().map(Addon.fromJson).toList()
            : const [],
      );

  bool get installed => File('$kRomsRoot/$relPath').existsSync();
  bool get hasAddons => addons.isNotEmpty;
}

class RomStoreApp extends StatelessWidget {
  const RomStoreApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RomStore',
      debugShowCheckedModeBanner: false,
      theme: buildRomStoreTheme(),
      home: const RootScreen(),
    );
  }
}

class RootScreen extends StatefulWidget {
  const RootScreen({super.key});
  @override
  State<RootScreen> createState() => _RootScreenState();
}

class _RootScreenState extends State<RootScreen> {
  late AppConfig config;
  late Api api;
  bool? loggedIn;
  String? storageError;

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    try {
      Directory(kConfigDir).createSync(recursive: true);
    } catch (e) {
      setState(() => storageError =
          'Cannot write to $kRomsRoot.\nGrant "All files access" to RomStore in Android Settings > Apps > RomStore > Permissions, then restart the app.');
      return;
    }
    config = AppConfig.load();
    api = Api(config);
    final ok = await api.checkSession();
    setState(() => loggedIn = ok);
  }

  @override
  Widget build(BuildContext context) {
    if (storageError != null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Text(storageError!, textAlign: TextAlign.center),
          ),
        ),
      );
    }
    if (loggedIn == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (!loggedIn!) {
      return LoginScreen(
          config: config, api: api, onLoggedIn: () => setState(() => loggedIn = true));
    }
    return StoreScreen(
        api: api,
        onLogout: () {
          config.cookie = '';
          config.save();
          setState(() => loggedIn = false);
        });
  }
}

class LoginScreen extends StatefulWidget {
  final AppConfig config;
  final Api api;
  final VoidCallback onLoggedIn;
  const LoginScreen(
      {super.key, required this.config, required this.api, required this.onLoggedIn});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  late final TextEditingController serverCtl;
  late final TextEditingController userCtl;
  final passCtl = TextEditingController();
  String? error;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    serverCtl = TextEditingController(text: widget.config.serverUrl);
    userCtl = TextEditingController(text: widget.config.username);
  }

  Future<void> _login() async {
    setState(() {
      busy = true;
      error = null;
    });
    widget.config.serverUrl = serverCtl.text.trim();
    try {
      final ok = await widget.api.login(userCtl.text.trim(), passCtl.text);
      if (ok) {
        widget.onLoggedIn();
      } else {
        setState(() => error = 'Invalid credentials');
      }
    } catch (e) {
      setState(() => error = 'Cannot reach server: $e');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.videogame_asset, size: 64),
                const SizedBox(height: 8),
                Text('RomStore',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 24),
                TextField(
                    controller: serverCtl,
                    decoration: const InputDecoration(
                        labelText: 'Server URL', border: OutlineInputBorder())),
                const SizedBox(height: 12),
                TextField(
                    controller: userCtl,
                    decoration: const InputDecoration(
                        labelText: 'Username', border: OutlineInputBorder())),
                const SizedBox(height: 12),
                TextField(
                    controller: passCtl,
                    obscureText: true,
                    onSubmitted: (_) => _login(),
                    decoration: const InputDecoration(
                        labelText: 'Password', border: OutlineInputBorder())),
                const SizedBox(height: 16),
                if (error != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Text(error!,
                        textAlign: TextAlign.center,
                        style: TextStyle(color: Theme.of(context).colorScheme.error)),
                  ),
                FilledButton(
                  onPressed: busy ? null : _login,
                  child: busy
                      ? const SizedBox(
                          width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Log in'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

