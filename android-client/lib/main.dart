import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

// RomStore Android client — talks to the RomStore server and installs ROMs
// directly into the on-device emulator tree at /storage/emulated/0/ROMs.

const kRomsRoot = '/storage/emulated/0/ROMs';
const kConfigDir = '$kRomsRoot/.romstore';
const kConfigFile = '$kConfigDir/config.json';

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

  Map<String, String> get authHeaders =>
      config.cookie.isEmpty ? {} : {'cookie': config.cookie};

  // Streams the ROM to its place in the on-device tree, reporting progress 0..1.
  Future<void> download(Game g, void Function(double) onProgress) async {
    final res =
        await _send('GET', '/api/download', query: {'type': 'roms', 'path': g.relPath});
    if (res.statusCode != 200) {
      await res.drain();
      throw Exception('download: HTTP ${res.statusCode}');
    }
    final total = res.contentLength;
    final target = File('$kRomsRoot/${g.relPath}');
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
  final String? artworkPath;
  final bool isDlc;

  Game(this.name, this.originalName, this.system, this.systemName, this.relPath,
      this.size, this.artworkPath, this.isDlc);

  factory Game.fromJson(Map<String, dynamic> j) => Game(
        j['name'] ?? '?',
        j['originalName'] ?? '',
        j['system'] ?? '?',
        j['systemName'] ?? j['system'] ?? '?',
        j['relPath'] ?? '',
        j['size'] ?? '',
        j['artworkPath'],
        j['isDlc'] == true,
      );

  bool get installed => File('$kRomsRoot/$relPath').existsSync();
}

class RomStoreApp extends StatelessWidget {
  const RomStoreApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RomStore',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xFFE8590C), brightness: Brightness.dark),
        useMaterial3: true,
      ),
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
    return LibraryScreen(
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

class LibraryScreen extends StatefulWidget {
  final Api api;
  final VoidCallback onLogout;
  const LibraryScreen({super.key, required this.api, required this.onLogout});

  @override
  State<LibraryScreen> createState() => _LibraryScreenState();
}

class _LibraryScreenState extends State<LibraryScreen> {
  List<Game>? all;
  String? error;
  String systemFilter = 'all';
  String search = '';
  final Map<String, double> progress = {}; // relPath -> 0..1
  final Set<String> installing = {};

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      error = null;
      all = null;
    });
    try {
      final games = await widget.api.games();
      games.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
      setState(() => all = games);
    } catch (e) {
      setState(() => error = '$e');
    }
  }

  List<String> get systems {
    final s = (all ?? []).map((g) => g.system).toSet().toList()..sort();
    return s;
  }

  List<Game> get visible {
    var v = all ?? [];
    if (systemFilter != 'all') v = v.where((g) => g.system == systemFilter).toList();
    if (search.isNotEmpty) {
      final q = search.toLowerCase();
      v = v.where((g) => g.name.toLowerCase().contains(q)).toList();
    }
    return v;
  }

  Future<void> _install(Game g) async {
    setState(() {
      installing.add(g.relPath);
      progress[g.relPath] = 0;
    });
    try {
      await widget.api.download(g, (p) {
        if (mounted) setState(() => progress[g.relPath] = p);
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('${g.name} installed to ROMs/${g.system}')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed: $e')));
      }
    } finally {
      if (mounted) {
        setState(() {
          installing.remove(g.relPath);
          progress.remove(g.relPath);
        });
      }
    }
  }

  Future<void> _confirmDelete(Game g) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Remove from device?'),
        content: Text('${g.name}\n\nDeletes the local copy only; the server keeps it.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Delete')),
        ],
      ),
    );
    if (yes == true) {
      File('$kRomsRoot/${g.relPath}').deleteSync();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('RomStore'),
        actions: [
          IconButton(onPressed: _refresh, icon: const Icon(Icons.refresh)),
          IconButton(onPressed: widget.onLogout, icon: const Icon(Icons.logout)),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(64),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Row(
              children: [
                DropdownMenu<String>(
                  initialSelection: systemFilter,
                  onSelected: (v) => setState(() => systemFilter = v ?? 'all'),
                  dropdownMenuEntries: [
                    const DropdownMenuEntry(value: 'all', label: 'All systems'),
                    ...systems.map((s) => DropdownMenuEntry(value: s, label: s)),
                  ],
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: TextField(
                    onChanged: (v) => setState(() => search = v),
                    decoration: const InputDecoration(
                      prefixIcon: Icon(Icons.search),
                      hintText: 'Search',
                      isDense: true,
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
      body: error != null
          ? Center(
              child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text(error!),
              const SizedBox(height: 8),
              FilledButton(onPressed: _refresh, child: const Text('Retry')),
            ]))
          : all == null
              ? const Center(child: CircularProgressIndicator())
              : GridView.builder(
                  padding: const EdgeInsets.all(12),
                  gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
                    maxCrossAxisExtent: 220,
                    childAspectRatio: 0.62,
                    crossAxisSpacing: 12,
                    mainAxisSpacing: 12,
                  ),
                  itemCount: visible.length,
                  itemBuilder: (c, i) => _card(visible[i]),
                ),
    );
  }

  Widget _card(Game g) {
    final installed = g.installed;
    final busy = installing.contains(g.relPath);
    final p = progress[g.relPath];
    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: busy
            ? null
            : installed
                ? () => _confirmDelete(g)
                : () => _install(g),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(
              child: g.artworkPath != null
                  ? Image.network(
                      widget.api.artworkUrl(g.artworkPath!),
                      headers: widget.api.authHeaders,
                      fit: BoxFit.cover,
                      errorBuilder: (c, e, s) => _placeholder(),
                    )
                  : _placeholder(),
            ),
            Padding(
              padding: const EdgeInsets.all(8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(g.name,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Text('${g.system} · ${g.size}',
                      style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: 6),
                  if (busy)
                    LinearProgressIndicator(value: p)
                  else if (installed)
                    Row(children: [
                      Icon(Icons.check_circle,
                          size: 16, color: Theme.of(context).colorScheme.primary),
                      const SizedBox(width: 4),
                      const Text('Installed', style: TextStyle(fontSize: 12)),
                    ])
                  else
                    Row(children: const [
                      Icon(Icons.download, size: 16),
                      SizedBox(width: 4),
                      Text('Install', style: TextStyle(fontSize: 12)),
                    ]),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _placeholder() => Container(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        child: const Center(child: Icon(Icons.videogame_asset, size: 48)),
      );
}
