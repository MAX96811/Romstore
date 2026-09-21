import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'cloud_sync.dart';
import 'cocoon_refresh.dart';
import 'esde_export.dart';
import 'switch_addons.dart';

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

  // Streams the ROM to its place in the on-device tree, reporting progress 0..1.
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
      {this.description = '', this.releaseDate, this.addons = const []});

  factory Game.fromJson(Map<String, dynamic> j) => Game(
        j['name'] ?? '?',
        j['originalName'] ?? '',
        j['system'] ?? '?',
        j['systemName'] ?? j['system'] ?? '?',
        j['relPath'] ?? '',
        j['size'] ?? '',
        j['artworkPath'],
        j['isDlc'] == true,
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
  final Map<String, String> addonStatus = {}; // relPath -> what is happening
  bool syncingAddons = false;
  // Games installed or removed since Cocoon last rescanned. Cocoon only adds
  // and drops tiles during a scan, so this is what the "Send to Cocoon" badge
  // counts.
  final Set<String> pendingForCocoon = {};
  String? cocoonStatus;

  late final EsdeExport esde =
      EsdeExport(widget.api, log: (m) => debugPrint('[esde] $m'));

  @override
  void initState() {
    super.initState();
    _loadPending();
    _refresh();
    _listenForShopLinks();
  }

  void _loadPending() {
    try {
      final f = File(kPendingFile);
      if (!f.existsSync()) return;
      final saved = jsonDecode(f.readAsStringSync());
      if (saved is List) pendingForCocoon.addAll(saved.whereType<String>());
    } catch (_) {}
  }

  void _markPending(String relPath) {
    pendingForCocoon.add(relPath);
    _savePending();
  }

  void _savePending() {
    try {
      Directory(kConfigDir).createSync(recursive: true);
      File(kPendingFile).writeAsStringSync(jsonEncode(pendingForCocoon.toList()));
    } catch (_) {}
  }

  // A per-system shop tile in the launcher opens straight into that system.
  Future<void> _listenForShopLinks() async {
    kLinkChannel.setMethodCallHandler((call) async {
      if (call.method == 'link') {
        _openPlatform(platformFromLink(call.arguments as String?));
      }
    });
    try {
      _openPlatform(platformFromLink(
          await kLinkChannel.invokeMethod<String>('consumeInitialLink')));
    } catch (_) {
      // Plain launch, or a host activity without the channel: show everything.
    }
  }

  void _openPlatform(String? platform) {
    if (platform == null || !mounted) return;
    setState(() {
      systemFilter = systemForEsdePlatform(platform);
      search = '';
    });
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
      // Publish the server's title, description and box art as ES-DE data
      // straight away: the next Cocoon refresh then produces a finished tile
      // instead of a filename, with nothing scraped on the device.
      try {
        await esde.publish(g);
        if (mounted) setState(() => _markPending(g.relPath));
      } catch (e) {
        debugPrint('[esde] ${g.name}: $e');
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('${g.name} installed to ROMs/${g.system}')));
      }
      // A freshly installed Switch game gets its update and DLC right away,
      // so the first launch is already on the newest version.
      if (g.hasAddons) await _installAddons(g);
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

  void _setAddonStatus(Game g, String? text) {
    if (!mounted) return;
    setState(() {
      if (text == null) {
        addonStatus.remove(g.relPath);
      } else {
        addonStatus[g.relPath] = text;
      }
    });
  }

  // Downloads every missing update/DLC file for a base game into ROMs/switch
  // and registers it in each Eden NAND on the device. Idempotent: files that
  // are already present, with the right size, are skipped.
  Future<void> _installAddons(Game g) async {
    if (!g.hasAddons) return;
    final installer = EdenContentInstaller((m) => debugPrint('[addons] $m'));
    try {
      if (!await Shizuku.ping()) {
        throw Exception('Shizuku is not running: open it and start it, then use "Updates & DLC".');
      }
      if (!await Shizuku.ensurePermission()) throw Exception('Shizuku permission denied.');
      final edenDirs = await installer.findEdenDirs();
      if (edenDirs.isEmpty) throw Exception('No Eden NAND found on this device.');
      var i = 0;
      var written = 0;
      var stopped = false;
      for (final a in g.addons) {
        i++;
        final target = File('$kRomsRoot/${a.relPath}');
        final present = target.existsSync() &&
            (a.sizeBytes == null || target.lengthSync() == a.sizeBytes);
        if (!present) {
          _setAddonStatus(g, 'Downloading ${a.label} $i/${g.addons.length}…');
          await widget.api.downloadRelPath(a.relPath, (p) {
            _setAddonStatus(g, 'Downloading ${a.label} $i/${g.addons.length} ${(p * 100).round()}%');
          });
        }
        _setAddonStatus(g, 'Installing ${a.label} $i/${g.addons.length} into Eden…');
        if (!stopped) {
          // Eden only reads its registered cache at startup and would keep a
          // stale index, so it is closed before the first write.
          await installer.stopEden();
          stopped = true;
        }
        written += await installer.installNsp(target.path, edenDirs: edenDirs);
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Text(written == 0
                ? '${g.name}: updates and DLC already installed.'
                : '${g.name}: ${g.addons.length} add-on file(s) installed into Eden.')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Updates/DLC for ${g.name}: $e')));
      }
    } finally {
      _setAddonStatus(g, null);
    }
  }

  // App-bar action: bring every installed Switch game up to date in one go.
  Future<void> _syncAllAddons() async {
    if (syncingAddons) return;
    final targets = (all ?? []).where((g) => g.installed && g.hasAddons).toList();
    if (targets.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No installed Switch game has updates or DLC on the server.')));
      return;
    }
    setState(() => syncingAddons = true);
    try {
      for (final g in targets) {
        await _installAddons(g);
      }
    } finally {
      if (mounted) setState(() => syncingAddons = false);
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
      // Leave no metadata behind for a file that is gone; the tile itself
      // disappears on the next rescan, which reports it as removed.
      try {
        esde.withdraw(g);
      } catch (e) {
        debugPrint('[esde] withdraw ${g.name}: $e');
      }
      setState(() => _markPending(g.relPath));
    }
  }

  // One button for the whole hand-off: publish metadata for everything
  // RomStore has installed since the last run, then drive Cocoon's Rescan
  // Games and restart it, so the new tiles come up already carrying their
  // title and artwork.
  //
  // Only games this app touched are published. Republishing the whole library
  // would hand Cocoon our metadata for games it already scraped, which is the
  // user's call, not ours -- that is what the backfill action is for.
  Future<void> _sendToCocoon() async {
    if (cocoonStatus != null) return;
    setState(() => cocoonStatus = 'Writing metadata…');
    try {
      final byPath = {for (final g in all ?? <Game>[]) g.relPath: g};
      final waiting = pendingForCocoon
          .map((p) => byPath[p])
          .whereType<Game>()
          .where((g) => g.installed)
          .toList();

      var done = 0;
      for (final g in waiting) {
        try {
          await esde.publish(g, force: true);
        } catch (e) {
          debugPrint('[esde] ${g.name}: $e');
        }
        done++;
        if (mounted) {
          setState(() => cocoonStatus = 'Writing metadata $done/${waiting.length}…');
        }
      }

      await _runCocoonRefresh();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Cocoon refresh: $e')));
      }
    } finally {
      if (mounted) setState(() => cocoonStatus = null);
    }
  }

  Future<void> _runCocoonRefresh() async {
    final refresher = CocoonRefresh(log: (m) {
      if (mounted) setState(() => cocoonStatus = m);
    });
    final result = await refresher.refresh();
    if (!mounted) return;
    if (result.scanRan) {
      setState(() {
        pendingForCocoon.clear();
        _savePending();
      });
    }
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(result.message)));
  }

  // Hands Cocoon RomStore's metadata for every installed game, not just the
  // ones it downloaded. Worth it for a library Cocoon has not scraped well —
  // and destructive if it has, so it asks first.
  Future<void> _backfillCocoon() async {
    if (cocoonStatus != null) return;
    final installed =
        (all ?? []).where((g) => g.installed && !g.isDlc).length;
    final yes = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Publish all metadata?'),
        content: Text(
            'Writes RomStore\'s title, description and box art for all $installed installed '
            'games into the ES-DE library.\n\nIf Cocoon is set to prioritise ES-DE, this '
            'replaces artwork and titles it scraped itself.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Publish')),
        ],
      ),
    );
    if (yes != true) return;

    setState(() => cocoonStatus = 'Writing metadata…');
    try {
      await esde.publishAll(all ?? [], onProgress: (done, total) {
        if (mounted) setState(() => cocoonStatus = 'Writing metadata $done/$total…');
      });
      await _runCocoonRefresh();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Backfill: $e')));
      }
    } finally {
      if (mounted) setState(() => cocoonStatus = null);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(cocoonStatus ?? 'RomStore',
            style: cocoonStatus == null ? null : const TextStyle(fontSize: 16)),
        actions: [
          IconButton(
            tooltip: pendingForCocoon.isEmpty
                ? 'Send to Cocoon'
                : 'Send to Cocoon (${pendingForCocoon.length} waiting)',
            onPressed: cocoonStatus != null ? null : _sendToCocoon,
            icon: cocoonStatus != null
                ? const SizedBox(
                    width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : Badge(
                    isLabelVisible: pendingForCocoon.isNotEmpty,
                    label: Text('${pendingForCocoon.length}'),
                    child: const Icon(Icons.grid_view),
                  ),
          ),
          IconButton(
            tooltip: 'Cloud Sync',
            onPressed: () => Navigator.push(context,
                MaterialPageRoute(builder: (c) => SyncScreen(api: widget.api))),
            icon: const Icon(Icons.cloud_sync),
          ),
          IconButton(
            tooltip: 'Updates & DLC',
            onPressed: syncingAddons ? null : _syncAllAddons,
            icon: syncingAddons
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.system_update),
          ),
          IconButton(onPressed: _refresh, icon: const Icon(Icons.refresh)),
          IconButton(onPressed: widget.onLogout, icon: const Icon(Icons.logout)),
          PopupMenuButton<String>(
            enabled: cocoonStatus == null,
            onSelected: (v) {
              if (v == 'backfill') _backfillCocoon();
            },
            itemBuilder: (c) => const [
              PopupMenuItem(
                value: 'backfill',
                child: Text('Publish all metadata to Cocoon…'),
              ),
            ],
          ),
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
    final addonText = addonStatus[g.relPath];
    final busy = installing.contains(g.relPath) || addonText != null;
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
                  Text(
                      g.hasAddons
                          ? '${g.system} · ${g.size} · ${g.addons.length} add-on${g.addons.length == 1 ? '' : 's'}'
                          : '${g.system} · ${g.size}',
                      style: Theme.of(context).textTheme.bodySmall),
                  const SizedBox(height: 6),
                  if (addonText != null)
                    Text(addonText, maxLines: 1, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 11))
                  else if (busy)
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
