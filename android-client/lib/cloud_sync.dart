import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'main.dart' show Api, kRomsRoot;

// On-device save sync. Mirrors tools/thorsync.js: same mappings, same
// conservative 3-way rules, same server endpoints — but the file access runs
// through Shizuku, because Android 13 blocks apps from other apps'
// Android/data folders where the emulators keep their saves.

const _channel = MethodChannel('romstore/shizuku');
const _tmpDir = '$kRomsRoot/.romstore/tmp';
const _stateFile = '$kRomsRoot/.romstore/syncstate-device.json';

const _mappings = [
  (thor: '/sdcard/Android/data/org.dolphinemu.dolphinemu/files/Wii/title', server: 'dolphin/Wii/title'),
  (thor: '/sdcard/Android/data/org.dolphinemu.dolphinemu/files/GC', server: 'dolphin/GC'),
  (thor: '/sdcard/Android/data/me.magnum.melondualds/files/saves', server: 'melonds/saves'),
];
const _edenLocalBase = '/sdcard/Android/data/com.miHoYo.Yuanshen/files/nand/user/save/0000000000000000';
const _edenServerBase = 'eden/saves/0000000000000000';

class Shizuku {
  static Future<bool> ping() async => await _channel.invokeMethod('ping') == true;
  static Future<bool> ensurePermission() async {
    if (await _channel.invokeMethod('hasPermission') == true) return true;
    return await _channel.invokeMethod('requestPermission') == true;
  }

  static Future<String> run(String cmd) async {
    final r = Map<String, dynamic>.from(await _channel.invokeMethod('exec', {'cmd': cmd}));
    if (r['code'] != 0 && (r['out'] as String).isEmpty) {
      throw Exception('shell(${r['code']}): ${r['err']}');
    }
    return r['out'] as String;
  }
}

String _shq(String p) => "'${p.replaceAll("'", "'\\''")}'";

class LocalFile {
  final String fullPath, rel;
  final int size, mtimeMs;
  LocalFile(this.fullPath, this.rel, this.size, this.mtimeMs);
}

class SyncEngine {
  final Api api;
  final void Function(String) log;
  SyncEngine(this.api, this.log);

  Map<String, dynamic> state = {};
  final conflicts = <String>[];
  int uploaded = 0, downloaded = 0;

  Future<List<LocalFile>> _listLocal(String base) async {
    String out;
    try {
      out = await Shizuku.run(
          "find ${_shq(base)} -type f -exec stat -c '%s|%Y|%n' {} + 2>/dev/null");
    } catch (_) {
      return [];
    }
    final files = <LocalFile>[];
    for (final line in out.split('\n')) {
      final i1 = line.indexOf('|'), i2 = line.indexOf('|', i1 + 1);
      if (i1 < 1 || i2 < 0) continue;
      final size = int.tryParse(line.substring(0, i1));
      final mtime = int.tryParse(line.substring(i1 + 1, i2));
      final full = line.substring(i2 + 1);
      if (size == null || mtime == null || full.length <= base.length) continue;
      files.add(LocalFile(full, full.substring(base.length + 1), size, mtime * 1000));
    }
    return files;
  }

  Future<void> _download(Map s, String thorPath) async {
    final bytes = await api.downloadSaveBytes(s['relPath']);
    final tmp = File('$_tmpDir/dl.bin');
    tmp.parent.createSync(recursive: true);
    tmp.writeAsBytesSync(bytes);
    final dir = thorPath.substring(0, thorPath.lastIndexOf('/'));
    await Shizuku.run('mkdir -p ${_shq(dir)} && cp ${_shq(tmp.path)} ${_shq(thorPath)}');
    final st = (await Shizuku.run("stat -c '%s|%Y' ${_shq(thorPath)}")).trim().split('|');
    state[s['relPath']] = {
      'thorMtimeMs': int.parse(st[1]) * 1000,
      'thorSize': int.parse(st[0]),
      'serverHash': s['hash'],
    };
    tmp.deleteSync();
    downloaded++;
  }

  Future<void> _upload(LocalFile f, String serverRel, {String? alsoTo}) async {
    final tmp = '$_tmpDir/ul.bin';
    await Shizuku.run('mkdir -p ${_shq(_tmpDir)} && cp ${_shq(f.fullPath)} ${_shq(tmp)}');
    final bytes = File(tmp).readAsBytesSync();
    final resp = await api.uploadSaveBytes(serverRel, bytes);
    if (alsoTo != null) await api.uploadSaveBytes(alsoTo, bytes);
    state[serverRel] = {
      'thorMtimeMs': f.mtimeMs,
      'thorSize': f.size,
      'serverHash': resp['hash'],
    };
    File(tmp).deleteSync();
    uploaded++;
  }

  // The same decision table as the desktop agent.
  Future<void> _syncPair({
    required List<LocalFile> local,
    required List<Map> server,
    required String localBase,
    required String serverPrefix,
    String? prefer,
    String Function(String rel)? alsoUploadTo,
  }) async {
    final byRel = <String, Map<String, dynamic>>{};
    for (final f in local) {
      byRel[f.rel] = {'local': f};
    }
    for (final s in server) {
      final rel = (s['relPath'] as String).substring(serverPrefix.length + 1);
      (byRel[rel] ??= {})['server'] = s;
    }
    for (final e in byRel.entries) {
      final LocalFile? l = e.value['local'];
      final Map? s = e.value['server'];
      final serverRel = '$serverPrefix/${e.key}';
      final thorPath = '$localBase/${e.key}';
      final rec = state[serverRel];

      Future<void> up() async {
        log('⬆ $serverRel');
        await _upload(l!, serverRel, alsoTo: alsoUploadTo?.call(e.key));
      }

      Future<void> down() async {
        log('⬇ $serverRel');
        await _download(s!, thorPath);
      }

      if (l != null && s == null) { await up(); continue; }
      if (l == null && s != null) { await down(); continue; }
      if (l == null || s == null) continue;

      final localChanged = rec == null || rec['thorMtimeMs'] != l.mtimeMs || rec['thorSize'] != l.size;
      final serverChanged = rec == null || rec['serverHash'] != s['hash'];
      if (rec == null) {
        final serverMs = DateTime.parse(s['mtime']).millisecondsSinceEpoch;
        if (l.size == s['sizeBytes'] && (l.mtimeMs - serverMs).abs() < 2000) {
          state[serverRel] = {'thorMtimeMs': l.mtimeMs, 'thorSize': l.size, 'serverHash': s['hash']};
        } else if ((prefer ?? (l.mtimeMs > serverMs ? 'thor' : 'server')) == 'thor') {
          await up();
        } else {
          await down();
        }
        continue;
      }
      if (localChanged && serverChanged) {
        if (prefer == 'thor') { await up(); }
        else if (prefer == 'server') { await down(); }
        else { conflicts.add(serverRel); log('! conflict: $serverRel'); }
        continue;
      }
      if (localChanged) { await up(); continue; }
      if (serverChanged) { await down(); continue; }
    }
  }

  Future<String> run({String? prefer}) async {
    if (!await Shizuku.ping()) {
      throw Exception('Shizuku is not running. Open the Shizuku app and start it, then retry.');
    }
    if (!await Shizuku.ensurePermission()) {
      throw Exception('Shizuku permission denied.');
    }
    try {
      state = jsonDecode(File(_stateFile).readAsStringSync());
    } catch (_) {
      state = {};
    }
    conflicts.clear();
    uploaded = 0;
    downloaded = 0;

    final saves = await api.saves();

    for (final m in _mappings) {
      await _syncPair(
        local: await _listLocal(m.thor),
        server: saves.where((s) => (s['relPath'] as String).startsWith('${m.server}/')).toList(),
        localBase: m.thor,
        serverPrefix: m.server,
        prefer: prefer,
      );
    }

    // Eden profile UUID differs per device; join on title id.
    final uuids = (await Shizuku.run('ls ${_shq(_edenLocalBase)} 2>/dev/null'))
        .split('\n')
        .map((s) => s.trim())
        .where((s) => RegExp(r'^[0-9A-Fa-f]{32}$').hasMatch(s) && !RegExp(r'^0+$').hasMatch(s))
        .toList();
    final localUuid = uuids.isEmpty ? null : uuids.first;
    if (localUuid != null) {
      // Bridge: PC Ryujinx slots <-> local Eden titles, joined on title id.
      final slotByTitle = <String, Map<String, dynamic>>{};
      for (final s in saves) {
        final m = RegExp(r'^ryujinx/saves/([0-9a-f]{16})/([01])/(.+)$', caseSensitive: false)
            .firstMatch(s['relPath']);
        final title = (s['switchTitleId'] as String?)?.toUpperCase();
        if (m == null || title == null) continue;
        final info = slotByTitle[title] ??= {'slot': m.group(1), 'gens': <String, List<Map>>{}};
        ((info['gens'] as Map)[m.group(2)!] ??= <Map>[]).add(s);
      }
      for (final entry in slotByTitle.entries) {
        final gens = (entry.value['gens'] as Map).entries.toList()
          ..sort((a, b) {
            int newest(List l) => l
                .map((f) => DateTime.parse(f['mtime']).millisecondsSinceEpoch)
                .reduce((x, y) => x > y ? x : y);
            return newest(b.value) - newest(a.value);
          });
        if (gens.isEmpty) continue;
        final gen = gens.first.key, files = List<Map>.from(gens.first.value);
        final slot = entry.value['slot'];
        final other = gen == '0' ? '1' : '0';
        await _syncPair(
          local: await _listLocal('$_edenLocalBase/$localUuid/${entry.key}'),
          server: files,
          localBase: '$_edenLocalBase/$localUuid/${entry.key}',
          serverPrefix: 'ryujinx/saves/$slot/$gen',
          prefer: prefer,
          alsoUploadTo: (rel) => 'ryujinx/saves/$slot/$other/$rel',
        );
      }

      // Plain Eden tree.
      final localEden = await _listLocal('$_edenLocalBase/$localUuid');
      final serverEden = saves.where((s) => (s['relPath'] as String).startsWith('$_edenServerBase/')).toList();
      final titleToUuid = <String, String>{};
      for (final s in serverEden) {
        final parts = (s['relPath'] as String).split('/');
        if (parts.length >= 5 && RegExp(r'^[0-9A-Fa-f]{32}$').hasMatch(parts[3])) {
          titleToUuid[parts[4].toUpperCase()] = parts[3];
        }
      }
      final titles = <String>{
        ...localEden.map((f) => f.rel.split('/').first.toUpperCase()),
        ...titleToUuid.keys,
      };
      for (final title in titles) {
        final serverUuid = titleToUuid[title] ?? localUuid;
        final prefix = '$_edenServerBase/$serverUuid/$title';
        await _syncPair(
          local: localEden
              .where((f) => f.rel.toUpperCase().startsWith('$title/'))
              .map((f) => LocalFile(f.fullPath, f.rel.split('/').skip(1).join('/'), f.size, f.mtimeMs))
              .toList(),
          server: serverEden
              .where((s) => (s['relPath'] as String).toUpperCase().startsWith('${prefix.toUpperCase()}/'))
              .toList(),
          localBase: '$_edenLocalBase/$localUuid/$title',
          serverPrefix: prefix,
          prefer: prefer,
        );
      }
    }

    File(_stateFile).parent.createSync(recursive: true);
    File(_stateFile).writeAsStringSync(jsonEncode(state));
    return 'Done: $uploaded uploaded, $downloaded downloaded'
        '${conflicts.isEmpty ? '' : ', ${conflicts.length} conflicts'}';
  }
}

class SyncScreen extends StatefulWidget {
  final Api api;
  const SyncScreen({super.key, required this.api});
  @override
  State<SyncScreen> createState() => _SyncScreenState();
}

class _SyncScreenState extends State<SyncScreen> {
  final lines = <String>[];
  bool busy = false;
  bool hasConflicts = false;

  Future<void> _run({String? prefer}) async {
    setState(() {
      busy = true;
      lines.clear();
      hasConflicts = false;
    });
    final engine = SyncEngine(widget.api, (m) => setState(() => lines.add(m)));
    try {
      final summary = await engine.run(prefer: prefer);
      setState(() {
        lines.add(summary);
        hasConflicts = engine.conflicts.isNotEmpty;
      });
    } catch (e) {
      setState(() => lines.add('Error: $e'));
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Cloud Sync')),
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(children: [
            FilledButton.icon(
              onPressed: busy ? null : () => _run(),
              icon: const Icon(Icons.sync),
              label: const Text('Sync now'),
            ),
            const SizedBox(width: 12),
            if (hasConflicts) ...[
              OutlinedButton(
                  onPressed: busy ? null : () => _run(prefer: 'thor'),
                  child: const Text('Keep device')),
              const SizedBox(width: 8),
              OutlinedButton(
                  onPressed: busy ? null : () => _run(prefer: 'server'),
                  child: const Text('Keep server')),
            ],
            if (busy)
              const Padding(
                padding: EdgeInsets.only(left: 12),
                child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
              ),
          ]),
        ),
        const Divider(height: 1),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.all(12),
            itemCount: lines.length,
            itemBuilder: (c, i) => Text(lines[i],
                style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
          ),
        ),
      ]),
    );
  }
}
