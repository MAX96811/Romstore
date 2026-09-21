import 'dart:io';

import 'main.dart' show Api, Game;

// Publishes what the server already knows about a game — title, description,
// release date, box art — as an ES-DE library on the device.
//
// This is how a downloaded game arrives in Cocoon already dressed. Cocoon's
// ES-DE Integration links this folder and, with "Automatic startup sync" on,
// re-reads it every time it starts: our title replaces the filename and our
// cover becomes the tile. Nothing is ever scraped on the device.
//
// The one rule this cannot break: ES-DE data only *enriches* games Cocoon has
// already scanned. Writing here does not add a game to the library -- that is
// what CocoonRefresh's rescan is for, and it has to run first.

const kEsdeRoot = '/storage/emulated/0/ES-DE';

// Cocoon identifies a platform by its folder name. Two of ours differ from the
// ids on its compatibility list; everything else matches on both sides.
const _platformAliases = {
  'gamecube': 'gc',
  'megadrive': 'genesis',
};

String esdePlatformFor(String system) {
  final s = system.toLowerCase();
  return _platformAliases[s] ?? s;
}

// The other direction, for a shop link that arrives carrying Cocoon's id.
String systemForEsdePlatform(String platform) {
  final p = platform.toLowerCase();
  for (final e in _platformAliases.entries) {
    if (e.value == p) return e.key;
  }
  return p;
}

String _xml(String s) => s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    // Control characters are not legal in XML 1.0 and some scraped summaries
    // carry stray ones; they would make Cocoon skip the whole file.
    .replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F]'), '');

String _baseName(String fileName) {
  final dot = fileName.lastIndexOf('.');
  return dot <= 0 ? fileName : fileName.substring(0, dot);
}

// ES-DE writes dates as YYYYMMDDT000000. The server hands us IGDB's release
// date in epoch seconds.
String? _esdeDate(int? epochSeconds) {
  if (epochSeconds == null || epochSeconds <= 0) return null;
  final d = DateTime.fromMillisecondsSinceEpoch(epochSeconds * 1000, isUtc: true);
  final mm = d.month.toString().padLeft(2, '0');
  final dd = d.day.toString().padLeft(2, '0');
  return '${d.year}$mm${dd}T000000';
}

class EsdeExport {
  final Api api;
  final void Function(String)? log;
  // Overridden by tests; on the device this is always the linked ES-DE folder.
  final String root;
  EsdeExport(this.api, {this.log, this.root = kEsdeRoot});

  File gamelistFile(String platform) =>
      File('$root/gamelists/$platform/gamelist.xml');

  Directory coversDir(String platform) =>
      Directory('$root/downloaded_media/$platform/covers');

  // Writes (or refreshes) one game's metadata and cover. Safe to call twice.
  Future<void> publish(Game g, {bool force = false}) async {
    final platform = esdePlatformFor(g.system);
    final fileName = g.relPath.split('/').last;
    await _mergeEntry(platform, fileName, g);
    await _saveCover(platform, fileName, g, force: force);
  }

  // Backfills games that are already on the device.
  //
  // Deliberately not automatic. Cocoon can be set to let ES-DE win over its
  // own scraped data, so publishing a whole library replaces titles and art
  // the user may have spent time on. RomStore publishes what it installs, and
  // this runs only when the user asks for it.
  Future<int> publishAll(Iterable<Game> games,
      {bool force = true, void Function(int done, int total)? onProgress}) async {
    final installed = games.where((g) => g.installed && !g.isDlc).toList();
    var done = 0;
    for (final g in installed) {
      try {
        await publish(g, force: force);
      } catch (e) {
        log?.call('${g.name}: $e');
      }
      onProgress?.call(++done, installed.length);
    }
    return done;
  }

  // gamelist.xml is rewritten rather than appended to: entries are keyed by
  // <path>, ours are replaced, and anything another tool wrote is copied
  // through untouched.
  Future<void> _mergeEntry(String platform, String fileName, Game g) async {
    final file = gamelistFile(platform);
    final entries = <String, String>{}; // <path> value -> whole <game> block
    if (file.existsSync()) {
      final existing = file.readAsStringSync();
      for (final m in RegExp(r'<game>.*?</game>', dotAll: true).allMatches(existing)) {
        final block = m.group(0)!;
        final path = RegExp(r'<path>(.*?)</path>', dotAll: true).firstMatch(block)?.group(1);
        if (path != null) entries[path.trim()] = block;
      }
    }

    final path = './$fileName';
    final b = StringBuffer()
      ..writeln('\t<game>')
      ..writeln('\t\t<path>${_xml(path)}</path>')
      ..writeln('\t\t<name>${_xml(g.name)}</name>');
    if (g.description.isNotEmpty) {
      b.writeln('\t\t<desc>${_xml(g.description)}</desc>');
    }
    final date = _esdeDate(g.releaseDate);
    if (date != null) b.writeln('\t\t<releasedate>$date</releasedate>');
    b.write('\t</game>');
    entries[path] = b.toString();

    final out = StringBuffer()
      ..writeln('<?xml version="1.0"?>')
      ..writeln('<gameList>');
    for (final block in entries.values) {
      out.writeln(block);
    }
    out.writeln('</gameList>');

    file.parent.createSync(recursive: true);
    file.writeAsStringSync(out.toString());
  }

  // Cocoon maps its Icon/Box Art slot to the ES-DE "covers" folder, and
  // matches media to a game by file name.
  Future<void> _saveCover(String platform, String fileName, Game g,
      {bool force = false}) async {
    final art = g.artworkPath;
    if (art == null || art.isEmpty) return;

    final ext = art.toLowerCase().endsWith('.jpg') || art.toLowerCase().endsWith('.jpeg')
        ? '.jpg'
        : '.png';
    final target = File('${coversDir(platform).path}/${_baseName(fileName)}$ext');
    if (!force && target.existsSync() && target.lengthSync() > 0) return;

    final bytes = await api.artworkBytes(art);
    if (bytes.isEmpty) return;
    target.parent.createSync(recursive: true);
    target.writeAsBytesSync(bytes);
  }

  // Drops a game from the ES-DE library. Called when the local copy is
  // deleted, so a rescan does not leave metadata behind for a missing file.
  void withdraw(Game g) {
    final platform = esdePlatformFor(g.system);
    final fileName = g.relPath.split('/').last;
    final file = gamelistFile(platform);
    if (file.existsSync()) {
      final existing = file.readAsStringSync();
      final kept = RegExp(r'<game>.*?</game>', dotAll: true)
          .allMatches(existing)
          .map((m) => m.group(0)!)
          .where((block) {
        final path = RegExp(r'<path>(.*?)</path>', dotAll: true).firstMatch(block)?.group(1);
        return path?.trim() != './$fileName';
      }).toList();

      final out = StringBuffer()
        ..writeln('<?xml version="1.0"?>')
        ..writeln('<gameList>');
      for (final block in kept) {
        out.writeln(block);
      }
      out.writeln('</gameList>');
      file.writeAsStringSync(out.toString());
    }

    for (final ext in const ['.png', '.jpg']) {
      final cover = File('${coversDir(platform).path}/${_baseName(fileName)}$ext');
      if (cover.existsSync()) cover.deleteSync();
    }
  }
}
