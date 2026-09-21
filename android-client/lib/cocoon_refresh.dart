import 'dart:io';

import 'cloud_sync.dart' show Shizuku;

// Makes Cocoon notice what RomStore just installed.
//
// Cocoon has no rescan intent, no content provider and no folder watching: it
// does not pick up new files on resume, on a cold start, or after "Refetch
// Platforms" (all measured). The only way in is Settings -> Library & data ->
// Rescan Games, so we drive it the way a controller would, through Shizuku's
// shell.
//
// The sequence is key events only, no screen coordinates, which is what makes
// it survive Cocoon's updates: rows move, key counts rarely do. It still
// depends on the menu order, so `rescanScript` is kept in one place and the
// result reports honestly when nothing happened.

const _cocoonPackage = 'rip.moth.cocoonshell';
const _cocoonActivity = '$_cocoonPackage/.MainActivity';

// Printed by the macro script so one shell call can report both "Cocoon is
// not here" and "the keys were sent".
const _missingMarker = 'COCOON_MISSING';
const _doneMarker = 'MACRO_DONE';

// Cocoon writes these in the ROM folder, world readable. They are how we know
// a scan actually ran instead of assuming it did.
//
// The database log is the reliable one: it records `commit-rescan` for every
// scan that commits. scan_debug.log is only written when files are hashed, so
// a scan that merely drops a deleted game leaves it untouched -- watching it
// alone reports a false failure on every uninstall.
const _dbLog = '/storage/emulated/0/ROMs/cocoon-database-log.txt';
const _scanLog = '/storage/emulated/0/ROMs/scan_debug.log';
const _scanCommitted = 'mutation.complete operation=commit-rescan';

// Android key codes, gamepad names as Cocoon documents them.
const _kStart = 108; // BUTTON_START -> Start menu
const _kUp = 19;
const _kDown = 20;
const _kA = 96; // BUTTON_A -> confirm
const _kB = 97; // BUTTON_B -> back/cancel, safe on any screen
const _kY = 100; // BUTTON_Y -> "run" in the Rescan dialog

// Cocoon's scraped artwork, and the row directly below Rescan Games is
// "Clear Downloaded Media". If the menu ever shifts under us, that is what a
// stray confirm would empty, so it is counted before and after.
const _mediaDir = '/storage/emulated/0/ROMs/downloaded_media';

class CocoonRefreshResult {
  final bool scanRan;
  final String message;
  CocoonRefreshResult(this.scanRan, this.message);
}

class CocoonRefresh {
  final void Function(String)? log;
  CocoonRefresh({this.log});

  // Start menu -> Cocoon Settings -> Library & data -> Rescan Games -> run.
  //
  // Sent as a single shell script rather than one call per key. Every hop
  // through Shizuku spawns a process, and every `input` invocation starts a
  // JVM, so the cost was in the round trips, not in Cocoon: batching and
  // merging adjacent presses took this from ~16s to a measured 4.1s, with
  // 25ms of spread over repeated runs.
  //
  // The leading UP presses are not padding: the Start menu does not always
  // open on the same row, so the highlight is pinned to the top item first and
  // everything below counts from there.
  //
  // The pauses are the screen transitions, trimmed until they were still
  // reliable three runs in a row and no further; if Cocoon ever animates more
  // slowly, these are the numbers to raise.
  static String get rescanScript => [
        // Checked in the same shell rather than as its own round trip.
        'pm path $_cocoonPackage >/dev/null 2>&1 || { echo $_missingMarker; exit 0; }',
        'am start -n $_cocoonActivity >/dev/null 2>&1',
        'sleep 0.5', // Cocoon comes to the front
        'input keyevent $_kStart',
        'sleep 0.25', // Start menu opens
        // Pin to the top row, drop to Cocoon Settings, open it.
        'input keyevent $_kUp $_kUp $_kUp $_kUp $_kUp $_kUp $_kUp '
            '$_kDown $_kDown $_kDown $_kDown $_kDown $_kA',
        'sleep 0.45', // Settings opens on Personalization
        'input keyevent $_kDown $_kA', // -> Library & data, focus its pane
        'sleep 0.45',
        'input keyevent $_kDown $_kDown $_kA', // -> Rescan Games, open it
        'sleep 0.5', // the Rescan dialog appears
        'input keyevent $_kY', // run it for every platform
        'echo $_doneMarker',
      ].join('; ');

  // Closes the scan report and restarts Cocoon, so its ES-DE startup sync
  // dresses the new tiles. Sent only when the report is known to be up.
  static String get _finishScript => [
        'input keyevent $_kA', // OK on the scan report
        'sleep 0.3',
        'am force-stop $_cocoonPackage',
        'sleep 0.8',
        'am start -n $_cocoonActivity >/dev/null 2>&1',
        'echo $_doneMarker',
      ].join('; ');

  // Used when nothing committed: press only keys that decline, then let
  // force-stop close whatever B did not.
  static String get _abortScript => [
        'input keyevent $_kB $_kB $_kB',
        'am force-stop $_cocoonPackage',
        'sleep 0.8',
        'am start -n $_cocoonActivity >/dev/null 2>&1',
        'echo $_doneMarker',
      ].join('; ');

  Future<CocoonRefreshResult> refresh() async {
    if (!await Shizuku.ping()) {
      throw Exception('Shizuku is not running. Open Shizuku, start it, then try again.');
    }
    if (!await Shizuku.ensurePermission()) {
      throw Exception('Shizuku permission denied.');
    }

    final watcher = _ScanWatcher();
    final artworkBefore = _mediaFileCount();

    log?.call('Rescanning Cocoon…');
    final out = await Shizuku.run(rescanScript);
    if (out.contains(_missingMarker)) {
      throw Exception('Cocoon is not installed on this device.');
    }

    final scanned = await watcher.waitForCommit(log: log);

    log?.call(scanned ? 'Restarting Cocoon…' : 'Backing out…');
    await Shizuku.run(scanned ? _finishScript : _abortScript);

    final artworkAfter = _mediaFileCount();
    if (artworkBefore > 0 && artworkAfter < artworkBefore ~/ 2) {
      return CocoonRefreshResult(
          scanned,
          'Cocoon lost artwork during the refresh ($artworkBefore files before, '
          '$artworkAfter after). Its menu has probably moved — stop using this '
          'button and re-check the key sequence.');
    }

    return CocoonRefreshResult(
      scanned,
      scanned
          ? 'Cocoon rescanned and restarted.'
          : 'Cocoon did not report a scan, so nothing was confirmed. Run '
              'Settings → Library & data → Rescan Games by hand, and check whether '
              'that menu has changed.',
    );
  }

  // Cheap canary: the number of scraped media files Cocoon holds. Read
  // directly, since this lives on shared storage.
  int _mediaFileCount() {
    try {
      final dir = Directory(_mediaDir);
      if (!dir.existsSync()) return 0;
      return dir.listSync(recursive: true).whereType<File>().length;
    } catch (_) {
      return 0;
    }
  }

}

// Waits for Cocoon to commit a rescan, by reading only the bytes its database
// log gains after we start. Nothing here writes: these files just happen to be
// readable, and they are the only honest confirmation available, since the
// scan report exists solely on screen.
class _ScanWatcher {
  int _from = _lengthOf(_dbLog);
  int _hashedBytes = _lengthOf(_scanLog);

  static int _lengthOf(String path) {
    try {
      final f = File(path);
      return f.existsSync() ? f.lengthSync() : 0;
    } catch (_) {
      return 0;
    }
  }

  // The tail written since we started watching; a scan adds tens of KB at
  // most, so it is re-read whole on each poll.
  String _sinceStart() {
    try {
      final f = File(_dbLog);
      if (!f.existsSync()) return '';
      final length = f.lengthSync();
      if (length < _from) _from = 0; // log was rotated or cleared
      if (length == _from) return '';
      final handle = f.openSync();
      try {
        handle.setPositionSync(_from);
        return String.fromCharCodes(handle.readSync(length - _from));
      } finally {
        handle.closeSync();
      }
    } catch (_) {
      return '';
    }
  }

  Future<bool> waitForCommit({void Function(String)? log}) async {
    // Hashing a freshly downloaded Switch dump is slow, so the ceiling is
    // generous; the early exit below is what keeps a failed macro short.
    const giveUpAfter = Duration(minutes: 5);
    const abandonIfIdle = Duration(seconds: 45);

    final start = DateTime.now();
    while (DateTime.now().difference(start) < giveUpAfter) {
      // Reading the tail of a local file is cheap, so poll often: this is
      // otherwise dead time between the scan committing and the user seeing it.
      await Future.delayed(const Duration(milliseconds: 250));

      if (_sinceStart().contains(_scanCommitted)) return true;

      final hashed = _lengthOf(_scanLog);
      final working = hashed != _hashedBytes;
      if (working) {
        _hashedBytes = hashed;
        log?.call('Scanning…');
      }
      // Nothing committed and not a single file hashed: the key sequence never
      // reached the button, so say so now instead of in five minutes.
      if (!working && DateTime.now().difference(start) > abandonIfIdle) {
        return false;
      }
    }
    return false;
  }
}
