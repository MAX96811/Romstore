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
// depends on the menu order, so `rescanKeySequence` is kept in one place and
// `verify` reports honestly when nothing happened.

const _cocoonPackage = 'rip.moth.cocoonshell';
const _cocoonActivity = '$_cocoonPackage/.MainActivity';

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

  Future<bool> isInstalled() async {
    try {
      final out = await Shizuku.run('pm path $_cocoonPackage 2>/dev/null');
      return out.contains('package:');
    } catch (_) {
      return false;
    }
  }

  // Start menu -> Cocoon Settings -> Library & data -> Rescan Games -> run.
  //
  // The leading UP presses are not padding: the Start menu does not always
  // open on the same row, so the highlight is pinned to the top item first and
  // everything below counts from there.
  static const rescanKeySequence = <(int, int)>[
    (_kStart, 900), // open the Start menu
    (_kUp, 120), (_kUp, 120), (_kUp, 120), (_kUp, 120),
    (_kUp, 120), (_kUp, 120), (_kUp, 400), // pin the highlight to "Apps"
    (_kDown, 250), (_kDown, 250), (_kDown, 250), (_kDown, 250),
    (_kDown, 400), // -> Cocoon Settings
    (_kA, 2200), // open Settings (lands on Personalization)
    (_kDown, 400), // -> Library & data
    (_kA, 2200), // focus the right-hand pane (lands on Default Sort)
    (_kDown, 300), (_kDown, 500), // -> Rescan Games
    (_kA, 2500), // open the Rescan dialog
  ];

  Future<CocoonRefreshResult> refresh() async {
    if (!await Shizuku.ping()) {
      throw Exception('Shizuku is not running. Open Shizuku, start it, then try again.');
    }
    if (!await Shizuku.ensurePermission()) {
      throw Exception('Shizuku permission denied.');
    }
    if (!await isInstalled()) {
      throw Exception('Cocoon is not installed on this device.');
    }

    final watcher = _ScanWatcher();

    log?.call('Opening Cocoon…');
    await Shizuku.run('am start -n $_cocoonActivity');
    await Future.delayed(const Duration(seconds: 3));

    final artworkBefore = _mediaFileCount();

    log?.call('Running Rescan Games…');
    for (final (key, pauseMs) in rescanKeySequence) {
      await Shizuku.run('input keyevent $key');
      await Future.delayed(Duration(milliseconds: pauseMs));
    }

    // Y runs the scan in the Rescan dialog. If the menu ever shifts and this
    // lands somewhere else, the scan simply never commits -- which is why
    // every key from here on is decided by evidence, not by hope.
    await Shizuku.run('input keyevent $_kY');
    final scanned = await watcher.waitForCommit(log: log);

    if (scanned) {
      // Only now is a confirm key safe: the scan report is the screen in
      // front of us, and A is its OK button.
      log?.call('Closing the scan report…');
      await Shizuku.run('input keyevent $_kA');
      await Future.delayed(const Duration(milliseconds: 800));
    } else {
      // No idea what is on screen, so press nothing that can agree to
      // anything. B cancels, and force-stop closes whatever B did not.
      log?.call('Backing out…');
      for (var i = 0; i < 3; i++) {
        await Shizuku.run('input keyevent $_kB');
        await Future.delayed(const Duration(milliseconds: 400));
      }
    }

    // The metadata we wrote is only read by Cocoon's ES-DE startup sync, so
    // a new game keeps its file name until Cocoon restarts. Doing it here is
    // what makes one button produce a finished tile.
    log?.call('Restarting Cocoon…');
    await Shizuku.run('am force-stop $_cocoonPackage');
    await Future.delayed(const Duration(seconds: 2));
    await Shizuku.run('am start -n $_cocoonActivity');

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
      await Future.delayed(const Duration(milliseconds: 1500));

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
