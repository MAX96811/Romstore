import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'main.dart' show kConfigDir;

// Client for the foreground download service.
//
// Flutter only asks for a download and watches it happen; the bytes are moved
// by DownloadService, so closing the app or going back to a game does not
// abandon a half-finished ROM. Progress arrives on an event channel, and the
// service also leaves a state file behind, which is how a download that
// finished while the UI was dead still gets published to Cocoon on next start.

const _method = MethodChannel('romstore/downloads');
const _events = EventChannel('romstore/downloads/events');
const kDownloadStateFile = '$kConfigDir/downloads.json';

enum DownloadState { queued, running, done, failed, cancelled }

DownloadState _parseState(String? raw) => switch (raw) {
      'running' => DownloadState.running,
      'done' => DownloadState.done,
      'failed' => DownloadState.failed,
      'cancelled' => DownloadState.cancelled,
      _ => DownloadState.queued,
    };

class DownloadItem {
  final String id; // the game's relPath
  final String title;
  final int received;
  final int total;
  final DownloadState state;
  final String? error;

  const DownloadItem({
    required this.id,
    required this.title,
    this.received = 0,
    this.total = 0,
    this.state = DownloadState.queued,
    this.error,
  });

  double? get progress => total > 0 ? (received / total).clamp(0.0, 1.0) : null;
  bool get active => state == DownloadState.queued || state == DownloadState.running;

  DownloadItem copyWith({int? received, int? total, DownloadState? state, String? error}) =>
      DownloadItem(
        id: id,
        title: title,
        received: received ?? this.received,
        total: total ?? this.total,
        state: state ?? this.state,
        error: error ?? this.error,
      );
}

class DownloadJob {
  final String id, url, dest, title;
  final String cookie;
  final int total;
  const DownloadJob({
    required this.id,
    required this.url,
    required this.dest,
    required this.title,
    required this.cookie,
    this.total = 0,
  });

  Map<String, dynamic> toJson() =>
      {'id': id, 'url': url, 'dest': dest, 'title': title, 'cookie': cookie, 'total': total};
}

class Downloads extends ChangeNotifier {
  Downloads._() {
    _subscription = _events.receiveBroadcastStream().listen(_onEvent, onError: (_) {});
  }

  static final Downloads instance = Downloads._();

  final Map<String, DownloadItem> _items = {};
  StreamSubscription? _subscription;

  // Fired when a download lands, so metadata can be published and the game
  // queued for Cocoon. Set by the screen that owns that logic.
  void Function(String id)? onCompleted;

  List<DownloadItem> get items => _items.values.toList();
  List<DownloadItem> get active => _items.values.where((i) => i.active).toList();
  int get activeCount => active.length;
  DownloadItem? operator [](String id) => _items[id];

  void _onEvent(dynamic raw) {
    if (raw is! Map) return;
    final id = raw['id'] as String?;
    if (id == null) return;

    final existing = _items[id];
    final state = _parseState(raw['state'] as String?);
    _items[id] = (existing ?? DownloadItem(id: id, title: id.split('/').last)).copyWith(
      received: (raw['received'] as num?)?.toInt() ?? existing?.received ?? 0,
      total: (raw['total'] as num?)?.toInt() ?? existing?.total ?? 0,
      state: state,
      error: raw['error'] as String?,
    );
    notifyListeners();

    if (state == DownloadState.done) onCompleted?.call(id);
  }

  Future<void> enqueue(List<DownloadJob> jobs) async {
    for (final job in jobs) {
      _items[job.id] = DownloadItem(id: job.id, title: job.title, total: job.total);
    }
    notifyListeners();
    await _method.invokeMethod('enqueue', {
      'jobs': jsonEncode(jobs.map((j) => j.toJson()).toList()),
    });
  }

  Future<void> cancel(String id) async {
    await _method.invokeMethod('cancel', {'id': id});
    _items[id] = _items[id]?.copyWith(state: DownloadState.cancelled) ??
        DownloadItem(id: id, title: id, state: DownloadState.cancelled);
    notifyListeners();
  }

  Future<void> cancelAll() async {
    await _method.invokeMethod('cancelAll');
    for (final entry in _items.entries.toList()) {
      if (entry.value.active) {
        _items[entry.key] = entry.value.copyWith(state: DownloadState.cancelled);
      }
    }
    notifyListeners();
  }

  void clearFinished() {
    _items.removeWhere((_, item) => !item.active);
    notifyListeners();
  }

  // Picks the service's view back up after the UI was restarted, and reports
  // which downloads finished while nobody was watching.
  Future<List<String>> reconcile() async {
    final finished = <String>[];
    try {
      final raw = await _method.invokeMethod<String>('state') ?? '[]';
      for (final entry in (jsonDecode(raw) as List).whereType<Map>()) {
        final id = entry['id'] as String?;
        if (id == null) continue;
        final state = _parseState(entry['state'] as String?);
        _items[id] = DownloadItem(
          id: id,
          title: (entry['title'] as String?) ?? id.split('/').last,
          received: (entry['received'] as num?)?.toInt() ?? 0,
          total: (entry['total'] as num?)?.toInt() ?? 0,
          state: state,
          error: entry['error'] as String?,
        );
        if (state == DownloadState.done) finished.add(id);
      }
    } catch (_) {
      // Service not running: fall back to what it left on disk.
      try {
        final file = File(kDownloadStateFile);
        if (file.existsSync()) {
          for (final entry in (jsonDecode(file.readAsStringSync()) as List).whereType<Map>()) {
            if (entry['state'] == 'done' && entry['id'] is String) {
              finished.add(entry['id'] as String);
            }
          }
        }
      } catch (_) {}
    }
    notifyListeners();
    return finished;
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }
}
