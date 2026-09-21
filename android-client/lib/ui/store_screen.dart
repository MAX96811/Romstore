import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import '../cloud_sync.dart' show Shizuku, SyncScreen;
import '../cocoon_refresh.dart';
import '../downloads.dart';
import '../esde_export.dart';
import '../main.dart';
import '../switch_addons.dart';
import 'downloads_sheet.dart';
import 'game_sheet.dart';
import 'theme.dart';

// The store: pick a system, pick a game, and it downloads in the background
// and turns up in Cocoon already carrying its artwork.

class StoreScreen extends StatefulWidget {
  final Api api;
  final VoidCallback onLogout;
  const StoreScreen({super.key, required this.api, required this.onLogout});

  @override
  State<StoreScreen> createState() => _StoreScreenState();
}

class _StoreScreenState extends State<StoreScreen> {
  List<Game>? all;
  String? error;
  String systemFilter = 'all';
  String search = '';
  bool searching = false;

  final Map<String, String> addonStatus = {};
  bool syncingAddons = false;

  // Installed or removed since Cocoon last rescanned.
  final Set<String> pendingForCocoon = {};
  String? cocoonStatus;

  late final EsdeExport esde =
      EsdeExport(widget.api, log: (m) => debugPrint('[esde] $m'));
  final downloads = Downloads.instance;

  @override
  void initState() {
    super.initState();
    _loadPending();
    downloads.onCompleted = _onDownloadFinished;
    downloads.addListener(_onDownloadsChanged);
    _refresh();
    _listenForShopLinks();
  }

  @override
  void dispose() {
    downloads.removeListener(_onDownloadsChanged);
    if (downloads.onCompleted == _onDownloadFinished) downloads.onCompleted = null;
    super.dispose();
  }

  void _onDownloadsChanged() {
    if (mounted) setState(() {});
  }

  // ---------------------------------------------------------------- library

  Future<void> _refresh() async {
    setState(() {
      error = null;
      all = null;
    });
    try {
      final games = await widget.api.games();
      games.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
      if (!mounted) return;
      setState(() => all = games);
      // Anything that landed while the UI was gone still needs its metadata
      // published and Cocoon told about it.
      for (final id in await downloads.reconcile()) {
        _onDownloadFinished(id);
      }
    } catch (e) {
      if (mounted) setState(() => error = '$e');
    }
  }

  List<Game> get _library => (all ?? []).where((g) => !g.isDlc).toList();

  Map<String, int> get _systemCounts {
    final counts = <String, int>{};
    for (final g in _library) {
      counts[g.system] = (counts[g.system] ?? 0) + 1;
    }
    return counts;
  }

  List<Game> get visible {
    var v = _library;
    if (systemFilter != 'all') v = v.where((g) => g.system == systemFilter).toList();
    if (search.isNotEmpty) {
      final q = search.toLowerCase();
      v = v.where((g) => g.name.toLowerCase().contains(q)).toList();
    }
    return v;
  }

  // ---------------------------------------------------------------- linking

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
      // Plain launch: show everything.
    }
  }

  void _openPlatform(String? platform) {
    if (platform == null || !mounted) return;
    setState(() {
      systemFilter = systemForEsdePlatform(platform);
      search = '';
    });
  }

  // -------------------------------------------------------------- installing

  Future<void> _install(Game g) async {
    await downloads.enqueue([
      DownloadJob(
        id: g.relPath,
        url: widget.api.downloadUrl(g.relPath),
        dest: '$kRomsRoot/${g.relPath}',
        title: g.name,
        cookie: widget.api.config.cookie,
        total: g.sizeBytes ?? 0,
      )
    ]);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('${g.name} — downloading in the background'),
          action: SnackBarAction(label: 'View', onPressed: _openDownloads),
        ),
      );
    }
  }

  // Runs when the service reports a finished file, whether or not this screen
  // was on show at the time.
  Future<void> _onDownloadFinished(String relPath) async {
    final game = (all ?? []).where((g) => g.relPath == relPath).firstOrNull;
    if (game == null) return;
    try {
      await esde.publish(game);
      if (mounted) setState(() => _markPending(relPath));
    } catch (e) {
      debugPrint('[esde] ${game.name}: $e');
    }
    if (game.hasAddons) await _installAddons(game);
  }

  Future<void> _delete(Game g) async {
    File('$kRomsRoot/${g.relPath}').deleteSync();
    try {
      esde.withdraw(g);
    } catch (e) {
      debugPrint('[esde] withdraw ${g.name}: $e');
    }
    if (mounted) setState(() => _markPending(g.relPath));
  }

  // Downloads every missing update/DLC for a base game and registers it in
  // each Eden NAND on the device.
  Future<void> _installAddons(Game g) async {
    if (!g.hasAddons) return;
    final installer = EdenContentInstaller((m) => debugPrint('[addons] $m'));
    void status(String? text) {
      if (!mounted) return;
      setState(() {
        if (text == null) {
          addonStatus.remove(g.relPath);
        } else {
          addonStatus[g.relPath] = text;
        }
      });
    }

    try {
      if (!await Shizuku.ping()) {
        throw Exception('Shizuku is not running: open it and start it first.');
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
        final present =
            target.existsSync() && (a.sizeBytes == null || target.lengthSync() == a.sizeBytes);
        if (!present) {
          status('Downloading ${a.label} $i/${g.addons.length}…');
          await widget.api.downloadRelPath(a.relPath, (p) {
            status('Downloading ${a.label} $i/${g.addons.length} ${(p * 100).round()}%');
          });
        }
        status('Installing ${a.label} $i/${g.addons.length} into Eden…');
        if (!stopped) {
          // Eden reads its registered cache at startup only.
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
      status(null);
    }
  }

  Future<void> _syncAllAddons() async {
    if (syncingAddons) return;
    final targets = _library.where((g) => g.installed && g.hasAddons).toList();
    if (targets.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content: Text('No installed Switch game has updates or DLC on the server.')));
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

  // ------------------------------------------------------------ Cocoon sync

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
        if (mounted) setState(() => cocoonStatus = 'Writing metadata $done/${waiting.length}…');
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
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(result.message)));
  }

  Future<void> _backfillCocoon() async {
    if (cocoonStatus != null) return;
    final installed = _library.where((g) => g.installed).length;
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
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Backfill: $e')));
      }
    } finally {
      if (mounted) setState(() => cocoonStatus = null);
    }
  }

  // ----------------------------------------------------------------- sheets

  void _openGame(Game g) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => GameSheet(
        game: g,
        api: widget.api,
        onInstall: () => _install(g),
        onDelete: () => _delete(g),
        onCancel: () => downloads.cancel(g.relPath),
        onInstallAddons: () => _installAddons(g),
      ),
    ).then((_) {
      if (mounted) setState(() {});
    });
  }

  void _openDownloads() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => const DownloadsSheet(),
    );
  }

  // ------------------------------------------------------------------ build

  @override
  Widget build(BuildContext context) {
    return StoreBackdrop(
      child: Scaffold(
        backgroundColor: Colors.transparent,
        body: RefreshIndicator(
          onRefresh: _refresh,
          child: CustomScrollView(
            slivers: [
              _appBar(),
              if (all != null && error == null)
                SliverToBoxAdapter(
                  child: _PlatformRail(
                    counts: _systemCounts,
                    names: {for (final g in _library) g.system: g.systemName},
                    selected: systemFilter,
                    onSelect: (s) => setState(() => systemFilter = s),
                  ),
                ),
              if (error != null)
                SliverFillRemaining(hasScrollBody: false, child: _error())
              else if (all == null)
                const SliverFillRemaining(
                    hasScrollBody: false, child: Center(child: CircularProgressIndicator()))
              else if (visible.isEmpty)
                SliverFillRemaining(hasScrollBody: false, child: _empty())
              else
                _grid(),
              const SliverToBoxAdapter(child: SizedBox(height: 28)),
            ],
          ),
        ),
      ),
    );
  }

  Widget _appBar() {
    final waiting = pendingForCocoon.length;
    final busy = cocoonStatus != null;
    return SliverAppBar(
      floating: true,
      pinned: true,
      expandedHeight: 108,
      backgroundColor: kInk.withValues(alpha: 0.86),
      title: AnimatedSwitcher(
        duration: const Duration(milliseconds: 220),
        child: busy
            ? Row(key: const ValueKey('busy'), children: [
                const SizedBox(
                    width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 10),
                Flexible(
                    child: Text(cocoonStatus!,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 15))),
              ])
            : const Text('RomStore',
                key: ValueKey('title'),
                style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 0.2)),
      ),
      actions: [
        _DownloadsButton(count: downloads.activeCount, onPressed: _openDownloads),
        IconButton(
          tooltip: waiting == 0 ? 'Send to Cocoon' : 'Send to Cocoon ($waiting waiting)',
          onPressed: busy ? null : _sendToCocoon,
          icon: Badge(
            isLabelVisible: waiting > 0,
            label: Text('$waiting'),
            child: const Icon(Icons.grid_view_rounded),
          ),
        ),
        PopupMenuButton<String>(
          enabled: !busy,
          onSelected: (v) => switch (v) {
            'addons' => _syncAllAddons(),
            'backfill' => _backfillCocoon(),
            'sync' => Navigator.push(context,
                MaterialPageRoute(builder: (c) => SyncScreen(api: widget.api))),
            'logout' => widget.onLogout(),
            _ => null,
          },
          itemBuilder: (c) => [
            PopupMenuItem(
                value: 'addons',
                enabled: !syncingAddons,
                child: const Text('Updates & DLC for installed games')),
            const PopupMenuItem(value: 'sync', child: Text('Cloud save sync')),
            const PopupMenuItem(
                value: 'backfill', child: Text('Publish all metadata to Cocoon…')),
            const PopupMenuItem(value: 'logout', child: Text('Log out')),
          ],
        ),
      ],
      flexibleSpace: FlexibleSpaceBar(
        background: Align(
          alignment: Alignment.bottomCenter,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 10),
            child: TextField(
              onChanged: (v) => setState(() => search = v),
              textInputAction: TextInputAction.search,
              decoration: InputDecoration(
                hintText: 'Search the library',
                prefixIcon: const Icon(Icons.search_rounded),
                suffixIcon: search.isEmpty
                    ? null
                    : IconButton(
                        icon: const Icon(Icons.close_rounded),
                        onPressed: () => setState(() => search = ''),
                      ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _grid() {
    return SliverPadding(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      sliver: SliverGrid(
        gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
          maxCrossAxisExtent: 190,
          childAspectRatio: 0.66,
          crossAxisSpacing: 14,
          mainAxisSpacing: 14,
        ),
        delegate: SliverChildBuilderDelegate(
          (context, i) {
            final game = visible[i];
            return EntranceFade(
              index: i,
              child: GameCard(
                key: ValueKey(game.relPath),
                game: game,
                api: widget.api,
                download: downloads[game.relPath],
                statusText: addonStatus[game.relPath],
                onTap: () => _openGame(game),
              ),
            );
          },
          childCount: visible.length,
        ),
      ),
    );
  }

  Widget _error() => Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          const Icon(Icons.cloud_off_rounded, size: 48),
          const SizedBox(height: 12),
          Text(error!, textAlign: TextAlign.center),
          const SizedBox(height: 16),
          FilledButton(onPressed: _refresh, child: const Text('Retry')),
        ]),
      );

  Widget _empty() => Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          const Icon(Icons.videogame_asset_off_rounded, size: 44),
          const SizedBox(height: 12),
          Text(
            search.isNotEmpty
                ? 'Nothing matches "$search".'
                : 'No games in this system yet.',
            textAlign: TextAlign.center,
          ),
        ]),
      );
}

// A row of systems with counts. Selection animates, because on a handheld the
// chip you just moved to should be obvious without reading it.
class _PlatformRail extends StatefulWidget {
  final Map<String, int> counts;
  final Map<String, String> names;
  final String selected;
  final ValueChanged<String> onSelect;

  const _PlatformRail({
    required this.counts,
    required this.names,
    required this.selected,
    required this.onSelect,
  });

  @override
  State<_PlatformRail> createState() => _PlatformRailState();
}

class _PlatformRailState extends State<_PlatformRail> {
  final _controller = ScrollController();

  @override
  void didUpdateWidget(_PlatformRail old) {
    super.didUpdateWidget(old);
    if (old.selected != widget.selected) _revealSelected();
  }

  @override
  void initState() {
    super.initState();
    if (widget.selected != 'all') {
      WidgetsBinding.instance.addPostFrameCallback((_) => _revealSelected());
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  // Scrolls the selected system into view. A shop tile opens straight into its
  // own platform, and with forty systems that chip is usually far off-screen.
  //
  // The offset is measured rather than found through the widget tree: chips
  // that far out are never mounted, so there is no context to ensureVisible on.
  void _revealSelected() {
    if (!_controller.hasClients || widget.selected == 'all') return;
    final systems = widget.counts.keys.toList()..sort();
    final index = systems.indexOf(widget.selected);
    if (index < 0) return;

    var offset = _chipWidth('All systems', _totalCount);
    for (var i = 0; i < index; i++) {
      offset += _chipWidth(widget.names[systems[i]] ?? systems[i], widget.counts[systems[i]] ?? 0);
    }
    // Leave a sliver of the previous chip visible, so it reads as a position
    // in a list rather than the start of one.
    final target = (offset - 28).clamp(0.0, _controller.position.maxScrollExtent);
    _controller.animateTo(target,
        duration: const Duration(milliseconds: 380), curve: Curves.easeOutCubic);
  }

  int get _totalCount => widget.counts.values.fold<int>(0, (a, b) => a + b);

  double _chipWidth(String label, int count) {
    double measure(String text, double size, FontWeight weight) {
      final painter = TextPainter(
        text: TextSpan(text: text, style: TextStyle(fontSize: size, fontWeight: weight)),
        textDirection: TextDirection.ltr,
      )..layout();
      return painter.width;
    }

    // 16 padding either side, 8 between label and count, 8 of margin.
    return 32 + measure(label, 14, FontWeight.w600) + 8 + measure('$count', 12, FontWeight.w400) + 8;
  }

  @override
  Widget build(BuildContext context) {
    final systems = widget.counts.keys.toList()..sort();
    final total = widget.counts.values.fold<int>(0, (a, b) => a + b);
    return SizedBox(
      height: 64,
      child: ListView(
        controller: _controller,
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        children: [
          _chip(context, 'all', 'All systems', total),
          for (final s in systems)
            _chip(context, s, widget.names[s] ?? s, widget.counts[s] ?? 0),
        ],
      ),
    );
  }

  Widget _chip(BuildContext context, String value, String label, int count) {
    final active = widget.selected == value;
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        curve: Curves.easeOut,
        decoration: BoxDecoration(
          color: active ? kBrandOrange : kSurfaceHigh,
          borderRadius: BorderRadius.circular(30),
          boxShadow: active
              ? [BoxShadow(color: kBrandOrange.withValues(alpha: 0.35), blurRadius: 14)]
              : null,
        ),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(30),
            onTap: () => widget.onSelect(value),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              child: Row(children: [
                Text(label,
                    style: TextStyle(
                      fontWeight: active ? FontWeight.w700 : FontWeight.w500,
                      color: active ? Colors.white : Colors.white70,
                    )),
                const SizedBox(width: 8),
                Text('$count',
                    style: TextStyle(
                      fontSize: 12,
                      color: active ? Colors.white70 : Colors.white38,
                    )),
              ]),
            ),
          ),
        ),
      ),
    );
  }
}

class _DownloadsButton extends StatelessWidget {
  final int count;
  final VoidCallback onPressed;
  const _DownloadsButton({required this.count, required this.onPressed});

  @override
  Widget build(BuildContext context) {
    return IconButton(
      tooltip: count == 0 ? 'Downloads' : '$count downloading',
      onPressed: onPressed,
      icon: Badge(
        isLabelVisible: count > 0,
        label: Text('$count'),
        child: Icon(count > 0 ? Icons.downloading_rounded : Icons.download_rounded),
      ),
    );
  }
}

// One game. Cover art fills the card, with a scrim so the title stays legible
// over bright box art, and the download state drawn on top of it.
class GameCard extends StatelessWidget {
  final Game game;
  final Api api;
  final DownloadItem? download;
  final String? statusText;
  final VoidCallback onTap;

  const GameCard({
    super.key,
    required this.game,
    required this.api,
    required this.onTap,
    this.download,
    this.statusText,
  });

  @override
  Widget build(BuildContext context) {
    final installed = game.installed;
    final busy = download?.active == true || statusText != null;

    return Card(
      child: InkWell(
        onTap: onTap,
        child: Stack(
          fit: StackFit.expand,
          children: [
            Hero(
              tag: 'cover-${game.relPath}',
              child: GameCover(game: game, api: api),
            ),
            const DecoratedBox(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.center,
                  end: Alignment.bottomCenter,
                  colors: [Colors.transparent, Color(0xEE14110F)],
                ),
              ),
            ),
            if (busy) _busyOverlay(context),
            Positioned(
              left: 10,
              right: 10,
              bottom: 10,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    game.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    statusText ?? game.size,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 11, color: Colors.white60),
                  ),
                ],
              ),
            ),
            if (installed && !busy)
              const Positioned(
                top: 8,
                right: 8,
                child: _Pill(icon: Icons.check_rounded, label: 'Installed'),
              ),
            if (game.hasAddons && !busy)
              Positioned(
                top: 8,
                left: 8,
                child: _Pill(icon: Icons.extension_rounded, label: '${game.addons.length}'),
              ),
          ],
        ),
      ),
    );
  }

  Widget _busyOverlay(BuildContext context) {
    final p = download?.progress;
    return Container(
      color: Colors.black54,
      child: Center(
        child: SizedBox(
          width: 52,
          height: 52,
          child: Stack(
            alignment: Alignment.center,
            children: [
              TweenAnimationBuilder<double>(
                tween: Tween(begin: 0, end: p ?? 0),
                duration: const Duration(milliseconds: 350),
                builder: (c, value, _) => CircularProgressIndicator(
                  value: p == null ? null : value,
                  strokeWidth: 3,
                ),
              ),
              if (p != null)
                Text('${(p * 100).round()}',
                    style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700)),
            ],
          ),
        ),
      ),
    );
  }
}

// Box art, or a tidy placeholder. Images fade in rather than snapping, which
// matters when a screen of them loads at once.
class GameCover extends StatelessWidget {
  final Game game;
  final Api api;
  const GameCover({super.key, required this.game, required this.api});

  @override
  Widget build(BuildContext context) {
    final art = game.artworkPath;
    if (art == null) {
      return const ColoredBox(
        color: kSurfaceHigh,
        child: Center(child: Icon(Icons.videogame_asset_rounded, size: 40, color: Colors.white24)),
      );
    }
    return Image.network(
      api.artworkUrl(art),
      headers: api.authHeaders,
      fit: BoxFit.cover,
      frameBuilder: (context, child, frame, wasSync) {
        if (wasSync) return child;
        return AnimatedOpacity(
          opacity: frame == null ? 0 : 1,
          duration: const Duration(milliseconds: 260),
          curve: Curves.easeOut,
          child: child,
        );
      },
      errorBuilder: (c, e, s) => const ColoredBox(
        color: kSurfaceHigh,
        child: Center(child: Icon(Icons.broken_image_rounded, size: 34, color: Colors.white24)),
      ),
    );
  }
}

class _Pill extends StatelessWidget {
  final IconData icon;
  final String label;
  const _Pill({required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 13, color: kBrandOrangeLight),
        const SizedBox(width: 4),
        Text(label, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
      ]),
    );
  }
}
