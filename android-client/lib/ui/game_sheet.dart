import 'package:flutter/material.dart';

import '../downloads.dart';
import '../main.dart';
import 'store_screen.dart' show GameCover;
import 'theme.dart';

// One game, opened from the grid. The cover flies up from the card it was
// tapped on, so the sheet feels like the tile expanding rather than a new
// screen arriving.
class GameSheet extends StatefulWidget {
  final Game game;
  final Api api;
  final VoidCallback onInstall;
  final Future<void> Function() onDelete;
  final VoidCallback onCancel;
  final VoidCallback onInstallAddons;

  const GameSheet({
    super.key,
    required this.game,
    required this.api,
    required this.onInstall,
    required this.onDelete,
    required this.onCancel,
    required this.onInstallAddons,
  });

  @override
  State<GameSheet> createState() => _GameSheetState();
}

class _GameSheetState extends State<GameSheet> {
  final downloads = Downloads.instance;

  @override
  void initState() {
    super.initState();
    downloads.addListener(_changed);
  }

  @override
  void dispose() {
    downloads.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  Future<void> _confirmDelete() async {
    final g = widget.game;
    final yes = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Remove from device?'),
        content: Text('${g.name}\n\nDeletes the local copy only; the server keeps it. '
            'The tile disappears from Cocoon on the next refresh.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Delete')),
        ],
      ),
    );
    if (yes != true) return;
    await widget.onDelete();
    if (mounted) Navigator.of(context).maybePop();
  }

  @override
  Widget build(BuildContext context) {
    final g = widget.game;
    final item = downloads[g.relPath];
    final busy = item?.active == true;
    final installed = g.installed;

    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.72,
      minChildSize: 0.45,
      maxChildSize: 0.95,
      builder: (context, controller) => ListView(
        controller: controller,
        padding: const EdgeInsets.fromLTRB(20, 4, 20, 28),
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Hero(
                tag: 'cover-${g.relPath}',
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(16),
                  child: SizedBox(
                    width: 128,
                    height: 178,
                    child: GameCover(game: g, api: widget.api),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 6),
                    Text(g.name,
                        style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 8),
                    _metaRow(Icons.memory_rounded, g.systemName),
                    _metaRow(Icons.sd_storage_rounded, g.size),
                    if (g.hasAddons)
                      _metaRow(Icons.extension_rounded,
                          '${g.addons.length} update/DLC file${g.addons.length == 1 ? '' : 's'}'),
                    if (installed)
                      _metaRow(Icons.check_circle_rounded, 'Installed on this device',
                          color: kBrandOrangeLight),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (busy) _progress(item!) else _actions(installed),
          if (g.description.isNotEmpty) ...[
            const SizedBox(height: 22),
            const Text('About', style: TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            Text(g.description,
                style: const TextStyle(height: 1.45, color: Colors.white70)),
          ],
          const SizedBox(height: 18),
          Text('ROMs/${g.relPath}',
              style: const TextStyle(fontSize: 11, color: Colors.white30)),
        ],
      ),
    );
  }

  Widget _metaRow(IconData icon, String text, {Color? color}) => Padding(
        padding: const EdgeInsets.only(bottom: 4),
        child: Row(children: [
          Icon(icon, size: 15, color: color ?? Colors.white38),
          const SizedBox(width: 6),
          Expanded(
            child: Text(text,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontSize: 12.5, color: color ?? Colors.white60)),
          ),
        ]),
      );

  Widget _progress(DownloadItem item) {
    final p = item.progress;
    final mb = (item.received / 1048576).toStringAsFixed(0);
    final totalMb = item.total > 0 ? (item.total / 1048576).toStringAsFixed(0) : '?';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TweenAnimationBuilder<double>(
          tween: Tween(begin: 0, end: p ?? 0),
          duration: const Duration(milliseconds: 350),
          builder: (c, value, _) => ClipRRect(
            borderRadius: BorderRadius.circular(10),
            child: LinearProgressIndicator(
              value: p == null ? null : value,
              minHeight: 10,
              backgroundColor: kSurfaceHigh,
            ),
          ),
        ),
        const SizedBox(height: 10),
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text(
            item.state == DownloadState.queued ? 'Waiting…' : '$mb / $totalMb MB',
            style: const TextStyle(fontSize: 12, color: Colors.white60),
          ),
          TextButton.icon(
            onPressed: widget.onCancel,
            icon: const Icon(Icons.stop_rounded, size: 18),
            label: const Text('Cancel'),
          ),
        ]),
        const SizedBox(height: 4),
        const Text('Downloading in the background — you can leave the app.',
            style: TextStyle(fontSize: 11.5, color: Colors.white38)),
      ],
    );
  }

  Widget _actions(bool installed) {
    if (!installed) {
      return Row(children: [
        Expanded(
          child: FilledButton.icon(
            onPressed: () {
              widget.onInstall();
              Navigator.of(context).maybePop();
            },
            icon: const Icon(Icons.download_rounded),
            label: const Text('Install'),
          ),
        ),
      ]);
    }
    return Row(children: [
      if (widget.game.hasAddons) ...[
        Expanded(
          child: FilledButton.tonalIcon(
            onPressed: () {
              widget.onInstallAddons();
              Navigator.of(context).maybePop();
            },
            icon: const Icon(Icons.extension_rounded),
            label: const Text('Updates & DLC'),
          ),
        ),
        const SizedBox(width: 10),
      ],
      Expanded(
        child: OutlinedButton.icon(
          onPressed: _confirmDelete,
          icon: const Icon(Icons.delete_outline_rounded),
          label: const Text('Remove'),
        ),
      ),
    ]);
  }
}
