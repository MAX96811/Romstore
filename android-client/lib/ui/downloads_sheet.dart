import 'package:flutter/material.dart';

import '../downloads.dart';
import 'theme.dart';

// The queue. Downloads belong to the service, not to this sheet, so closing it
// (or the whole app) changes nothing about what is being fetched.
class DownloadsSheet extends StatefulWidget {
  const DownloadsSheet({super.key});

  @override
  State<DownloadsSheet> createState() => _DownloadsSheetState();
}

class _DownloadsSheetState extends State<DownloadsSheet> {
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

  @override
  Widget build(BuildContext context) {
    final items = downloads.items;
    final active = items.where((i) => i.active).toList();
    final finished = items.where((i) => !i.active).toList();

    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      minChildSize: 0.3,
      maxChildSize: 0.92,
      builder: (context, controller) => Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 4, 12, 8),
            child: Row(children: [
              const Text('Downloads',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
              const Spacer(),
              if (active.isNotEmpty)
                TextButton(
                  onPressed: downloads.cancelAll,
                  child: const Text('Cancel all'),
                ),
              if (finished.isNotEmpty)
                TextButton(
                  onPressed: downloads.clearFinished,
                  child: const Text('Clear'),
                ),
            ]),
          ),
          Expanded(
            child: items.isEmpty
                ? const Center(
                    child: Padding(
                      padding: EdgeInsets.all(32),
                      child: Text('Nothing downloading.',
                          style: TextStyle(color: Colors.white54)),
                    ),
                  )
                : ListView(
                    controller: controller,
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 28),
                    children: [
                      for (final item in active) _row(item),
                      if (finished.isNotEmpty) ...[
                        const Padding(
                          padding: EdgeInsets.fromLTRB(4, 16, 4, 8),
                          child: Text('Finished',
                              style: TextStyle(fontSize: 12, color: Colors.white38)),
                        ),
                        for (final item in finished) _row(item),
                      ],
                    ],
                  ),
          ),
        ],
      ),
    );
  }

  Widget _row(DownloadItem item) {
    final p = item.progress;
    final done = item.state == DownloadState.done;
    final failed =
        item.state == DownloadState.failed || item.state == DownloadState.cancelled;

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 6, 12),
        child: Row(children: [
          Icon(
            done
                ? Icons.check_circle_rounded
                : failed
                    ? Icons.error_outline_rounded
                    : Icons.downloading_rounded,
            color: done
                ? kBrandOrangeLight
                : failed
                    ? Colors.redAccent
                    : Colors.white54,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(item.title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13.5)),
                const SizedBox(height: 6),
                if (item.active)
                  TweenAnimationBuilder<double>(
                    tween: Tween(begin: 0, end: p ?? 0),
                    duration: const Duration(milliseconds: 350),
                    builder: (c, value, _) => ClipRRect(
                      borderRadius: BorderRadius.circular(8),
                      child: LinearProgressIndicator(
                        value: p == null ? null : value,
                        minHeight: 6,
                        backgroundColor: kSurfaceHigh,
                      ),
                    ),
                  ),
                const SizedBox(height: 5),
                Text(
                  _subtitle(item),
                  style: const TextStyle(fontSize: 11.5, color: Colors.white54),
                ),
              ],
            ),
          ),
          if (item.active)
            IconButton(
              tooltip: 'Cancel',
              onPressed: () => downloads.cancel(item.id),
              icon: const Icon(Icons.close_rounded, size: 20),
            ),
        ]),
      ),
    );
  }

  String _subtitle(DownloadItem item) {
    final mb = (item.received / 1048576).toStringAsFixed(0);
    final total = item.total > 0 ? (item.total / 1048576).toStringAsFixed(0) : '?';
    return switch (item.state) {
      DownloadState.queued => 'Waiting…',
      DownloadState.running => '$mb / $total MB',
      DownloadState.done => 'Installed · $total MB',
      DownloadState.cancelled => 'Cancelled',
      DownloadState.failed => item.error ?? 'Failed',
    };
  }
}
