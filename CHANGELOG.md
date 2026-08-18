# Changelog

## v2.1.3 - 2026-08-18

### Added
- Automatic Switch save sync. Enabling auto-sync now also watches the live Ryujinx save root; slots that change while you play are queued and uploaded as complete bundles once Ryujinx exits and the files settle. Previously the auto-sync toggle silently covered no Switch game at all, because Ryujinx paths are excluded from the per-file watcher by design.
- Auto-sync covers every slot with a readable Title ID, so a game does not have to be linked in the library first.
- Toasts reporting each automatic bundle upload, and a failure notice once a slot has exhausted its retries.

### Fixed
- The Switch watcher ignores dot-entries relative to the slots root rather than anywhere in the path. The obvious `/(^|[\/\\])\../` rule matches the Flatpak root itself (`~/.var/app/...`) and would have ignored the entire save tree.
- Auto-sync fails closed: if the running-process check throws, the bundle is treated as in use and left for the next tick instead of being snapshotted from live files.
- The emulator re-check now runs after every bundle in a flush, not only after a failed one, so relaunching Ryujinx mid-flush cannot expose the remaining slots to a live snapshot.

### Changed
- The local-candidate panel states whether auto-sync will pick the candidates up, instead of implying a manual snapshot is the only route.

## v2.1.2 - 2026-08-16

### Fixed
- Resolved Ryujinx save slots through the application Title ID embedded in `ExtraData0/1`, so Switch games can find their saves without treating opaque slot numbers as game IDs.
- Canonicalized and validated save paths at both client and server boundaries, deduplicating legacy Linux filenames that contain Windows backslashes without deleting them.
- Stopped startup timestamp reconciliation from silently replacing local emulator progress with newer cloud upload timestamps.
- Reset previously enabled unsafe auto-sync once during the upgrade and excluded transactional Ryujinx bundles from the legacy per-file watcher.

### Added
- Complete Ryujinx bundle backup and restore for `saves`, `saveMeta`, both generations, and `ExtraData`, with Title ID/hash verification.
- Atomic activation with rollback and preserved previous local/server candidates; Ryujinx must be closed during backup or restore.
- Retention for the ten most recent RomStore bundle generations per slot, without touching Ryujinx `.oldsave` recovery waves.
- Local Ryujinx title discovery, automatic matching for launched games, and an admin-assisted candidate linker for games whose ROM filename has no Title ID.
- Save-path health APIs for safely inventorying and materializing legacy backslash paths without overwriting canonical files.

### Changed
- Switch saves are shown as independent candidates rather than a misleading list of individually restorable files.
- Cloud-only or cloud-changed saves now require an explicit restore/conflict choice; automatic backups remain local-to-server only.

## v2.1.1 - 2026-08-16

### Fixed
- Made **Play** and **Install** persistent actions instead of hiding them behind a clicked cover overlay.
- Added an always-visible installed/cloud badge and local-library totals so launchable games are immediately clear.
- Limited local discovery to EmuDeck library folders and preserved logical paths through symlinked ROM directories.
- Normalized trailing slashes in server URLs so background save uploads do not produce double-slash API paths.
- Queued background save uploads and suppressed download echoes to prevent burst retries and notification spam during startup sync.
- Kept logical EmuDeck save paths when scanning symlinked emulator folders, avoiding rejected `../` upload paths.

### Changed
- Refined the desktop layout, navigation, game cards, list rows, loading and empty states, settings panels, and upload workflow.
- Added drag-and-drop game selection and clearer install, launch, and EmuDeck connection feedback.

## v2.1.0 - 2026-08-16

### Added
- Integrated game uploads directly into the Electron desktop client with authenticated 8 MB chunking and per-console targets.
- Added EmuDeck-aware **Play** actions for installed games.
- Automatically discovers EmuDeck system definitions, launcher scripts, standalone emulator fallbacks, and installed RetroArch cores.
- Added editable per-platform emulator profiles using `{rom}` or `%ROM%` placeholders.
- Added `/api/platforms` for console names, supported extensions, and nested EmuDeck upload folders.
- Added automated tests for EmuDeck command resolution, AppImage environment cleanup, platform parsing, and recursive game discovery.

### Changed
- Game discovery now supports nested EmuDeck layouts such as `wiiu/roms` while excluding artwork and metadata files.
- Uploads automatically target an existing platform's nested `roms` directory when required by EmuDeck.
- Emulator launches strip AppImage-mounted runtime paths before invoking Flatpak-backed EmuDeck launchers.
- Updated Electron, electron-builder, Axios, FormData, Multer, and backend transitive dependencies; production dependency audits are clean.

## v2.0.2 - 2026-02-15

### Fixed
- Bulk game upload now finalizes files into the selected ROM system folder instead of leaving them in temporary upload storage.
- Bulk upload progress bars now render correctly in the frontend.
- Upload requests now include credentials and improved path handling for reliable authenticated uploads.

## v2.0.1 - 2026-02-13

### Added
- Electron login `Remember me` option restored and persisted through config/session IPC.
- Background daemon behavior restored in Electron:
  - Run in background on close (optional).
  - Minimize to tray (optional).
  - Launch to tray (optional).
  - Start with system toggle wiring.
- Tray menu actions restored (`Open`, `Hide To Tray`, `Quit`).

### Fixed
- Session persistence flow in Electron no longer depends only on `localStorage`.
- Duplicate app instance behavior reduced with single-instance lock in Electron.

## v2.0.0 - 2026-02-13

### Added
- Multi-user accounts with roles (`admin`, `user`).
- Admin user management API and UI:
  - Create users with temporary passwords.
  - Force password change on first login.
- Per-user save isolation on server:
  - Saves now scoped under user directories.
  - Legacy save migration support for existing installs.
- Save version history:
  - List versions for a save.
  - Restore specific version.
- Game-level save discovery:
  - `Game Saves` action from game cards.
  - `GET /api/game-saves` endpoint.
- Switch save ID mapping support:
  - `data/switch_save_map.json`.
  - Admin APIs:
    - `GET /api/admin/switch-save-map`
    - `POST /api/admin/switch-save-map`
- Switch title matching improvements:
  - Parse title IDs from save paths.
  - Metadata fallback title ID matching.
- Conflict UX improvements:
  - Better labels and timestamps.
  - Per-item and bulk actions (`Keep Local`, `Keep Cloud`, `Keep All`).
- Frontend + Electron visual redesign to match website style.

### Changed
- Authentication/session flow improved:
  - Persistent session token handling in Electron.
  - Better auth status checks.
- Sync behavior hardened:
  - Auto-sync guarded by authenticated state.
  - Conflict checks improved with better comparison logic.
- Save scanning/classification improvements:
  - Better Wii and Switch save title labeling.
  - Better grouping and identification in UI.
- Electron cache/session handling updated to reduce startup cache errors.
- UI modernized across web and Electron while keeping existing features.

### Fixed
- `docker-compose` YAML parsing issues in project config.
- Renderer syntax issue (`Unexpected identifier 'showToast'`).
- `Unexpected token '<'` when loading game saves (error handling hardening).
- Hashing bug for files between 1MB and 2MB:
  - Fixed out-of-range read length causing hash failures.
- Conflict action button color contrast and readability issues.
- Multiple cases where conflict modal appeared in invalid states.

### Sync Filtering
- Excluded noisy/system files from sync/conflict workflow (emulator/system metadata, backup/system paths, test files), reducing false conflicts.

### Migration / Notes
- Existing installs continue to work; legacy saves are migrated to user-scoped storage.
- If Switch saves use abstract slot IDs (for example `000000000000000X`), add mappings in `data/switch_save_map.json` so game-to-save linking is accurate.
