# Changelog

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
