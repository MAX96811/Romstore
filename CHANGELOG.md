# Changelog

## v2.2.0 - 2026-08-31

### Added
- Full gamepad navigation in the desktop client. The d-pad or left stick moves focus to the nearest control in that direction, A activates it, B closes the open dialog (or clears the search box), LB/RB step through the system filters, and Start opens Settings — so the client is usable from Steam Big Picture on a TV with no mouse or keyboard. Focus is confined to the topmost open dialog while one is up, and the focus ring only appears once a controller has actually been used, so nothing changes for mouse users.
- `deploy/udev/65-xbox-bt-joystick-fix.rules`, for the Bluetooth Xbox Wireless Controller. Linux's default `input_id` heuristic does not tag it `ID_INPUT_JOYSTICK`, which hides it from the Gamepad API entirely when the client is run standalone. Launching RomStore through Steam avoids this, since Steam Input's virtual pad is tagged correctly.

## v2.1.5 - 2026-08-19

### Added
- Offline mode works on a cold start. With no cached listing — a fresh install, or a client that has never reached the server — the library is rebuilt from the ROMs on disk, applying the same rules the server uses (each platform's `systeminfo.txt` extensions, and the same ignored directories), so offline mode does not depend on having been online first.
- Offline mode. If the RomStore server cannot be reached, the client no longer stops at a login box it has no way of satisfying. It falls back to the last cached library, still scans local files, and still launches installed games — everything needed to play is local already. A banner states how old the cached listing is, and the client re-probes the server every 30 seconds (or on demand) and rejoins automatically.
- The Switch auto-sync queue is persisted to disk. Saves made while the server was down, or during a session that ended in a crash rather than a clean exit, are uploaded once the server returns instead of being lost with the process.

### Changed
- Server-only actions (download, upload, Switch backup/restore, Title ID relinking) are refused with an explanatory message while offline, rather than failing obscurely. Launching and uninstalling stay available, since neither touches the server.

### Fixed
- Offline is distinguished from unauthorized. Only a failed connection triggers offline mode; any real HTTP response, 401 included, still routes to the login screen, so an auth problem is never hidden behind an offline banner.

## v2.1.4 - 2026-08-19

### Security
- `.env` is no longer baked into the backend image. `.dockerignore` excluded `client`, `frontend` and `.git` but not `.env`, so `COPY . .` shipped a live `SESSION_SECRET` inside every published image.
- `.env` is no longer tracked in git. It was committed to a public repository, so the previous `SESSION_SECRET` must be treated as disclosed and has been rotated.
- The session secret is now supplied to the container through its environment rather than a file in the image. `server.js` falls back to `crypto.randomBytes(32)` when `SESSION_SECRET` is unset, which would silently regenerate the secret on every restart and invalidate all sessions, so the value has to be injected by the deployment.

## v2.1.3 - 2026-08-18

### Added
- Automatic Switch save sync. Enabling auto-sync now also watches the live Ryujinx save root; slots that change while you play are queued and uploaded as complete bundles once Ryujinx exits and the files settle. Previously the auto-sync toggle silently covered no Switch game at all, because Ryujinx paths are excluded from the per-file watcher by design.
- Auto-sync covers every slot with a readable Title ID, so a game does not have to be linked in the library first.
- Toasts reporting each automatic bundle upload, and a failure notice once a slot has exhausted its retries.

### Fixed
- Server: a Switch slot that changed hands is now adopted instead of rejected. Ryujinx reuses slot numbers across games, so an upload whose Title ID disagreed with the slot's previous owner was refused outright, permanently stranding every future upload for that slot. The previous contents are archived under their own Title ID and the incoming bundle goes live, so neither game loses history. Without this, automatic sync fails for exactly the slots Ryujinx has reassigned.
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
