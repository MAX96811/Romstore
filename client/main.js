const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { execFileSync, spawn } = require('child_process');
const {
    listProfiles,
    sanitizeLaunchEnvironment,
    selectProfile
} = require('./emudeck');
const { normalizeSaveRelativePath, scanDirectoryStats, scanLocalEmulation } = require('./local-library');
const { collectSwitchBundleFiles, discoverSwitchAssociations, matchSwitchTitleId, readSlotTitleId, resolveRyujinxUserRoot, resolveSwitchSlotsRoot } = require('./switch-library');
const { createSwitchAutoSync, slotIdFromRelativePath } = require('./switch-autosync');
const { restoreSwitchBundle } = require('./switch-save-restore');

app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
app.commandLine.appendSwitch('disable-http-cache');

let mainWindow = null;
let tray = null;
let isQuitting = false;

const singleInstanceLock = app.requestSingleInstanceLock();
if (!singleInstanceLock) {
    app.quit();
}

const sessionDataPath = path.join(app.getPath('userData'), 'session-data');
if (!fs.existsSync(sessionDataPath)) fs.mkdirSync(sessionDataPath, { recursive: true });
app.setPath('sessionData', sessionDataPath);

function getConfigPath() {
    return path.join(app.getPath('userData'), 'config.json');
}

function getConfig() {
    const configPath = getConfigPath();
    if (!fs.existsSync(configPath)) return {};
    try {
        return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {
        console.error('[Config] Failed to parse config.json:', e.message);
        return {};
    }
}

function saveConfig(configPatch) {
    const configPath = getConfigPath();
    const current = getConfig();
    const next = { ...current, ...(configPatch || {}) };
    fs.writeFileSync(configPath, JSON.stringify(next, null, 2));
    return next;
}

function getTrayIconPath() {
    return path.join(__dirname, 'renderer', 'LOGO.png');
}

function ensureTray() {
    if (tray) return tray;
    const icon = nativeImage.createFromPath(getTrayIconPath());
    tray = new Tray(icon);
    tray.setToolTip('RomStore');
    tray.on('double-click', () => {
        if (!mainWindow) return;
        mainWindow.show();
        mainWindow.focus();
        mainWindow.webContents.send('visibility-changed', { hidden: false });
    });
    return tray;
}

function updateTrayMenu() {
    if (!tray) return;
    const menu = Menu.buildFromTemplate([
        {
            label: 'Open RomStore',
            click: () => {
                if (!mainWindow) return;
                mainWindow.show();
                mainWindow.focus();
                mainWindow.webContents.send('visibility-changed', { hidden: false });
            }
        },
        {
            label: 'Hide To Tray',
            click: () => {
                if (!mainWindow) return;
                mainWindow.hide();
                mainWindow.webContents.send('visibility-changed', { hidden: true });
            }
        },
        { type: 'separator' },
        {
            label: 'Quit',
            click: () => {
                isQuitting = true;
                app.quit();
            }
        }
    ]);
    tray.setContextMenu(menu);
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#121212',
        icon: path.join(__dirname, 'renderer', 'LOGO.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    // In production we would load the file. 
    // For now, it will load our local copy of the UI
    mainWindow.loadFile('renderer/index.html');
    // mainWindow.webContents.openDevTools();

    mainWindow.on('close', (event) => {
        const cfg = getConfig();
        const keepInBackground = !!cfg.keepInBackground;
        if (!isQuitting && keepInBackground) {
            event.preventDefault();
            mainWindow.hide();
            ensureTray();
            updateTrayMenu();
            mainWindow.webContents.send('visibility-changed', { hidden: true });
        }
    });

    mainWindow.on('minimize', (event) => {
        const cfg = getConfig();
        if (cfg.minimizeToTray) {
            event.preventDefault();
            mainWindow.hide();
            ensureTray();
            updateTrayMenu();
            mainWindow.webContents.send('visibility-changed', { hidden: true });
        }
    });

    mainWindow.on('show', () => {
        if (!mainWindow) return;
        mainWindow.webContents.send('visibility-changed', { hidden: false });
    });
}

app.on('second-instance', () => {
    if (mainWindow) {
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.show();
        mainWindow.focus();
    }
});

app.whenReady().then(() => {
    createWindow();

    const cfg = getConfig();
    app.setLoginItemSettings({ openAtLogin: !!cfg.startWithSystem });
    if (cfg.keepInBackground || cfg.minimizeToTray) {
        ensureTray();
        updateTrayMenu();
    }
    if (cfg.launchToTray && mainWindow) {
        mainWindow.hide();
        mainWindow.webContents.send('visibility-changed', { hidden: true });
    }
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
    isQuitting = true;
});

// IPC Handlers for Local File Operations
ipcMain.handle('select-dirs', async () => {
    const result = await dialog.showOpenDialog({
        properties: ['openDirectory']
    });
    return result.filePaths[0];
});

ipcMain.handle('scan-local-emulation', async (event, baseDir) => {
    try {
        const results = scanLocalEmulation(baseDir);
        console.log('[Scan] Total files found:', results.length);
        return results;
    } catch (e) {
        console.error('[Scan] Walk failed:', e);
        return [];
    }
});

ipcMain.handle('scan-dir-stat', async (event, baseDir) => {
    try {
        return scanDirectoryStats(baseDir);
    } catch (e) {
        console.error("Scan Stat failed", e);
        return [];
    }
});

ipcMain.handle('get-switch-associations', async (event, localDir) => {
    try {
        return discoverSwitchAssociations({
            homeDir: app.getPath('home'),
            emulationDir: localDir || getConfig().localDir
        });
    } catch (error) {
        console.error('[Switch] Association discovery failed:', error);
        return { games: [], slots: [], error: error.message };
    }
});

ipcMain.handle('get-switch-title-id', async (event, payload) => {
    try {
        const associations = discoverSwitchAssociations({
            homeDir: app.getPath('home'),
            emulationDir: payload?.localDir || getConfig().localDir
        });
        return matchSwitchTitleId(payload?.game || {}, associations);
    } catch (error) {
        console.error('[Switch] Title matching failed:', error);
        return null;
    }
});

function isRyujinxRunning() {
    try {
        if (process.platform === 'linux') {
            return fs.readdirSync('/proc')
                .filter(name => /^\d+$/.test(name))
                .some(pid => {
                    try {
                        const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8');
                        const commandLine = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ');
                        return /(?:^|[\/\s])(ryujinx|ryubing)(?:[\/\s.]|$)/i.test(`${comm} ${commandLine}`);
                    } catch (error) {
                        return false;
                    }
                });
        }
        if (process.platform === 'win32') {
            return /ryujinx|ryubing/i.test(execFileSync('tasklist', ['/FO', 'CSV', '/NH'], { encoding: 'utf8' }));
        }
        return /ryujinx|ryubing/i.test(execFileSync('ps', ['-ax', '-o', 'comm='], { encoding: 'utf8' }));
    } catch (error) {
        // Failing closed prevents a restore when emulator state cannot be checked.
        console.error('[Switch Restore] Could not inspect running processes:', error.message);
        return true;
    }
}

ipcMain.handle('restore-switch-bundle', async (event, payload) => {
    const config = getConfig();
    const localDir = String(config.localDir || '');
    const ryujinxUserRoot = resolveRyujinxUserRoot({ homeDir: app.getPath('home'), emulationDir: localDir });
    let serverUrl = String(config.serverUrl || 'http://localhost:3000').replace(/\/+$/, '');
    if (serverUrl && !serverUrl.startsWith('http')) serverUrl = 'http://' + serverUrl;

    try {
        return await restoreSwitchBundle({
            localDir,
            ryujinxUserRoot,
            slotId: payload?.slotId,
            files: payload?.files,
            isRyujinxRunning,
            downloadFile: async (file, destination) => {
                const response = await axios.get(
                    `${serverUrl}/api/download?type=saves&path=${encodeURIComponent(file.relPath)}`,
                    {
                        responseType: 'arraybuffer',
                        headers: payload?.sessionToken ? { 'X-Session-Token': payload.sessionToken } : {}
                    }
                );
                fs.writeFileSync(destination, Buffer.from(response.data));
            }
        });
    } catch (error) {
        console.error('[Switch Restore] Failed:', error);
        return { success: false, error: error.message };
    }
});

// Shared by the manual "Snapshot slot" button and by auto-sync, so both paths
// get the same identity checks, the same mid-write abort, and the same
// all-or-nothing upload.
async function uploadSwitchBundle(payload) {
    const config = getConfig();
    const localDir = String(config.localDir || '');
    let serverUrl = String(config.serverUrl || 'http://localhost:3000').replace(/\/+$/, '');
    if (serverUrl && !serverUrl.startsWith('http')) serverUrl = 'http://' + serverUrl;
    if (isRyujinxRunning()) return { success: false, error: 'Close Ryujinx before backing up a Switch save.' };

    let snapshotDir = null;
    try {
        const files = collectSwitchBundleFiles(localDir, payload?.slotId, app.getPath('home'));
        snapshotDir = fs.mkdtempSync(path.join(app.getPath('temp'), 'romstore-switch-backup-'));
        const snapshotFiles = files.map((file, index) => {
            const before = fs.statSync(file.fullPath);
            const snapshotPath = path.join(snapshotDir, String(index).padStart(4, '0'));
            fs.copyFileSync(file.fullPath, snapshotPath);
            const after = fs.statSync(file.fullPath);
            if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
                throw new Error(`Ryujinx save changed while snapshotting ${file.relPath}. Try again with Ryujinx closed.`);
            }
            return { ...file, fullPath: snapshotPath };
        });
        if (isRyujinxRunning()) {
            throw new Error('Ryujinx was opened while the backup snapshot was being created. Close it and try again.');
        }
        const FormData = require('form-data');
        const form = new FormData();
        form.append('slotId', String(payload?.slotId || ''));
        form.append('titleId', String(payload?.titleId || ''));
        form.append('relPaths', JSON.stringify(snapshotFiles.map(file => file.relPath)));
        for (const file of snapshotFiles) {
            form.append('files', fs.createReadStream(file.fullPath), path.basename(file.fullPath));
        }

        const response = await axios.post(`${serverUrl}/api/saves/switch-bundle/upload?type=saves`, form, {
            headers: {
                ...form.getHeaders(),
                ...(payload?.sessionToken ? { 'X-Session-Token': payload.sessionToken } : {})
            },
            maxBodyLength: Infinity,
            maxContentLength: Infinity
        });
        return response.data || { success: response.status === 200 };
    } catch (error) {
        console.error('[Switch Backup] Failed:', error.response?.data || error.message);
        return { success: false, error: error.response?.data?.error || error.message };
    } finally {
        if (snapshotDir && fs.existsSync(snapshotDir)) {
            try { fs.rmSync(snapshotDir, { recursive: true, force: true }); } catch (error) { }
        }
    }
}

ipcMain.handle('backup-switch-bundle', async (event, payload) => uploadSwitchBundle(payload));

ipcMain.handle('download-file', async (event, { url, destPath, sessionToken, relPath }) => {
    // Ensure directory exists
    const dir = path.dirname(destPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    const writer = fs.createWriteStream(destPath);
    const headers = {};
    if (sessionToken) headers['X-Session-Token'] = sessionToken;

    const response = await axios({
        url,
        method: 'GET',
        responseType: 'stream',
        headers: headers
    });

    const totalLengthValue = Number.parseInt(response.headers['content-length'] || '0', 10);
    const totalLength = Number.isFinite(totalLengthValue) && totalLengthValue > 0 ? totalLengthValue : 0;
    let downloaded = 0;
    let lastPercent = -1;
    let lastSampleTime = Date.now();
    let lastSampleBytes = 0;

    response.data.on('data', (chunk) => {
        downloaded += chunk.length;
        if (relPath) {
            const now = Date.now();
            const elapsedSeconds = Math.max((now - lastSampleTime) / 1000, 0.001);
            const sampledBytes = downloaded - lastSampleBytes;
            const bytesPerSec = Math.max(0, Math.round(sampledBytes / elapsedSeconds));
            const percent = totalLength > 0 ? Math.round((downloaded / totalLength) * 100) : -1;

            // Emit either on visible percent change or at least every 300ms for speed updates.
            if (percent > lastPercent || now - lastSampleTime >= 300) {
                lastPercent = percent;
                event.sender.send('download-progress', {
                    relPath,
                    percent,
                    bytesPerSec,
                    downloadedBytes: downloaded,
                    totalBytes: totalLength || null
                });
                lastSampleTime = now;
                lastSampleBytes = downloaded;
            }
        }
    });

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', () => {
            if (relPath) {
                event.sender.send('download-progress', {
                    relPath,
                    percent: 100,
                    bytesPerSec: 0,
                    downloadedBytes: downloaded,
                    totalBytes: totalLength || downloaded || null
                });
            }
            resolve();
        });
        writer.on('error', reject);
    });
});

ipcMain.handle('check-local-file', (event, filePath) => {
    return fs.existsSync(filePath);
});

ipcMain.handle('delete-file', async (event, filePath) => {
    if (!filePath) return false;
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            return true;
        }
        return false;
    } catch (e) {
        console.error('Delete failed', e);
        return false;
    }
});

ipcMain.handle('backup-local-file', async (event, filePath) => {
    if (!fs.existsSync(filePath)) return false;
    try {
        const dir = path.dirname(filePath);
        const oldSaveDir = path.join(dir, '.oldsave');
        if (!fs.existsSync(oldSaveDir)) fs.mkdirSync(oldSaveDir, { recursive: true });

        const filename = path.basename(filePath);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = path.join(oldSaveDir, `${timestamp}_${filename}`);

        fs.copyFileSync(filePath, backupPath);
        return true;
    } catch (e) {
        console.error('Backup failed', e);
        return false;
    }
});

ipcMain.handle('get-config', () => getConfig());

ipcMain.handle('save-config', (event, config) => {
    const next = saveConfig(config);
    app.setLoginItemSettings({ openAtLogin: !!next.startWithSystem });
    if (next.keepInBackground || next.minimizeToTray) {
        ensureTray();
        updateTrayMenu();
    } else if (tray) {
        tray.destroy();
        tray = null;
    }
    return next;
});

ipcMain.handle('get-emulator-profiles', async (event, localDir) => {
    const emulationDir = localDir || getConfig().localDir;
    if (!emulationDir) {
        return { detected: false, profiles: [], error: 'Set the local Emulation directory first.' };
    }

    try {
        const config = getConfig();
        return listProfiles({
            homeDir: app.getPath('home'),
            emulationDir,
            overrides: config.emulatorProfiles || {}
        });
    } catch (error) {
        console.error('[EmuDeck] Profile discovery failed:', error);
        return { detected: false, profiles: [], error: error.message };
    }
});

ipcMain.handle('save-emulator-profile', async (event, payload) => {
    const system = String(payload && payload.system || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const command = String(payload && payload.command || '').trim();
    const label = String(payload && payload.label || 'Custom profile').trim().slice(0, 80);
    if (!system) return { success: false, error: 'Choose a platform first.' };
    if (command && !/(?:%ROM%|\{rom\}|\{file\})/i.test(command)) {
        return { success: false, error: 'Custom commands must contain {rom} or %ROM%.' };
    }

    const config = getConfig();
    const emulatorProfiles = { ...(config.emulatorProfiles || {}) };
    if (command) emulatorProfiles[system] = { label, command };
    else delete emulatorProfiles[system];
    saveConfig({ emulatorProfiles });
    return { success: true, emulatorProfiles };
});

ipcMain.handle('launch-game', async (event, payload) => {
    const config = getConfig();
    const emulationDir = String(payload && payload.localDir || config.localDir || '');
    const relPath = String(payload && payload.relPath || '').replace(/\\/g, '/');
    if (!emulationDir || !relPath) return { success: false, error: 'Missing local Emulation directory or game path.' };

    const romRoot = path.resolve(emulationDir, 'roms');
    const romPath = path.resolve(romRoot, relPath);
    if (!romPath.startsWith(romRoot + path.sep)) return { success: false, error: 'Invalid game path.' };
    if (!fs.existsSync(romPath)) return { success: false, error: 'Install the game before launching it.' };
    try {
        if (!fs.statSync(romPath).isFile()) return { success: false, error: 'Directory-based games are not launchable yet.' };
    } catch (error) {
        return { success: false, error: `Cannot access the installed game: ${error.message}` };
    }

    const system = (relPath.split('/')[0] || payload.system || '').toLowerCase();
    const profile = selectProfile(system, {
        homeDir: app.getPath('home'),
        emulationDir,
        romPath,
        overrides: config.emulatorProfiles || {}
    });
    if (!profile.available || !profile.resolved) {
        return { success: false, error: profile.error || `No usable EmuDeck emulator was found for ${system}.` };
    }

    try {
        const child = spawn(profile.resolved.command, profile.resolved.args, {
            cwd: fs.existsSync(profile.resolved.cwd) ? profile.resolved.cwd : app.getPath('home'),
            detached: true,
            stdio: 'ignore',
            env: sanitizeLaunchEnvironment(process.env)
        });

        await new Promise((resolve, reject) => {
            const timeout = setTimeout(resolve, 750);
            child.once('spawn', () => {
                clearTimeout(timeout);
                resolve();
            });
            child.once('error', error => {
                clearTimeout(timeout);
                reject(error);
            });
        });
        child.unref();
        console.log(`[Launch] ${system} via ${profile.label}:`, profile.resolved.command, profile.resolved.args);
        return { success: true, system, profile: profile.label };
    } catch (error) {
        console.error('[Launch] Failed:', error);
        return { success: false, error: `Failed to start ${profile.label}: ${error.message}` };
    }
});

ipcMain.handle('check-session', () => {
    const cfg = getConfig();
    return {
        token: cfg.rememberMe ? (cfg.savedSessionToken || '') : '',
        rememberMe: !!cfg.rememberMe
    };
});

ipcMain.handle('set-session', (event, payload) => {
    const data = (payload && typeof payload === 'object') ? payload : { token: payload };
    const rememberMe = !!data.rememberMe;
    const token = data.token || '';
    saveConfig({
        rememberMe,
        savedSessionToken: rememberMe && token ? token : ''
    });
    return true;
});

ipcMain.handle('enter-daemon-mode', () => {
    if (!mainWindow) return false;
    ensureTray();
    updateTrayMenu();
    mainWindow.hide();
    mainWindow.webContents.send('visibility-changed', { hidden: true });
    return true;
});

// --- SAVE SYNC & WATCHER ---
let saveWatcher = null;
const uploadDebounceMap = new Map();

ipcMain.handle('start-save-watcher', async (event, saveDir) => {
    // Check if already watching this directory to avoid redundant restarts
    if (saveWatcher && saveWatcher.getWatched()[saveDir]) {
        console.log('[Watcher] Already watching:', saveDir);
        return true;
    }

    if (saveWatcher) {
        await saveWatcher.close();
        saveWatcher = null;
    }
    if (!fs.existsSync(saveDir)) return false;

    console.log('[Watcher] Starting (Chokidar) on:', saveDir);
    try {
        const { watch } = await import('chokidar');
        saveWatcher = watch(saveDir, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
            persistent: true,
            ignoreInitial: true,
            awaitWriteFinish: {
                stabilityThreshold: 2000,
                pollInterval: 100
            }
        });

        saveWatcher.on('all', (eventName, filePath) => {
            // Only care about adds and changes to files
            if (eventName !== 'add' && eventName !== 'change') return;
            try {
                if (fs.statSync(filePath).isDirectory()) return;
            } catch (e) {
                return;
            }

            // Debounce uploads per file to handle rapid successive writes
            if (uploadDebounceMap.has(filePath)) {
                clearTimeout(uploadDebounceMap.get(filePath));
            }

            const timer = setTimeout(() => {
                console.log(`[Watcher] ${eventName} (debounced): ${filePath}`);
                const rel = normalizeSaveRelativePath(path.relative(saveDir, filePath));
                if (!rel) {
                    console.warn('[Watcher] Rejected invalid save path:', filePath);
                    uploadDebounceMap.delete(filePath);
                    return;
                }
                event.sender.send('save-change', {
                    relPath: rel,
                    fullPath: filePath
                });
                uploadDebounceMap.delete(filePath);
            }, 1000);

            uploadDebounceMap.set(filePath, timer);
        });

        return true;
    } catch (e) {
        console.error('[Watcher] Failed:', e);
        return false;
    }
});

ipcMain.handle('stop-save-watcher', async () => {
    if (saveWatcher) {
        await saveWatcher.close();
        saveWatcher = null;
    }
    return true;
});

// --- SWITCH AUTO-SYNC ---
// The per-file watcher above deliberately refuses Ryujinx paths, so Switch
// saves get their own watcher: it only records which slots changed, and defers
// every upload until Ryujinx has exited and the slot has settled.
let switchWatcher = null;
let switchAutoSync = null;
let switchSessionToken = '';

// The queue outlives the process so that saves made while the server was
// unreachable - or while Ryujinx crashed before a flush - are still uploaded.
function switchQueuePath() {
    return path.join(app.getPath('userData'), 'switch-autosync-queue.json');
}

function readSwitchQueue() {
    try {
        const parsed = JSON.parse(fs.readFileSync(switchQueuePath(), 'utf8'));
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        return [];
    }
}

function writeSwitchQueue(slotIds) {
    try {
        if (!Array.isArray(slotIds) || !slotIds.length) {
            if (fs.existsSync(switchQueuePath())) fs.unlinkSync(switchQueuePath());
            return;
        }
        fs.writeFileSync(switchQueuePath(), JSON.stringify(slotIds));
    } catch (error) {
        console.error('[Switch AutoSync] Could not persist the queue:', error.message);
    }
}

function switchAutoSyncStatus(payload) {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('switch-autosync', payload);
    }
}

ipcMain.handle('start-switch-autosync', async (event, sessionToken) => {
    switchSessionToken = String(sessionToken || '');
    const config = getConfig();
    const slotsRoot = resolveSwitchSlotsRoot({
        homeDir: app.getPath('home'),
        emulationDir: String(config.localDir || '')
    });
    if (!slotsRoot || !fs.existsSync(slotsRoot)) {
        return { success: false, error: 'No Ryujinx save directory was found on this PC.' };
    }
    if (switchWatcher) return { success: true, slotsRoot };

    if (!switchAutoSync) {
        switchAutoSync = createSwitchAutoSync({
            isEmulatorRunning: () => isRyujinxRunning(),
            uploadBundle: async slotId => {
                const titleId = readSlotTitleId(slotsRoot, slotId);
                if (!titleId) return { success: false, error: `Slot ${slotId} has no readable Title ID.` };
                return uploadSwitchBundle({ slotId, titleId, sessionToken: switchSessionToken });
            },
            onResult: result => switchAutoSyncStatus(result),
            persistPending: writeSwitchQueue,
            restorePending: readSwitchQueue
        });
    }

    // A queue restored from disk has no timer running yet, and the emulator may
    // not touch those slots again for days. Start it explicitly.
    const resumed = switchAutoSync.resumePending();
    if (resumed.length) {
        console.log('[Switch AutoSync] Resuming queued slots from a previous session:', resumed.join(', '));
        switchAutoSyncStatus({ resumed: resumed.length });
    }

    try {
        const { watch } = await import('chokidar');
        switchWatcher = watch(slotsRoot, {
            persistent: true,
            ignoreInitial: true,
            // NOTE: a naive /(^|[\/\\])\../ ignore matches nothing here on Linux -
            // the Flatpak root itself lives under ~/.var, so it would silently
            // ignore the entire tree. Only path segments *below* the slots root
            // are tested, which still skips .oldsave, .lock and our own backups.
            ignored: targetPath => {
                const relative = path.relative(slotsRoot, targetPath);
                if (!relative) return false;
                return relative.split(path.sep).some(part => part.startsWith('.'));
            },
            awaitWriteFinish: { stabilityThreshold: 2000, pollInterval: 100 }
        });

        switchWatcher.on('all', (eventName, filePath) => {
            if (eventName !== 'add' && eventName !== 'change') return;
            const slotId = slotIdFromRelativePath(path.relative(slotsRoot, filePath));
            if (!slotId) return;
            if (switchAutoSync.markDirty(slotId)) {
                console.log('[Switch AutoSync] Slot queued:', slotId);
                switchAutoSyncStatus({ slotId, queued: true });
            }
        });

        console.log('[Switch AutoSync] Watching:', slotsRoot);
        return { success: true, slotsRoot };
    } catch (error) {
        console.error('[Switch AutoSync] Failed to start:', error);
        return { success: false, error: error.message };
    }
});

ipcMain.handle('stop-switch-autosync', async () => {
    if (switchWatcher) {
        await switchWatcher.close();
        switchWatcher = null;
    }
    if (switchAutoSync) switchAutoSync.stop();
    switchSessionToken = '';
    return true;
});

ipcMain.handle('upload-save', async (event, { filePath, relPath, sessionToken }) => {
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found' };

    try {
        if (fs.statSync(filePath).isDirectory()) return { success: false, error: 'Skipped directory' };
    } catch (e) { return { success: false, error: 'File access failed' }; }

    const safeRelPath = normalizeSaveRelativePath(relPath);
    if (!safeRelPath) return { success: false, error: 'Invalid save path' };

    // Check config for server URL
    const configPath = path.join(app.getPath('userData'), 'config.json');
    let serverUrl = 'http://localhost:3000';
    if (fs.existsSync(configPath)) {
        const conf = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (conf.serverUrl) serverUrl = conf.serverUrl;
    }
    serverUrl = serverUrl.replace(/\/+$/, '');

    try {
        const FormData = require('form-data');
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));
        form.append('relPath', safeRelPath);

        const res = await axios.post(`${serverUrl}/api/saves/upload?type=saves`, form, {
            headers: {
                ...form.getHeaders(),
                'X-Session-Token': sessionToken
            }
        });
        return { success: res.status === 200, ...(res.data || {}) };
    } catch (e) {
        console.error('[Upload] Failed:', e.message);
        return { success: false, error: e.message };
    }
});
