const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage, Notification } = require('electron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');

// CLI Arguments
const isDaemon = process.argv.includes('--daemon');

let mainWindow = null;
let tray = null;
let backgroundSyncInterval = null;
let isQuitting = false;
let sessionToken = null; // Store session token in memory for Daemon

// Manifest & Config Paths
const userDataPath = app.getPath('userData');
const configPath = path.join(userDataPath, 'config.json');
const manifestPath = path.join(userDataPath, 'sync_manifest.json');
const sessionPath = path.join(userDataPath, 'session.json');

// --- Helper Functions ---

function loadConfig() {
    if (fs.existsSync(configPath)) {
        try { return JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) { return {}; }
    }
    return {};
}

function saveConfig(config) {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

function loadManifest() {
    if (fs.existsSync(manifestPath)) {
        try { return JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (e) { return {}; }
    }
    return {};
}

function saveManifest(manifest) {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
}

function loadSession() {
    if (fs.existsSync(sessionPath)) {
        try {
            const s = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
            sessionToken = s.token;
        } catch (e) { }
    }
}

function saveSession(token) {
    sessionToken = token;
    fs.writeFileSync(sessionPath, JSON.stringify({ token }, null, 2));
}

function getServerUrl() {
    const cfg = loadConfig();
    return cfg.serverUrl || 'http://localhost:3000';
}

function getLocalDir() {
    const cfg = loadConfig();
    return cfg.localDir;
}

// --- Sync Logic (Moved to Main) ---

async function downloadFileMain(url, destPath, relPath) {
    const dir = path.dirname(destPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const writer = fs.createWriteStream(destPath);
    const headers = {};
    if (sessionToken) headers['X-Session-Token'] = sessionToken;

    const response = await axios({
        url, method: 'GET', responseType: 'stream', headers
    });

    const totalLength = response.headers['content-length'];
    let downloaded = 0;

    // If window is open, send progress
    response.data.on('data', (chunk) => {
        downloaded += chunk.length;
        if (mainWindow && totalLength) {
            const percent = Math.round((downloaded / totalLength) * 100);
            mainWindow.webContents.send('download-progress', { relPath, percent });
        }
    });

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
    });
}

function backupLocalFileMain(filePath) {
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
}

async function uploadFileMain(filePath, relPath) {
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found' };
    const serverUrl = getServerUrl();

    try {
        const form = new FormData();
        const stat = fs.statSync(filePath);
        form.append('file', fs.createReadStream(filePath));
        form.append('relPath', relPath);
        form.append('mtime', stat.mtime.getTime().toString());

        const res = await axios.post(`${serverUrl}/api/saves/upload?type=saves`, form, {
            headers: { ...form.getHeaders(), 'X-Session-Token': sessionToken }
        });
        return { success: res.status === 200 };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

async function scanDirStatMain(baseDir) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];

    function walk(dir, results = []) {
        const list = fs.readdirSync(dir);
        list.forEach(file => {
            if (file.startsWith('.') || file.toLowerCase().endsWith('.txt')) return;
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat && stat.isDirectory()) {
                walk(fullPath, results);
            } else {
                const rel = path.relative(baseDir, fullPath).replace(/\\/g, '/');
                results.push({ relPath: rel, mtime: stat.mtime });
            }
        });
        return results;
    }
    return walk(baseDir);
}

async function performSync(silent = true) {
    const localDir = getLocalDir();
    const serverUrl = getServerUrl();

    if (!localDir || !sessionToken) {
        console.log('[Sync] Missing config/token, skipping.');
        return;
    }

    // Lock Sync
    if (isSyncing) {
        console.log('[Sync] Already syncing in internal loop, skipping new request.');
        return;
    }
    isSyncing = true;

    console.log(`[Sync] Starting (${silent ? 'Silent' : 'Manual'})...`);
    if (!silent && mainWindow) mainWindow.webContents.send('sync-status', { msg: 'Scanning...', type: 'info' });

    try {
        // Fetch Server State
        const res = await axios.get(`${serverUrl}/api/saves`, { headers: { 'X-Session-Token': sessionToken } });
        const serverSaves = res.data;
        const localSaves = await scanDirStatMain(path.join(localDir, 'saves'));
        const manifest = loadManifest();

        const serverMap = new Map();
        serverSaves.forEach(s => serverMap.set(s.relPath, new Date(s.mtime).getTime()));
        const localMap = new Map();
        localSaves.forEach(l => localMap.set(l.relPath, new Date(l.mtime).getTime()));

        const allPaths = new Set([...serverMap.keys(), ...localMap.keys()]);
        const conflicts = [];
        let dlCount = 0, ulCount = 0;

        for (const relPath of allPaths) {
            const sTime = serverMap.get(relPath);
            const lTime = localMap.get(relPath);
            const mEntry = manifest[relPath];

            const fullPath = path.join(localDir, 'saves', relPath);
            const downloadUrl = `${serverUrl}/api/download?type=saves&path=${encodeURIComponent(relPath)}`;

            // Helper to update manifest
            const updateM = (lt, st) => { manifest[relPath] = { l: lt, s: st }; };

            // 1. New on Server
            if (lTime === undefined && sTime !== undefined) {
                if (!mEntry || !mEntry.l) {
                    await downloadFileMain(downloadUrl, fullPath, relPath);
                    const newStat = fs.statSync(fullPath);
                    updateM(newStat.mtime.getTime(), sTime);
                    dlCount++;
                }
                continue;
            }

            // 2. New on Local
            if (sTime === undefined && lTime !== undefined) {
                if (!mEntry || !mEntry.s) {
                    await uploadFileMain(fullPath, relPath);
                    // Assume server accepted it, update manifest with current local time as both
                    // Ideally we get server mtime back, but for now allow 2s variance sync next time
                    updateM(lTime, lTime);
                    ulCount++;
                }
                continue;
            }

            // 3. Exists on Both
            const lastL = mEntry ? mEntry.l : 0;
            const lastS = mEntry ? mEntry.s : 0;
            const localChanged = lTime !== undefined && Math.abs(lTime - lastL) > 2000;
            const serverChanged = sTime !== undefined && Math.abs(sTime - lastS) > 2000;

            if (!mEntry) {
                if (Math.abs(lTime - sTime) > 2000) conflicts.push({ path: relPath, lTime, sTime });
                else updateM(lTime, sTime);
                continue;
            }

            if (localChanged && serverChanged) {
                conflicts.push({ path: relPath, lTime, sTime });
            } else if (localChanged) {
                await uploadFileMain(fullPath, relPath);
                updateM(lTime, lTime); // approx
                ulCount++;
            } else if (serverChanged) {
                backupLocalFileMain(fullPath);
                await downloadFileMain(downloadUrl, fullPath, relPath);
                const newStat = fs.statSync(fullPath);
                updateM(newStat.mtime.getTime(), sTime);
                dlCount++;
            }
        }

        saveManifest(manifest);

        if (conflicts.length > 0) {
            console.log('[Sync] Conflicts found:', conflicts);
            if (!silent && mainWindow) {
                mainWindow.webContents.send('sync-conflict', conflicts);
            } else if (isDaemon) {
                // In Daemon mode, we might want to notify via OS notification
                new Notification({ title: 'RomStore Conflict', body: `${conflicts.length} files in conflict. Open app to resolve.` }).show();
            }
        } else if (dlCount > 0 || ulCount > 0) {
            console.log(`[Sync] Synced: ${dlCount} Down, ${ulCount} Up`);
            if (mainWindow) mainWindow.webContents.send('sync-status', { msg: `Synced: ${dlCount} ↓, ${ulCount} ↑`, type: 'success' });
        } else {
            if (!silent && mainWindow) mainWindow.webContents.send('sync-status', { msg: 'Up to date', type: 'info' });
        }

    } catch (e) {
        console.error('[Sync] Failed:', e.message);
        if (!silent && mainWindow) mainWindow.webContents.send('sync-status', { msg: 'Sync failed: ' + e.message, type: 'error' });
    } finally {
        isSyncing = false;
        console.log('[Sync] Finished.');
    }
}

// --- Tray & Window ---

function createTray() {
    const iconPath = path.join(__dirname, '..', 'lOGO.png');
    // In daemon mode, we might want a different icon or tooltip?
    const trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });

    tray = new Tray(trayIcon);
    tray.setToolTip('RomStore' + (isDaemon ? ' (Daemon)' : ''));

    const contextMenu = Menu.buildFromTemplate([
        {
            label: 'Open',
            click: () => {
                if (mainWindow) {
                    mainWindow.show();
                    mainWindow.focus();
                } else {
                    createWindow();
                }
            }
        },
        {
            label: 'Sync Now',
            click: () => performSync(false)
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

    tray.setContextMenu(contextMenu);

    tray.on('double-click', () => {
        if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
        } else {
            createWindow();
        }
    });
}

function createWindow() {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.show();
        return;
    }

    const win = new BrowserWindow({
        width: 1200, height: 800, backgroundColor: '#121212',
        icon: path.join(__dirname, '..', 'lOGO.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true, nodeIntegration: false,
            partition: 'persist:romstore', backgroundThrottling: false
        }
    });

    mainWindow = win;
    win.loadFile('renderer/index.html');

    win.on('close', (event) => {
        if (!isQuitting) {
            event.preventDefault();
            win.hide();
            // If not daemon, hiding means background mode. 
            // If daemon, we are always effectively in background mode logic-wise, 
            // but we might want to ensure timer is running.
            startBackgroundMode();
            return false;
        }
    });

    win.on('show', () => {
        // If not daemon, stop background timer to resume watcher? 
        // Actually, with the new Main logic, we can keep the watcher running in Main 
        // OR rely on Renderer watcher if we prefer. 
        // For Daemon consistency, let's keep Main logic dominant?
        // But the requirements said "resume watcher" (UI based).
        // Let's stick to the previous hybrid model:
        // Window Open -> Renderer Watcher active (sending IPC to Main to upload)
        // Window Hidden -> Main Timer active

        stopBackgroundMode();
        win.webContents.send('visibility-changed', true);
        performSync(false); // Manual sync on show
    });
}

function startBackgroundMode() {
    if (backgroundSyncInterval) clearInterval(backgroundSyncInterval);
    if (mainWindow) mainWindow.webContents.send('visibility-changed', false);

    console.log('[Main] Background Mode. Sync every 10m.');
    backgroundSyncInterval = setInterval(() => performSync(true), 600000);
}

function stopBackgroundMode() {
    if (backgroundSyncInterval) {
        clearInterval(backgroundSyncInterval);
        backgroundSyncInterval = null;
    }
}

// --- App Lifecycle ---

app.whenReady().then(async () => {
    loadSession(); // Load session for Daemon
    createTray();

    if (isDaemon) {
        console.log('[Main] Starting in DAEMON mode');
        startBackgroundMode();
        // Perform initial sync
        performSync(true);
    } else {
        createWindow();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
    else mainWindow.show();
});

// --- IPC Handlers (Updated for Main Logic) ---

ipcMain.handle('select-dirs', async () => {
    const result = await dialog.showOpenDialog({ properties: ['openDirectory'] });
    return result.filePaths[0];
});

ipcMain.handle('get-config', () => loadConfig());

ipcMain.handle('save-config', (event, config) => {
    saveConfig(config);
    return true;
});

// New: Renderer checking login status
ipcMain.handle('check-session', () => {
    loadSession();
    return !!sessionToken;
});

// New: Renderer sending session token on login
ipcMain.handle('set-session', (event, token) => {
    saveSession(token);
    return true;
});

ipcMain.handle('enter-daemon-mode', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.hide();
        startBackgroundMode();
        // Show a notification so user knows where it went
        new Notification({
            title: 'RomStore',
            body: 'Running in background. Check System Tray.'
        }).show();
    }
});

// Legacy: Scan local (Renderer uses for UI)
// We can reuse the Main helper
ipcMain.handle('scan-local-emulation', async (event, baseDir) => {
    // Basic scan returning relative paths
    if (!baseDir || !fs.existsSync(baseDir)) return [];
    // Reuse scanDirStatMain but just return paths? 
    // Or keep the old simple recursive walker for simple lists
    // Let's implement a simple version reuse
    const stats = await scanDirStatMain(baseDir);
    return stats.map(s => s.relPath);
});

ipcMain.handle('scan-dir-stat', async (event, baseDir) => scanDirStatMain(baseDir));

// Proxy for renderer logic
ipcMain.handle('download-file', async (event, { url, destPath, sessionToken: token, relPath }) => {
    // Update session if provided
    if (token) saveSession(token);
    await downloadFileMain(url, destPath, relPath);
});

ipcMain.handle('check-local-file', (event, filePath) => fs.existsSync(filePath));

ipcMain.handle('delete-file', async (event, filePath) => {
    if (fs.existsSync(filePath)) { fs.unlinkSync(filePath); return true; }
    return false;
});

ipcMain.handle('backup-local-file', async (event, filePath) => backupLocalFileMain(filePath));

// --- SAVE SYNC & WATCHER ---
let saveWatcher = null;
let isSyncing = false; // Prevents Watcher from firing during Sync downloads
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
            // Suppress events during sync to prevent loops
            if (isSyncing) return;

            // Only care about adds and changes to files
            if (eventName !== 'add' && eventName !== 'change') return;
            if (fs.statSync(filePath).isDirectory()) return;

            // Debounce uploads per file to handle rapid successive writes
            if (uploadDebounceMap.has(filePath)) {
                clearTimeout(uploadDebounceMap.get(filePath));
            }

            const timer = setTimeout(() => {
                if (isSyncing) return; // double check

                console.log(`[Watcher] ${eventName} (debounced): ${filePath}`);
                const rel = path.relative(saveDir, filePath).replace(/\\/g, '/');
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

// Triggered by Renderer Watcher (Window Open)
ipcMain.handle('upload-save', async (event, { filePath, relPath, sessionToken: token }) => {
    if (isSyncing) return { success: true }; // Ignore explicit uploads during sync too? Maybe safest.

    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found' };
    if (token) saveSession(token);
    const result = await uploadFileMain(filePath, relPath);
    if (result.success) {
        // Update manifest
        const manifest = loadManifest();
        const stat = fs.statSync(filePath);
        manifest[relPath] = { l: stat.mtime.getTime(), s: stat.mtime.getTime() };
        saveManifest(manifest);
    }
    return result;
});

// Renderer requesting manual sync (e.g. "Sync Now" button)
ipcMain.handle('trigger-manual-sync', () => {
    performSync(false);
});

// Renderer resolving conflict
ipcMain.handle('resolve-conflict', async (event, { path: relPath, choice }) => {
    const localDir = getLocalDir();
    const serverUrl = getServerUrl();
    const fullPath = path.join(localDir, 'saves', relPath);
    const downloadUrl = `${serverUrl}/api/download?type=saves&path=${encodeURIComponent(relPath)}`;

    if (choice === 'local') {
        await uploadFileMain(fullPath, relPath);
    } else {
        await downloadFileMain(downloadUrl, fullPath, relPath);
    }

    // Update manifest
    const manifest = loadManifest();
    const stat = fs.statSync(fullPath); // Should exist now
    manifest[relPath] = { l: stat.mtime.getTime(), s: stat.mtime.getTime() };
    saveManifest(manifest);

    // Check pending conflicts? Re-run sync silently to clear state
    performSync(true);
});
