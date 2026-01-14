const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

function createWindow() {
    const win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#121212',
        icon: path.join(__dirname, '..', 'lOGO.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            partition: 'persist:romstore'
        }
    });

    // In production we would load the file. 
    // For now, it will load our local copy of the UI
    win.loadFile('renderer/index.html');
    // win.webContents.openDevTools();
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// IPC Handlers for Local File Operations
ipcMain.handle('select-dirs', async () => {
    const result = await dialog.showOpenDialog({
        properties: ['openDirectory']
    });
    return result.filePaths[0];
});

ipcMain.handle('scan-local-emulation', async (event, baseDir) => {
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
                results.push(rel);
            }
        });
        return results;
    }
    
    try {
        return walk(baseDir);
    } catch (e) {
        console.error("Scan failed", e);
        return [];
    }
});

ipcMain.handle('scan-dir-stat', async (event, baseDir) => {
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
    
    try {
        return walk(baseDir);
    } catch (e) {
        console.error("Scan Stat failed", e);
        return [];
    }
});

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

    const totalLength = response.headers['content-length'];
    let downloaded = 0;
    let lastPercent = 0;

    response.data.on('data', (chunk) => {
        downloaded += chunk.length;
        if (totalLength && relPath) {
            const percent = Math.round((downloaded / totalLength) * 100);
            if (percent > lastPercent) {
                lastPercent = percent;
                event.sender.send('download-progress', { relPath, percent });
            }
        }
    });

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
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

ipcMain.handle('get-config', () => {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    if (fs.existsSync(configPath)) {
        return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    }
    return {};
});

ipcMain.handle('save-config', (event, config) => {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
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
            if (fs.statSync(filePath).isDirectory()) return;
            
            // Debounce uploads per file to handle rapid successive writes
            if (uploadDebounceMap.has(filePath)) {
                clearTimeout(uploadDebounceMap.get(filePath));
            }

            const timer = setTimeout(() => {
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

ipcMain.handle('upload-save', async (event, { filePath, relPath, sessionToken }) => {
    if (!fs.existsSync(filePath)) return { success: false, error: 'File not found' };

    try {
        if (fs.statSync(filePath).isDirectory()) return { success: false, error: 'Skipped directory' };
    } catch (e) { return { success: false, error: 'File access failed' }; }
    
    // Check config for server URL
    const configPath = path.join(app.getPath('userData'), 'config.json');
    let serverUrl = 'http://localhost:3000';
    if (fs.existsSync(configPath)) {
        const conf = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (conf.serverUrl) serverUrl = conf.serverUrl;
    }

    try {
        const FormData = require('form-data'); 
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));
        form.append('relPath', relPath);

        const res = await axios.post(`${serverUrl}/api/saves/upload?type=saves`, form, {
            headers: {
                ...form.getHeaders(),
                'X-Session-Token': sessionToken
            }
        });
        return { success: res.status === 200 };
    } catch (e) {
        console.error('[Upload] Failed:', e.message);
        return { success: false, error: e.message };
    }
});

