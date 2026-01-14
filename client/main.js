const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

function createWindow() {
    const win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#121212',
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
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat && stat.isDirectory()) {
                walk(fullPath, results);
            } else {
                // Get path relative to the emulation base folder
                // Normalizing to forward slashes for matching with server relPath
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

ipcMain.handle('download-file', async (event, { url, destPath, sessionToken }) => {
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

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
    });
});

ipcMain.handle('check-local-file', (event, filePath) => {
    return fs.existsSync(filePath);
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
