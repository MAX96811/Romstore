const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

// Keeps a Switch game's update and DLC current on this PC right before it is
// launched, then points Ryujinx at the folders they live in so it applies them
// on its own. Ryujinx (Ryubing) rescans `autoload_dirs` every time it starts,
// selects the newest update and enables every DLC it finds there.

function requestJson(url, sessionToken) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, { headers: { 'X-Session-Token': sessionToken || '' } }, res => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { body += chunk; });
            res.on('end', () => {
                if (res.statusCode === 404) return resolve(null);
                if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
                try { resolve(JSON.parse(body)); } catch (error) { reject(error); }
            });
        });
        req.on('error', reject);
    });
}

function downloadFile(url, destPath, sessionToken, onProgress) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, { headers: { 'X-Session-Token': sessionToken || '' } }, res => {
            if (res.statusCode !== 200) {
                res.resume();
                return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
            }
            fs.mkdirSync(path.dirname(destPath), { recursive: true });
            const partPath = `${destPath}.part`;
            const total = Number(res.headers['content-length'] || 0);
            let received = 0;
            const out = fs.createWriteStream(partPath);
            res.on('data', chunk => {
                received += chunk.length;
                if (onProgress) onProgress({ receivedBytes: received, totalBytes: total });
            });
            res.pipe(out);
            out.on('finish', () => {
                try {
                    if (total && received !== total) throw new Error(`Short download: ${received} of ${total} bytes`);
                    if (fs.existsSync(destPath)) fs.unlinkSync(destPath);
                    fs.renameSync(partPath, destPath);
                    resolve({ destPath, bytes: received });
                } catch (error) {
                    try { fs.unlinkSync(partPath); } catch (cleanupError) { }
                    reject(error);
                }
            });
            out.on('error', error => {
                try { fs.unlinkSync(partPath); } catch (cleanupError) { }
                reject(error);
            });
        });
        req.on('error', reject);
    });
}

// Every Ryujinx configuration this PC might launch. EmuDeck can point at the
// native build or the Flatpak, so all of them are kept in step: an extra
// autoload folder in an unused config is harmless, a missing one is a game
// without its update.
function listRyujinxConfigFiles(homeDir) {
    return [
        path.join(homeDir, '.config', 'Ryujinx', 'Config.json'),
        path.join(homeDir, '.config', 'Ryubing', 'Config.json'),
        path.join(homeDir, '.var', 'app', 'io.github.ryubing.Ryujinx', 'config', 'Ryujinx', 'Config.json'),
        path.join(homeDir, '.var', 'app', 'org.ryujinx.Ryujinx', 'config', 'Ryujinx', 'Config.json')
    ].filter(file => fs.existsSync(file));
}

function ensureAutoloadDirs(configPath, dirs) {
    const text = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(text);
    const existing = Array.isArray(config.autoload_dirs) ? config.autoload_dirs.map(String) : [];
    const added = dirs.filter(dir => !existing.includes(dir));
    if (!added.length) return { changed: false, added: [] };
    config.autoload_dirs = existing.concat(added);
    // Ryujinx writes its file with two-space indentation; keep it readable
    // and diff-friendly rather than collapsing it to one line.
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    return { changed: true, added };
}

function needsDownload(destPath, addon) {
    if (!fs.existsSync(destPath)) return true;
    const size = fs.statSync(destPath).size;
    return Number.isFinite(addon.sizeBytes) && addon.sizeBytes > 0 && size !== addon.sizeBytes;
}

async function prepareSwitchAddons(options) {
    const {
        serverUrl,
        sessionToken,
        emulationDir,
        relPath,
        homeDir,
        isEmulatorRunning = () => false,
        onProgress = () => { },
        fetchJson = requestJson,
        download = downloadFile,
        configFiles = listRyujinxConfigFiles(homeDir)
    } = options;

    const result = { addons: [], downloaded: [], skipped: [], failed: [], autoload: { configs: [], added: [], deferred: false } };
    const base = String(serverUrl || '').replace(/\/+$/, '');
    const info = await fetchJson(`${base}/api/switch/addons?relPath=${encodeURIComponent(relPath)}`, sessionToken);
    const addons = (info && Array.isArray(info.addons)) ? info.addons : [];
    result.addons = addons;
    if (!addons.length) return result;

    const romRoot = path.resolve(emulationDir, 'roms');
    let index = 0;
    for (const addon of addons) {
        index += 1;
        const destPath = path.resolve(romRoot, addon.relPath);
        if (!destPath.startsWith(romRoot + path.sep)) {
            result.failed.push({ addon, error: 'Add-on path escapes the ROM folder' });
            continue;
        }
        if (!needsDownload(destPath, addon)) {
            result.skipped.push({ addon, destPath });
            continue;
        }
        onProgress({ phase: 'start', addon, index, count: addons.length });
        try {
            await download(
                `${base}/api/download?type=roms&path=${encodeURIComponent(addon.relPath)}`,
                destPath,
                sessionToken,
                progress => onProgress({ phase: 'progress', addon, index, count: addons.length, ...progress })
            );
            result.downloaded.push({ addon, destPath });
        } catch (error) {
            result.failed.push({ addon, error: error.message });
        }
    }

    // Only folders that actually hold something are registered, so a failed
    // download never leaves Ryujinx scanning an empty directory forever.
    const present = result.downloaded.concat(result.skipped).map(item => path.dirname(item.destPath));
    const dirs = [...new Set(present)];
    if (dirs.length && configFiles.length) {
        // Ryujinx rewrites Config.json when it exits, which would discard an
        // edit made while it runs. The next launch gets another chance.
        if (isEmulatorRunning()) {
            result.autoload.deferred = true;
        } else {
            for (const configPath of configFiles) {
                try {
                    const outcome = ensureAutoloadDirs(configPath, dirs);
                    result.autoload.configs.push(configPath);
                    if (outcome.changed) result.autoload.added.push(...outcome.added);
                } catch (error) {
                    result.failed.push({ configPath, error: error.message });
                }
            }
        }
    }
    return result;
}

module.exports = {
    downloadFile,
    ensureAutoloadDirs,
    listRyujinxConfigFiles,
    prepareSwitchAddons,
    requestJson
};
