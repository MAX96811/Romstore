const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const https = require('https'); 
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { execSync } = require('child_process');

const app = express();
const PORT = 3000;

// EmuDeck paths
const EMULATION_DIR = '/emulation';
const ROMS_DIR = path.join(EMULATION_DIR, 'roms');
const BIOS_DIR = path.join(EMULATION_DIR, 'bios');
const SAVES_DIR = path.join(EMULATION_DIR, 'saves');

// Ensure essential emulation directories exist
[ROMS_DIR, BIOS_DIR, SAVES_DIR].forEach(dir => {
    try {
        if (!fs.existsSync(dir)) {
            console.log(`[Init] Creating missing directory: ${dir}`);
            fs.mkdirSync(dir, { recursive: true });
        }
    } catch (e) {
        console.error(`[Init] Failed to create directory ${dir}: ${e.message}`);
    }
});

// Data paths
const DATA_DIR = path.join(__dirname, 'data');
const METADATA_FILE = path.join(DATA_DIR, 'metadata.json');
const KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const HASH_CACHE_FILE = path.join(DATA_DIR, 'hashes.json');

// Ensure data dir exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Load Hashing Cache
let hashCache = {};
if (fs.existsSync(HASH_CACHE_FILE)) {
    try { hashCache = JSON.parse(fs.readFileSync(HASH_CACHE_FILE, 'utf8')); } catch (e) { hashCache = {}; }
}

function saveHashCache() {
    fs.writeFileSync(HASH_CACHE_FILE, JSON.stringify(hashCache, null, 2));
}

// Helper: Get File Hash (MD5)
function getFileHash(filePath) {
    try {
        const stats = fs.statSync(filePath);
        const mtime = stats.mtimeMs.toString();
        
        // Use cache if mtime hasn't changed
        if (hashCache[filePath] && hashCache[filePath].mtime === mtime) {
            return hashCache[filePath].hash;
        }

        // Calculate MD5 of first 1MB + last 1MB for speed on large files
        const buffer = Buffer.alloc(Math.min(stats.size, 1024 * 1024 * 2)); 
        const fd = fs.openSync(filePath, 'r');
        
        // Read first 1MB
        let bytesRead = fs.readSync(fd, buffer, 0, Math.min(stats.size, 1024 * 1024), 0);
        
        // Read last 1MB
        if (stats.size > 1024 * 1024) {
            const offset = stats.size - 1024 * 1024;
            bytesRead += fs.readSync(fd, buffer, 1024 * 1024, 1024 * 1024, offset);
        }
        fs.closeSync(fd);

        const hash = crypto.createHash('md5').update(buffer.slice(0, bytesRead)).digest('hex');
        
        hashCache[filePath] = { hash, mtime };
        saveHashCache();
        return hash;
    } catch (e) {
        console.error(`Hashing failed for ${filePath}: ${e.message}`);
        return null;
    }
}

// Load Metadata & Keys
let gameMetadata = {};
if (fs.existsSync(METADATA_FILE)) {
    try { gameMetadata = JSON.parse(fs.readFileSync(METADATA_FILE, 'utf8')); } catch (e) { console.error("Error loading metadata:", e); }
}

let apiKeys = { clientId: '', clientSecret: '' };
if (fs.existsSync(KEYS_FILE)) {
    try { apiKeys = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); } catch (e) { console.error("Error loading keys:", e); }
}

// User loading
function getUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { return []; }
}

let igdbAccessToken = null;
let tokenExpiry = 0;

app.use(cors({
    origin: function (origin, callback) {
        // Allow any origin for now to ensure Electron compatibility
        // In a strict production environment, you would validate this.
        callback(null, true);
    },
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token']
}));
app.use(express.json());

app.use(session({
    secret: 'romstore-secret-key-12345',
    resave: true,
    saveUninitialized: true,
    rolling: true,
    cookie: { 
        secure: false, // Must be false for HTTP
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000 
    }
}));

// Auth Middleware
const requireAuth = (req, res, next) => {
    const token = req.get('X-Session-Token');
    console.log(`[AuthCheck] URL: ${req.url}, Method: ${req.method}, Token: ${token || 'None'}`);
    
    if (token && !req.session.user) {
        req.sessionStore.get(token, (err, sess) => {
            if (sess && sess.user) {
                req.session.user = sess.user;
                console.log(`[AuthCheck] Success via Token: ${token}`);
                next();
            } else {
                console.warn(`[AuthCheck] Fail - Invalid Token: ${token}`);
                res.status(401).json({ error: 'Unauthorized' });
            }
        });
        return;
    }

    if (req.session && req.session.user) {
        console.log(`[AuthCheck] Success via Session: ${req.sessionID}`);
        next();
    } else {
        console.warn(`[AuthCheck] Fail - No Session/Token for ${req.url}`);
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// DEBUG: Log all requests
app.use((req, res, next) => {
    console.log(`[INCOMING] ${req.method} ${req.url} - Origin: ${req.get('origin')}`);
    next();
});

// --- FILE UPLOAD CONFIGURATION ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        let baseDir = ROMS_DIR;
        if (req.query.type === 'saves') baseDir = SAVES_DIR;
        else if (req.query.type === 'bios') baseDir = BIOS_DIR;

        const targetPath = req.query.path ? path.join(baseDir, req.query.path) : baseDir;
        
        // Security check
        if (!targetPath.startsWith(EMULATION_DIR)) return cb(new Error('Access Denied: Invalid Path'));
        
        if (!fs.existsSync(targetPath)) fs.mkdirSync(targetPath, { recursive: true });
        cb(null, targetPath);
    },
    filename: function (req, file, cb) { cb(null, file.originalname); }
});
const upload = multer({ storage: storage });

// --- HELPERS ---

// Scan directory helper
function scanDir(baseDir, relativePath = '') {
    const fullPath = path.join(baseDir, relativePath);
    if (!fs.existsSync(fullPath)) return [];
    
    let results = [];
    const list = fs.readdirSync(fullPath, { withFileTypes: true });
    
    for (const file of list) {
        if (file.name.startsWith('.') || file.name.toLowerCase().endsWith('.txt')) continue;

        const rel = path.join(relativePath, file.name).replace(/\\/g, '/');
        if (file.isDirectory()) {
            results = results.concat(scanDir(baseDir, rel));
        } else {
            const stats = fs.statSync(path.join(baseDir, rel));
            results.push({
                name: file.name,
                relPath: rel,
                size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                mtime: stats.mtime,
                hash: getFileHash(path.join(baseDir, rel))
            });
        }
    }
    return results;
}

// IGDB Token Manager
async function getIgdbToken() {
    if (igdbAccessToken && Date.now() < tokenExpiry) return igdbAccessToken;
    if (!apiKeys.clientId || !apiKeys.clientSecret) throw new Error("Missing IGDB Credentials");

    const url = `https://id.twitch.tv/oauth2/token?client_id=${apiKeys.clientId}&client_secret=${apiKeys.clientSecret}&grant_type=client_credentials`;
    const res = await fetch(url, { method: 'POST' });
    if (!res.ok) throw new Error("Failed to authenticate with Twitch/IGDB");
    
    const data = await res.json();
    igdbAccessToken = data.access_token;
    tokenExpiry = Date.now() + (data.expires_in * 1000) - 60000; // Buffer 1 min
    return igdbAccessToken;
}

// Download Helper
async function downloadFile(url, destPath) {
    console.log(`[Download] Starting download: ${url} -> ${destPath}`);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to download ${url}`);
    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    
    const targetDir = path.dirname(destPath);
    
    // Robust Directory Creation with Conflict Resolution
    const parts = targetDir.split(path.sep);
    let currentPath = parts[0];
    if (targetDir.startsWith('/')) currentPath = '/'; 

    for (let i = 0; i < parts.length; i++) {
        if (!parts[i]) continue; 
        if (i > 0 || !targetDir.startsWith('/')) { 
            currentPath = path.join(currentPath, parts[i]);
        }
        
        try {
            fs.mkdirSync(currentPath);
        } catch (e) {
            if (e.code === 'EEXIST') {
                // Path exists. Check if it is a directory.
                try {
                    const stats = fs.statSync(currentPath);
                    if (stats.isDirectory()) {
                        continue; // All good
                    } else {
                        // It exists and is NOT a directory (File or Link)
                        console.warn(`[Download] Conflict at ${currentPath}. Not a directory. Renaming.`);
                        const backupPath = `${currentPath}_backup_${Date.now()}`;
                        fs.renameSync(currentPath, backupPath);
                        // Try creating again
                        fs.mkdirSync(currentPath);
                    }
                } catch (statErr) {
                    // Stat failed? Maybe broken link? Try to unlink/rename anyway
                    console.warn(`[Download] Stat failed for existing path ${currentPath}: ${statErr.message}. Attempting rename.`);
                    try {
                        const backupPath = `${currentPath}_backup_${Date.now()}`;
                        fs.renameSync(currentPath, backupPath);
                        fs.mkdirSync(currentPath);
                    } catch (renameErr) {
                        throw new Error(`Failed to resolve conflict at ${currentPath}: ${renameErr.message}`);
                    }
                }
            } else {
                throw e; // Other mkdir error
            }
        }
    }

    fs.writeFileSync(destPath, buffer);
    console.log(`[Download] File written successfully.`);
}

// --- AUTH ROUTES ---

app.get('/api/auth/status', (req, res) => {
    const users = getUsers();
    res.json({
        needsSetup: users.length === 0,
        authenticated: !!(req.session && req.session.user),
        user: req.session ? req.session.user : null
    });
});

app.post('/api/auth/setup', (req, res) => {
    const users = getUsers();
    if (users.length > 0) return res.status(403).json({ error: 'Setup already completed' });

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { id: Date.now(), username, password: hashedPassword };
    
    fs.writeFileSync(USERS_FILE, JSON.stringify([newUser], null, 2));
    req.session.user = { id: newUser.id, username: newUser.username };
    res.json({ success: true, token: req.sessionID });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = { id: user.id, username: user.username };
        res.json({ success: true, token: req.sessionID });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// --- API ROUTES ---

// 1. List Games (ROMs) with Metadata
app.get('/api/games', requireAuth, (req, res) => {
    if (!fs.existsSync(ROMS_DIR)) return res.json([]);
    const systems = fs.readdirSync(ROMS_DIR, { withFileTypes: true }).filter(d => d.isDirectory());
    const games = [];
    
    const findArtwork = (systemPath, gameName) => {
        const baseName = path.parse(gameName).name;
        // Priority: Metadata-downloaded > Local folders
        const potentialDirs = [
            'media/boxart',
            'media/images',
            'images',
            'boxart',
            'downloaded_media/images'
        ];
        const extensions = ['.png', '.jpg', '.jpeg'];

        for (const dir of potentialDirs) {
            for (const ext of extensions) {
                const artPath = path.join(systemPath, dir, baseName + ext);
                if (fs.existsSync(artPath)) {
                    return path.relative(ROMS_DIR, artPath).replace(/\\/g, '/');
                }
            }
        }
        return null;
    };

    systems.forEach(system => {
        try {
            const systemPath = path.join(ROMS_DIR, system.name);
            const files = fs.readdirSync(systemPath, { withFileTypes: true }).filter(f => !f.isDirectory());
            files.forEach(file => {
                if (file.name.startsWith('.') || file.name.toLowerCase().endsWith('.txt')) return; 

                const relPath = path.join(system.name, file.name).replace(/\\/g, '/');
                const stats = fs.statSync(path.join(systemPath, file.name));
                let artPath = findArtwork(systemPath, file.name);

                // Apply Metadata
                let displayName = file.name;
                let description = '';
                let meta = gameMetadata[relPath];

                if (meta) {
                    if (meta.title) displayName = meta.title;
                    if (meta.summary) description = meta.summary;
                    // If metadata implies we downloaded art, findArtwork should have found it in media/boxart
                    // But we can check specifically if needed. For now, standard folders work.
                }

                games.push({
                    name: displayName,
                    originalName: file.name,
                    system: system.name,
                    relPath: relPath,
                    size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                    mtime: stats.mtime,
                    artworkPath: artPath,
                    description: description,
                    hasMetadata: !!meta
                });
            });
        } catch (e) {}
    });
    res.json(games);
});

// 2. List Saves
app.get('/api/saves', requireAuth, (req, res) => {
    let files = scanDir(SAVES_DIR);
    files = files.map(file => {
        const parts = file.relPath.split('/');
        let system = null, gameTitle = null;

        if (file.relPath.includes('title/00010000')) {
            system = 'Wii';
            const idx = parts.indexOf('00010000');
            if (idx !== -1 && parts[idx + 1]) {
                const hexId = parts[idx + 1];
                try {
                    let ascii = '';
                    for (let i = 0; i < hexId.length; i += 2) {
                        const code = parseInt(hexId.substr(i, 2), 16);
                        if (code >= 32 && code <= 126) ascii += String.fromCharCode(code);
                    }
                    gameTitle = ascii.length === 4 ? `Wii Game: ${ascii} (${hexId})` : `Wii ID: ${hexId}`;
                } catch (e) { gameTitle = `Wii ID: ${hexId}`; }
            }
        }
        
        if (!system) {
            const switchId = parts.find(p => /^[0-9A-Fa-f]{16}$/.test(p));
            if (switchId) { system = 'Switch'; gameTitle = `Switch TitleID: ${switchId}`; }
        }
        if (!system && (file.name.includes('MemoryCard') || file.name.endsWith('.gci'))) { system = 'GameCube'; gameTitle = 'GameCube Memory Card'; }
        if (!system) { system = parts.length > 1 ? parts[0] : 'Unknown'; gameTitle = system; }

        return { ...file, system, gameTitle: gameTitle || file.name };
    });
    res.json(files);
});

// 3. List Bios
app.get('/api/bios', requireAuth, (req, res) => res.json(scanDir(BIOS_DIR)));

// 4. Unified Download
app.get('/api/download', requireAuth, (req, res) => {
    const { type, path: relPath } = req.query;
    let base = type === 'saves' ? SAVES_DIR : (type === 'bios' ? BIOS_DIR : ROMS_DIR);
    const fullPath = path.join(base, relPath);
    if (!fullPath.startsWith(base) || !fs.existsSync(fullPath)) return res.status(403).send('Invalid Path');
    res.download(fullPath);
});

// 5. Artwork Serving
app.get('/api/artwork', requireAuth, (req, res) => {
    const { path: relPath } = req.query;
    if (!relPath) return res.status(400).send('No path provided');
    const fullPath = path.join(ROMS_DIR, relPath);
    if (!fullPath.startsWith(ROMS_DIR) || !fs.existsSync(fullPath)) return res.status(404).send('Image not found');
    res.sendFile(fullPath);
});

// 6. Upload
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    res.json({ message: 'File uploaded successfully', file: req.file });
});

// --- SAVE MANAGEMENT (Versioning) ---

app.post('/api/saves/upload', requireAuth, upload.single('file'), (req, res) => {
    const relPath = req.body.relPath; // e.g. "snes/mario.srm"
    if (!relPath) return res.status(400).json({ error: 'Missing relPath' });

    const fullPath = path.join(SAVES_DIR, relPath);
    if (!fullPath.startsWith(SAVES_DIR)) return res.status(403).json({ error: 'Invalid path' });

    // Ensure dir exists
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    // Handle Versioning
    if (fs.existsSync(fullPath)) {
        const versionDir = path.join(SAVES_DIR, '.versions', relPath);
        if (!fs.existsSync(versionDir)) fs.mkdirSync(versionDir, { recursive: true });

        const stats = fs.statSync(fullPath);
        const timestamp = stats.mtime.toISOString().replace(/[:.]/g, '-');
        const versionPath = path.join(versionDir, `${timestamp}_${path.basename(relPath)}`);

        fs.copyFileSync(fullPath, versionPath);
        console.log(`[SaveSync] Versioned: ${versionPath}`);

        // Prune old versions (Keep last 5)
        const versions = fs.readdirSync(versionDir)
            .map(f => ({ name: f, time: fs.statSync(path.join(versionDir, f)).mtime.getTime() }))
            .sort((a, b) => b.time - a.time);
        
        if (versions.length > 5) {
            versions.slice(5).forEach(v => {
                fs.unlinkSync(path.join(versionDir, v.name));
                console.log(`[SaveSync] Pruned: ${v.name}`);
            });
        }
    }

    // Move uploaded file to final destination
    // req.file.path is the temp location or the destination if destination defined in multer
    // Since we used the same storage engine, it might have already put it in ROMS_DIR if we didn't override.
    // But wait, the existing storage engine uses req.query.path. 
    // Let's manually move it from req.file.path if it ended up somewhere else or just overwrite.
    // Actually, our multer config uses req.query.path to determine destination.
    // If we want to use the same upload middleware, we should probably pass ?path=... in query 
    // OR create a specific multer config for saves. 
    // The current multer config targets ROMS_DIR by default unless ?path is set.
    // We should probably just move the file from where it landed.
    
    // However, the current upload middleware puts it in ROMS_DIR if path is not set, or subpath of ROMS_DIR.
    // We want SAVES_DIR. 
    // So we should effectively Move it from req.file.path (which might be in ROMS_DIR due to global config) to SAVES_DIR.
    // OR, we assume the client sends ?path=../saves/..., but that's risky security-wise.
    
    // Safer: Move from wherever it is to SAVES_DIR/relPath.
    try {
        fs.renameSync(req.file.path, fullPath);
        res.json({ success: true, message: 'Save uploaded and versioned' });
    } catch (e) {
        console.error("Move failed", e);
        res.status(500).json({ error: 'Failed to save file' });
    }
});

app.get('/api/saves/versions', requireAuth, (req, res) => {
    const { relPath } = req.query;
    if (!relPath) return res.status(400).json({ error: 'Missing relPath' });

    const versionDir = path.join(SAVES_DIR, '.versions', relPath);
    if (!fs.existsSync(versionDir)) return res.json([]);

    const versions = fs.readdirSync(versionDir).map(f => ({
        name: f,
        time: fs.statSync(path.join(versionDir, f)).mtime
    })).sort((a, b) => b.time - a.time);

    res.json(versions);
});

app.post('/api/saves/restore', requireAuth, (req, res) => {
    const { relPath, versionName } = req.body;
    if (!relPath || !versionName) return res.status(400).json({ error: 'Missing params' });

    const fullPath = path.join(SAVES_DIR, relPath);
    const versionPath = path.join(SAVES_DIR, '.versions', relPath, versionName);

    if (!fs.existsSync(versionPath)) return res.status(404).json({ error: 'Version not found' });

    // Version the current one before restoring? Yes.
    if (fs.existsSync(fullPath)) {
        const versionDir = path.join(SAVES_DIR, '.versions', relPath);
        const stats = fs.statSync(fullPath);
        const timestamp = stats.mtime.toISOString().replace(/[:.]/g, '-');
        const backupPath = path.join(versionDir, `${timestamp}_${path.basename(relPath)}`);
        fs.copyFileSync(fullPath, backupPath);
    }

    fs.copyFileSync(versionPath, fullPath);
    res.json({ success: true, message: 'Version restored' });
});

// 7. List all available systems (folders in roms dir)
app.get('/api/systems', requireAuth, (req, res) => {
    if (!fs.existsSync(ROMS_DIR)) return res.json([]);
    try {
        const systems = fs.readdirSync(ROMS_DIR, { withFileTypes: true })
            .filter(d => d.isDirectory())
            .map(d => d.name)
            .sort();
        res.json(systems);
    } catch (e) {
        res.status(500).json({ error: "Failed to list systems" });
    }
});

// --- METADATA & SETTINGS ROUTES ---

// Get Keys Status
app.get('/api/settings/keys', requireAuth, (req, res) => {
    res.json({ 
        hasClientId: !!apiKeys.clientId, 
        hasClientSecret: !!apiKeys.clientSecret 
    });
});

// Save Keys
app.post('/api/settings/keys', requireAuth, (req, res) => {
    const { clientId, clientSecret } = req.body;
    apiKeys = { clientId, clientSecret };
    fs.writeFileSync(KEYS_FILE, JSON.stringify(apiKeys, null, 2));
    igdbAccessToken = null; // Reset token
    res.json({ success: true });
});

// Search IGDB
app.get('/api/metadata/search', requireAuth, async (req, res) => {
    let query = req.query.q;
    if (!query) return res.status(400).json({ error: "Missing query" });

    // Clean Query Logic
    console.log(`[IGDB] Original Query: "${query}"`);
    
    // 1. Remove extension
    query = path.parse(query).name;
    
    // 2. Remove things in brackets/parentheses e.g. (USA), [v1.0]
    // Also remove common dump info like "En,Fr,Es", "Rev 1" if inside brackets
    query = query.replace(/\s*[\(\[].*?[\)\]]/g, '');
    
    // 3. Trim extra spaces
    query = query.trim();

    console.log(`[IGDB] Cleaned Query: "${query}"`);

    try {
        const token = await getIgdbToken();
        // IGDB API: Search games, get cover, summary, etc.
        const response = await fetch('https://api.igdb.com/v4/games', {
            method: 'POST',
            headers: {
                'Client-ID': apiKeys.clientId,
                'Authorization': `Bearer ${token}`
            },
            body: `search "${query}"; fields name, cover.url, summary, first_release_date, platforms.name; limit 10;`
        });
        
        if (!response.ok) throw new Error("IGDB Request Failed");
        const data = await response.json();
        
        // Fix cover URLs (they come as //images.igdb.com...)
        const results = data.map(g => ({
            ...g,
            coverUrl: g.cover ? `https:${g.cover.url}`.replace('t_thumb', 't_cover_big') : null
        }));
        
        res.json(results);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Apply Metadata
app.post('/api/metadata/apply', requireAuth, async (req, res) => {
    const { relPath, igdbData } = req.body;
    if (!relPath || !igdbData) return res.status(400).json({ error: "Missing data" });
    
    console.log(`[Apply] Applying to ${relPath}`);

    try {
        // 1. Download Cover if exists
        if (igdbData.coverUrl) {
            const system = relPath.split('/')[0];
            const gameFileName = path.basename(relPath);
            const gameBaseName = path.parse(gameFileName).name;
            // Target: roms/[system]/media/boxart/[gameName].png
            const targetDir = path.join(ROMS_DIR, system, 'media', 'boxart');
            console.log(`[Apply] Target Dir: ${targetDir}`);
            
            // Check ext from url
            const ext = path.extname(igdbData.coverUrl) || '.jpg';
            const finalPath = path.join(targetDir, `${gameBaseName}${ext}`);

            await downloadFile(igdbData.coverUrl, finalPath);
        }

        // 2. Save to Metadata JSON
        gameMetadata[relPath] = {
            title: igdbData.name,
            summary: igdbData.summary,
            igdbId: igdbData.id,
            releaseDate: igdbData.first_release_date
        };
        fs.writeFileSync(METADATA_FILE, JSON.stringify(gameMetadata, null, 2));

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to apply metadata" });
    }
});

app.get('/api/sync/manifest', requireAuth, (req, res) => {
    const manifest = {
        games: [],
        saves: [],
        bios: []
    };

    // 1. Games
    if (fs.existsSync(ROMS_DIR)) {
        const systems = fs.readdirSync(ROMS_DIR, { withFileTypes: true }).filter(d => d.isDirectory());
        systems.forEach(system => {
            const systemPath = path.join(ROMS_DIR, system.name);
            const files = fs.readdirSync(systemPath, { withFileTypes: true }).filter(f => !f.isDirectory());
            files.forEach(file => {
                if (file.name.startsWith('.') || file.name.toLowerCase().endsWith('.txt')) return; 
                const relPath = path.join(system.name, file.name).replace(/\\/g, '/');
                const fullPath = path.join(systemPath, file.name);
                const stats = fs.statSync(fullPath);
                const meta = gameMetadata[relPath] || {};
                
                manifest.games.push({
                    name: meta.title || file.name,
                    filename: file.name,
                    system: system.name,
                    relPath: relPath,
                    size: stats.size,
                    hash: getFileHash(fullPath),
                    mtime: stats.mtime
                });
            });
        });
    }

    // 2. Saves
    manifest.saves = scanDir(SAVES_DIR);

    // 3. Bios
    manifest.bios = scanDir(BIOS_DIR);

    res.json(manifest);
});

app.get('/api/system', (req, res) => res.json({ status: 'online', mode: 'native_api', storage_root: EMULATION_DIR }));

app.listen(PORT, () => {
    console.log(`RomStore Native Backend running on port ${PORT}`);
});

