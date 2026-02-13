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
const USERS_SAVES_DIR = path.join(SAVES_DIR, 'users');

// Ensure essential emulation directories exist
[ROMS_DIR, BIOS_DIR, SAVES_DIR, USERS_SAVES_DIR].forEach(dir => {
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
const SWITCH_SAVE_MAP_FILE = path.join(DATA_DIR, 'switch_save_map.json');

// Ensure data dir exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SWITCH_SAVE_MAP_FILE)) fs.writeFileSync(SWITCH_SAVE_MAP_FILE, '{}');

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
        const firstReadLen = Math.min(stats.size, 1024 * 1024, buffer.length);
        let bytesRead = fs.readSync(fd, buffer, 0, firstReadLen, 0);
        
        // Read last 1MB
        if (stats.size > 1024 * 1024) {
            const offset = stats.size - 1024 * 1024;
            const writePos = Math.min(1024 * 1024, buffer.length);
            const maxWritable = Math.max(0, buffer.length - writePos);
            const secondReadLen = Math.min(1024 * 1024, maxWritable);
            if (secondReadLen > 0) {
                bytesRead += fs.readSync(fd, buffer, writePos, secondReadLen, offset);
            }
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

let switchSaveMap = {};
let switchSaveMapMtime = 0;

function normalizeSwitchSaveMap(rawMap) {
    const normalized = {};
    if (!rawMap || typeof rawMap !== 'object') return normalized;

    for (const [rawKey, rawValue] of Object.entries(rawMap)) {
        const key = String(rawKey || '').trim().toUpperCase();
        const value = String(rawValue || '').trim().toUpperCase();
        if (/^[0-9A-F]{16}$/.test(key) && /^[0-9A-F]{16}$/.test(value)) {
            normalized[key] = value;
        }
    }
    return normalized;
}

function saveSwitchSaveMap() {
    fs.writeFileSync(SWITCH_SAVE_MAP_FILE, JSON.stringify(switchSaveMap, null, 2));
    try {
        switchSaveMapMtime = fs.statSync(SWITCH_SAVE_MAP_FILE).mtimeMs;
    } catch (e) {
        switchSaveMapMtime = Date.now();
    }
}

function loadSwitchSaveMap(force = false) {
    if (!fs.existsSync(SWITCH_SAVE_MAP_FILE)) {
        switchSaveMap = {};
        saveSwitchSaveMap();
        return switchSaveMap;
    }

    let currentMtime = 0;
    try { currentMtime = fs.statSync(SWITCH_SAVE_MAP_FILE).mtimeMs; } catch (e) {}
    if (!force && currentMtime <= switchSaveMapMtime) return switchSaveMap;

    try {
        const raw = JSON.parse(fs.readFileSync(SWITCH_SAVE_MAP_FILE, 'utf8'));
        switchSaveMap = normalizeSwitchSaveMap(raw);
    } catch (e) {
        switchSaveMap = {};
    }
    switchSaveMapMtime = currentMtime || Date.now();
    return switchSaveMap;
}

loadSwitchSaveMap(true);

// User loading
function getUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        if (!Array.isArray(users)) return [];

        let changed = false;
        const hasAdmin = users.some(u => u && u.role === 'admin');
        const normalized = users.map((u, idx) => {
            const next = { ...u };
            if (!next.role) {
                next.role = (!hasAdmin && idx === 0) ? 'admin' : 'user';
                changed = true;
            }
            if (typeof next.mustChangePassword === 'undefined') {
                next.mustChangePassword = false;
                changed = true;
            }
            return next;
        });

        if (changed) saveUsers(normalized);
        return normalized;
    } catch (e) {
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function normalizeUsername(username) {
    return (username || '').trim().toLowerCase();
}

function sanitizeSessionUser(user) {
    return {
        id: user.id,
        username: user.username,
        role: user.role || 'user',
        mustChangePassword: !!user.mustChangePassword
    };
}

function findUserById(userId) {
    const users = getUsers();
    return users.find(u => String(u.id) === String(userId)) || null;
}

function getUserSavesDirFromId(userId) {
    const safeId = String(userId || '').replace(/[^a-zA-Z0-9_-]/g, '');
    return path.join(USERS_SAVES_DIR, safeId);
}

function maybeMigrateLegacySaves(req, userDir) {
    if (!req.session || !req.session.user) return;
    const users = getUsers();
    if (users.length !== 1) return;
    if (String(users[0].id) !== String(req.session.user.id)) return;
    if (!users[0].role || users[0].role !== 'admin') return;
    if (fs.readdirSync(userDir).length > 0) return;

    const legacyItems = fs.readdirSync(SAVES_DIR, { withFileTypes: true })
        .filter(item => item.name !== 'users' && item.name !== '.tmp');
    if (legacyItems.length === 0) return;

    for (const item of legacyItems) {
        const sourcePath = path.join(SAVES_DIR, item.name);
        const targetPath = path.join(userDir, item.name);
        if (fs.existsSync(targetPath)) continue;
        fs.cpSync(sourcePath, targetPath, { recursive: true });
    }
}

function getUserSavesDir(req) {
    if (!req.session || !req.session.user) return null;
    const userDir = getUserSavesDirFromId(req.session.user.id);
    if (!userDir.startsWith(USERS_SAVES_DIR)) return null;
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    maybeMigrateLegacySaves(req, userDir);
    return userDir;
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
                const persisted = findUserById(sess.user.id);
                if (!persisted) return res.status(401).json({ error: 'Unauthorized' });
                req.session.user = sanitizeSessionUser(persisted);
                if (req.session.user.mustChangePassword && req.path !== '/api/auth/password') {
                    return res.status(403).json({ error: 'Password change required', mustChangePassword: true });
                }
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
        const persisted = findUserById(req.session.user.id);
        if (!persisted) return res.status(401).json({ error: 'Unauthorized' });

        req.session.user = sanitizeSessionUser(persisted);
        if (req.session.user.mustChangePassword && req.path !== '/api/auth/password') {
            return res.status(403).json({ error: 'Password change required', mustChangePassword: true });
        }

        console.log(`[AuthCheck] Success via Session: ${req.sessionID}`);
        next();
    } else {
        console.warn(`[AuthCheck] Fail - No Session/Token for ${req.url}`);
        res.status(401).json({ error: 'Unauthorized' });
    }
};

const requireAdmin = (req, res, next) => {
    if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
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
        if (req.query.type === 'saves') {
            const userSavesDir = getUserSavesDir(req);
            if (!userSavesDir) return cb(new Error('Unauthorized'));
            baseDir = userSavesDir;
        }
        else if (req.query.type === 'bios') baseDir = BIOS_DIR;

        // Use a .tmp directory for initial uploads to avoid collisions
        const targetPath = path.join(baseDir, '.tmp');
        
        if (!fs.existsSync(targetPath)) fs.mkdirSync(targetPath, { recursive: true });
        cb(null, targetPath);
    }
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

function findRomsForSystem(systemName) {
    const systemDir = path.join(ROMS_DIR, systemName);
    if (!fs.existsSync(systemDir)) return [];

    function walk(dir, results = []) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.name.startsWith('.')) continue;
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full, results);
            else results.push(full);
        }
        return results;
    }

    return walk(systemDir);
}

function getDisplayTitleFromRomPath(absRomPath) {
    const rel = path.relative(ROMS_DIR, absRomPath).replace(/\\/g, '/');
    const meta = gameMetadata[rel];
    return (meta && meta.title) ? meta.title : path.parse(absRomPath).name;
}

function buildSaveTitleLookup() {
    const wiiMap = {};
    const switchMap = {};

    // Build Wii ID -> title map.
    // For ISO, the first 6 bytes are the game/disc ID; we use first 4 for save title IDs.
    const wiiFiles = findRomsForSystem('wii');
    for (const romPath of wiiFiles) {
        try {
            const ext = path.extname(romPath).toLowerCase();
            const title = getDisplayTitleFromRomPath(romPath);

            if (ext === '.iso') {
                const fd = fs.openSync(romPath, 'r');
                const buf = Buffer.alloc(6);
                fs.readSync(fd, buf, 0, 6, 0);
                fs.closeSync(fd);
                const discId = buf.toString('ascii').trim().toUpperCase();
                if (/^[A-Z0-9]{6}$/.test(discId)) {
                    const shortId = discId.slice(0, 4);
                    if (!wiiMap[shortId]) wiiMap[shortId] = title;
                }
            }

            // Fallback: filename patterns like [RMCE01]
            const base = path.basename(romPath);
            const match = base.match(/\[([A-Z0-9]{6})\]/i);
            if (match) {
                const shortId = match[1].toUpperCase().slice(0, 4);
                if (!wiiMap[shortId]) wiiMap[shortId] = title;
            }
        } catch (e) {}
    }

    // Build Switch TitleID -> title map from common filename patterns.
    const switchFiles = findRomsForSystem('switch');
    for (const romPath of switchFiles) {
        try {
            const base = path.basename(romPath);
            const title = getDisplayTitleFromRomPath(romPath);
            const match = base.match(/\[([0-9a-fA-F]{16})\]/);
            if (match) {
                const tid = match[1].toUpperCase();
                if (!switchMap[tid]) switchMap[tid] = title;
            }
        } catch (e) {}
    }

    return { wiiMap, switchMap };
}

function countSaveVersions(userSavesDir, relPath) {
    const versionDir = path.join(userSavesDir, '.versions', relPath);
    if (!fs.existsSync(versionDir)) return 0;
    try {
        return fs.readdirSync(versionDir).length;
    } catch (e) {
        return 0;
    }
}

function getWiiShortIdFromRom(gameFullPath) {
    try {
        const ext = path.extname(gameFullPath).toLowerCase();
        if (ext !== '.iso') return null;
        const fd = fs.openSync(gameFullPath, 'r');
        const buf = Buffer.alloc(6);
        fs.readSync(fd, buf, 0, 6, 0);
        fs.closeSync(fd);
        const discId = buf.toString('ascii').trim().toUpperCase();
        if (!/^[A-Z0-9]{6}$/.test(discId)) return null;
        return discId.slice(0, 4);
    } catch (e) {
        return null;
    }
}

function getSwitchTitleIdFromRelPath(gameRelPath) {
    const fileName = path.basename(gameRelPath);
    const match = fileName.match(/\[([0-9a-fA-F]{16})\]/);
    return match ? match[1].toUpperCase() : null;
}

function getSwitchTitleIdFromMetadata(gameRelPath) {
    const metadata = gameMetadata[gameRelPath];
    if (!metadata || typeof metadata !== 'object') return null;

    const possible = [
        metadata.titleId,
        metadata.titleID,
        metadata.switchTitleId,
        metadata.switchTitleID,
        metadata.nspTitleId,
        metadata.nspTitleID
    ];

    for (const value of possible) {
        const candidate = String(value || '').trim().toUpperCase();
        if (/^[0-9A-F]{16}$/.test(candidate)) return candidate;
    }

    return null;
}

function getSwitchTitleIdFromSaveRelPath(saveRelPath) {
    const currentSwitchSaveMap = loadSwitchSaveMap();
    const ids = String(saveRelPath || '')
        .split('/')
        .filter(p => /^[0-9A-Fa-f]{16}$/.test(p))
        .map(p => p.toUpperCase());
    if (ids.length === 0) return null;

    // Prefer real game TitleIDs first.
    const gameId = ids.find(id => id.startsWith('0100'));
    if (gameId) return gameId;

    // User-defined mapping for emulators that store abstract slot IDs (e.g. 000000000000000X).
    for (const id of ids) {
        const mapped = currentSwitchSaveMap[id];
        if (mapped && /^[0-9A-Fa-f]{16}$/.test(mapped)) return mapped.toUpperCase();
    }

    // Then known system IDs.
    const systemId = ids.find(id => id.startsWith('8000'));
    if (systemId) return systemId;

    // Avoid all-zero placeholders when possible.
    const nonZero = ids.find(id => !/^0{16}$/.test(id));
    if (nonZero) return nonZero;

    return ids[0];
}

function buildGameSaveMatcher(gameRelPath) {
    const system = (gameRelPath.split('/')[0] || '').toLowerCase();
    const gameNameNoExt = path.parse(path.basename(gameRelPath)).name.toLowerCase();
    const normalized = gameNameNoExt.replace(/[^a-z0-9]+/g, ' ').trim();
    const keywords = normalized.split(' ').filter(w => w.length >= 4).slice(0, 6);

    const fullGamePath = path.join(ROMS_DIR, gameRelPath);

    if (system === 'wii') {
        const shortId = getWiiShortIdFromRom(fullGamePath);
        if (shortId) {
            const titleHex = Buffer.from(shortId, 'ascii').toString('hex').toLowerCase();
            return save => save.relPath.toLowerCase().includes(`/title/00010000/${titleHex}`);
        }
    }

    if (system === 'switch') {
        const titleId = getSwitchTitleIdFromRelPath(gameRelPath) || getSwitchTitleIdFromMetadata(gameRelPath);
        if (titleId) {
            return save => getSwitchTitleIdFromSaveRelPath(save.relPath) === titleId;
        }
    }

    return save => {
        if ((save.system || '').toLowerCase() !== system) return false;
        const haystack = `${save.relPath} ${save.name} ${(save.gameTitle || '')}`.toLowerCase();
        if (!keywords.length) return haystack.includes(normalized);
        return keywords.every(k => haystack.includes(k));
    };
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
    if (req.session && req.session.user) {
        const persisted = findUserById(req.session.user.id);
        req.session.user = persisted ? sanitizeSessionUser(persisted) : null;
    }
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
    if (users.some(u => normalizeUsername(u.username) === normalizeUsername(username))) {
        return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
        id: Date.now() + Math.floor(Math.random() * 10000),
        username: username.trim(),
        password: hashedPassword,
        role: 'admin',
        mustChangePassword: false,
        createdAt: new Date().toISOString()
    };
    
    saveUsers([newUser]);
    fs.mkdirSync(getUserSavesDirFromId(newUser.id), { recursive: true });
    req.session.user = sanitizeSessionUser(newUser);
    res.json({ success: true, token: req.sessionID, user: req.session.user });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => normalizeUsername(u.username) === normalizeUsername(username));

    if (user && bcrypt.compareSync(password, user.password)) {
        user.lastLoginAt = new Date().toISOString();
        saveUsers(users);
        req.session.user = sanitizeSessionUser(user);
        res.json({ success: true, token: req.sessionID, user: req.session.user, mustChangePassword: req.session.user.mustChangePassword });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/api/auth/password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing password fields' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const users = getUsers();
    const userIndex = users.findIndex(u => String(u.id) === String(req.session.user.id));
    if (userIndex === -1) return res.status(404).json({ error: 'User not found' });

    const user = users[userIndex];
    if (!bcrypt.compareSync(currentPassword, user.password)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }

    user.password = bcrypt.hashSync(newPassword, 10);
    user.mustChangePassword = false;
    user.passwordUpdatedAt = new Date().toISOString();
    users[userIndex] = user;
    saveUsers(users);
    req.session.user = sanitizeSessionUser(user);
    res.json({ success: true, user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const users = getUsers().map(u => ({
        id: u.id,
        username: u.username,
        role: u.role || 'user',
        mustChangePassword: !!u.mustChangePassword,
        createdAt: u.createdAt || null,
        lastLoginAt: u.lastLoginAt || null
    }));
    res.json(users);
});

app.post('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    const { username, tempPassword, role } = req.body;
    if (!username || !tempPassword) return res.status(400).json({ error: 'Missing username or temp password' });
    if (tempPassword.length < 6) return res.status(400).json({ error: 'Temporary password must be at least 6 characters' });

    const users = getUsers();
    if (users.some(u => normalizeUsername(u.username) === normalizeUsername(username))) {
        return res.status(409).json({ error: 'Username already exists' });
    }

    const userRole = role === 'admin' ? 'admin' : 'user';
    const newUser = {
        id: Date.now() + Math.floor(Math.random() * 10000),
        username: username.trim(),
        password: bcrypt.hashSync(tempPassword, 10),
        role: userRole,
        mustChangePassword: true,
        createdAt: new Date().toISOString()
    };
    users.push(newUser);
    saveUsers(users);
    fs.mkdirSync(getUserSavesDirFromId(newUser.id), { recursive: true });

    res.status(201).json({
        success: true,
        user: {
            id: newUser.id,
            username: newUser.username,
            role: newUser.role,
            mustChangePassword: true,
            createdAt: newUser.createdAt
        }
    });
});

app.get('/api/admin/switch-save-map', requireAuth, requireAdmin, (req, res) => {
    const map = loadSwitchSaveMap(true);
    const userSavesDir = getUserSavesDir(req);
    const allSaves = userSavesDir ? scanDir(userSavesDir) : [];
    const unresolvedSlotIds = [...new Set(
        allSaves
            .flatMap(file => String(file.relPath || '').split('/'))
            .filter(part => /^[0-9A-Fa-f]{16}$/.test(part))
            .map(part => part.toUpperCase())
            .filter(id => !id.startsWith('0100') && !id.startsWith('8000') && !map[id])
    )].sort();

    res.json({
        map,
        unresolvedSlotIds
    });
});

app.post('/api/admin/switch-save-map', requireAuth, requireAdmin, (req, res) => {
    const slotId = String(req.body?.slotId || '').trim().toUpperCase();
    const titleId = String(req.body?.titleId || '').trim().toUpperCase();
    const remove = !!req.body?.remove;

    if (!/^[0-9A-F]{16}$/.test(slotId)) {
        return res.status(400).json({ error: 'Invalid slotId format' });
    }

    loadSwitchSaveMap(true);
    if (remove) {
        delete switchSaveMap[slotId];
    } else {
        if (!/^[0-9A-F]{16}$/.test(titleId)) {
            return res.status(400).json({ error: 'Invalid titleId format' });
        }
        switchSaveMap[slotId] = titleId;
    }

    switchSaveMap = normalizeSwitchSaveMap(switchSaveMap);
    saveSwitchSaveMap();
    res.json({ success: true, map: switchSaveMap });
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
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    const titleLookup = buildSaveTitleLookup();
    let files = scanDir(userSavesDir);
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
                    if (ascii.length === 4) {
                        const knownTitle = titleLookup.wiiMap[ascii.toUpperCase()];
                        gameTitle = knownTitle
                            ? `Wii: ${knownTitle} (${ascii})`
                            : `Wii Game: ${ascii} (${hexId})`;
                    } else {
                        gameTitle = `Wii ID: ${hexId}`;
                    }
                } catch (e) { gameTitle = `Wii ID: ${hexId}`; }
            }
        }
        
        if (!system) {
            const switchId = getSwitchTitleIdFromSaveRelPath(file.relPath);
            if (switchId) {
                system = 'Switch';
                const knownTitle = titleLookup.switchMap[switchId];
                gameTitle = knownTitle
                    ? `Switch: ${knownTitle} (${switchId})`
                    : `Switch TitleID: ${switchId}`;
            }
        }
        if (!system && (file.name.includes('MemoryCard') || file.name.endsWith('.gci'))) { system = 'GameCube'; gameTitle = 'GameCube Memory Card'; }
        if (!system) { system = parts.length > 1 ? parts[0] : 'Unknown'; gameTitle = system; }

        return { ...file, system, gameTitle: gameTitle || file.name };
    });
    res.json(files);
});

app.get('/api/game-saves', requireAuth, (req, res) => {
    const { relPath: gameRelPath } = req.query;
    if (!gameRelPath) return res.status(400).json({ error: 'Missing game relPath' });

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const gameFullPath = path.join(ROMS_DIR, gameRelPath);
    if (!gameFullPath.startsWith(ROMS_DIR) || !fs.existsSync(gameFullPath)) {
        return res.status(404).json({ error: 'Game not found' });
    }

    const titleLookup = buildSaveTitleLookup();
    let saves = scanDir(userSavesDir).map(file => {
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
                    if (ascii.length === 4) {
                        const knownTitle = titleLookup.wiiMap[ascii.toUpperCase()];
                        gameTitle = knownTitle ? `Wii: ${knownTitle} (${ascii})` : `Wii Game: ${ascii} (${hexId})`;
                    } else {
                        gameTitle = `Wii ID: ${hexId}`;
                    }
                } catch (e) { gameTitle = `Wii ID: ${hexId}`; }
            }
        }

        if (!system) {
            const switchId = getSwitchTitleIdFromSaveRelPath(file.relPath);
            if (switchId) {
                system = 'Switch';
                const knownTitle = titleLookup.switchMap[switchId];
                gameTitle = knownTitle ? `Switch: ${knownTitle} (${switchId})` : `Switch TitleID: ${switchId}`;
            }
        }
        if (!system && (file.name.includes('MemoryCard') || file.name.endsWith('.gci'))) { system = 'GameCube'; gameTitle = 'GameCube Memory Card'; }
        if (!system) { system = parts.length > 1 ? parts[0] : 'Unknown'; gameTitle = system; }

        return { ...file, system, gameTitle: gameTitle || file.name };
    });

    const matcher = buildGameSaveMatcher(gameRelPath);
    saves = saves
        .filter(matcher)
        .map(s => ({ ...s, versionsCount: countSaveVersions(userSavesDir, s.relPath) }))
        .sort((a, b) => new Date(b.mtime) - new Date(a.mtime));

    res.json(saves);
});

// 3. List Bios
app.get('/api/bios', requireAuth, (req, res) => res.json(scanDir(BIOS_DIR)));

// 4. Unified Download
app.get('/api/download', requireAuth, (req, res) => {
    const { type, path: relPath } = req.query;
    let base = type === 'saves' ? getUserSavesDir(req) : (type === 'bios' ? BIOS_DIR : ROMS_DIR);
    if (!base) return res.status(401).send('Unauthorized');
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
    const relPath = req.body.relPath; 
    if (!relPath) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Missing relPath' });
    }

    console.log(`[SaveSync] Upload request for: ${relPath}`);
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const fullPath = path.join(userSavesDir, relPath);
    if (!fullPath.startsWith(userSavesDir)) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Invalid path' });
    }

    // Ensure dir exists
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    // Handle Versioning
    try {
        if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
            const versionDir = path.join(userSavesDir, '.versions', relPath);
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
                    try { fs.unlinkSync(path.join(versionDir, v.name)); } catch(e) {}
                });
            }
        }
    } catch (e) {
        console.warn(`[SaveSync] Versioning failed for ${relPath}:`, e.message);
    }

    try {
        // Robust move: copy + unlink to handle cross-device issues if any
        fs.copyFileSync(req.file.path, fullPath);
        fs.unlinkSync(req.file.path);
        console.log(`[SaveSync] Successfully saved: ${relPath}`);
        res.json({ success: true, message: 'Save uploaded and versioned' });
    } catch (e) {
        console.error(`[SaveSync] Save failed for ${relPath}:`, e);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: 'Failed to save file: ' + e.message });
    }
});

app.get('/api/saves/versions', requireAuth, (req, res) => {
    const { relPath } = req.query;
    if (!relPath) return res.status(400).json({ error: 'Missing relPath' });

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const versionDir = path.join(userSavesDir, '.versions', relPath);
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

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const fullPath = path.join(userSavesDir, relPath);
    const versionPath = path.join(userSavesDir, '.versions', relPath, versionName);

    if (!fs.existsSync(versionPath)) return res.status(404).json({ error: 'Version not found' });

    // Version the current one before restoring? Yes.
    if (fs.existsSync(fullPath)) {
        const versionDir = path.join(userSavesDir, '.versions', relPath);
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
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    manifest.saves = scanDir(userSavesDir);

    // 3. Bios
    manifest.bios = scanDir(BIOS_DIR);

    res.json(manifest);
});

app.get('/api/system', (req, res) => res.json({ status: 'online', mode: 'native_api', storage_root: EMULATION_DIR }));

app.listen(PORT, () => {
    console.log(`RomStore Native Backend running on port ${PORT}`);
});
