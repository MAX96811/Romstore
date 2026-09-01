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
const {
    findGameFiles,
    getPlatformInfo,
    isDlcRelPath,
    listPlatforms,
    looksLikeDlcFileName,
    resolveUploadDirectory
} = require('./lib/rom-library');
const {
    cleanSearchQuery,
    pickConfidentMatch
} = require('./lib/game-title');
const {
    findCanonicalFile,
    inventoryLegacyBackslashFiles,
    materializeLegacyBackslashFiles,
    normalizeSaveRelativePath,
    resolveContainedSavePath,
    scanCanonicalFiles
} = require('./lib/save-paths');
const {
    buildRyujinxSlotTitleMap,
    getRyujinxSlotId,
    getSwitchTitleIdFromSavePath,
    normalizeSwitchTitleId
} = require('./lib/switch-saves');
const { activateBundleUpload } = require('./lib/switch-bundle-store');
require('dotenv').config();

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3000;

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

// Cleanup dangling chunked uploads from previous sessions
const CHUNKS_DIR = path.join(ROMS_DIR, '.tmp_chunks');
try {
    if (fs.existsSync(CHUNKS_DIR)) {
        const chunks = fs.readdirSync(CHUNKS_DIR);
        if (chunks.length > 0) {
            console.log(`[Init] Cleaning up ${chunks.length} dangling upload chunks...`);
            for (const file of chunks) {
                try { fs.unlinkSync(path.join(CHUNKS_DIR, file)); } catch (err) { }
            }
        }
    }
} catch (e) {
    console.error(`[Init] Failed to cleanup chunks: ${e.message}`);
}

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
    try { currentMtime = fs.statSync(SWITCH_SAVE_MAP_FILE).mtimeMs; } catch (e) { }
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

const FileStore = require('session-file-store')(session);
app.use(session({
    store: new FileStore({
        path: path.join(__dirname, 'data', 'sessions'),
        ttl: 30 * 24 * 60 * 60, // 30 days
        logFn: function () { } // Suppress console clutter
    }),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: false, // Must be false for HTTP
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));

// Auth Middleware
const resolveToken = (req, res, next) => {
    const token = req.get('X-Session-Token');
    if (token && (!req.session || !req.session.user)) {
        req.sessionStore.get(token, (err, sess) => {
            if (sess && sess.user) {
                if (!req.session) Object.defineProperty(req, 'session', { value: {}, writable: true });
                req.session.user = sess.user;
            }
            next();
        });
        return;
    }
    next();
};

app.use(resolveToken);

const requireAuth = (req, res, next) => {
    if (req.session && req.session.user) {
        const persisted = findUserById(req.session.user.id);
        if (!persisted) return res.status(401).json({ error: 'Unauthorized' });

        req.session.user = sanitizeSessionUser(persisted);
        if (req.session.user.mustChangePassword && req.path !== '/api/auth/password') {
            return res.status(403).json({ error: 'Password change required', mustChangePassword: true });
        }

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
    const ip = req.ip || req.get('x-forwarded-for') || req.socket?.remoteAddress || 'unknown';
    const cfRay = req.get('cf-ray') || 'n/a';
    const contentLength = req.get('content-length') || 'n/a';
    console.log(`[INCOMING] ${req.method} ${req.url} - Origin: ${req.get('origin') || 'none'} - IP: ${ip} - Len: ${contentLength} - CF-Ray: ${cfRay}`);
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
const chunkUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 25 * 1024 * 1024 }
});

// --- HELPERS ---

// Scan directory helper
function scanDir(baseDir, options = {}) {
    const skipTextFiles = options.skipTextFiles !== false;
    return scanCanonicalFiles(baseDir, {
        skipEntry: entry => entry.name.startsWith('.') || (skipTextFiles && entry.name.toLowerCase().endsWith('.txt'))
    }).map(file => ({
        name: path.posix.basename(file.relPath),
        relPath: file.relPath,
        size: (file.stats.size / 1024 / 1024).toFixed(2) + ' MB',
        sizeBytes: file.stats.size,
        mtime: file.stats.mtime,
        hash: getFileHash(file.physicalPath)
    }));
}

function findRomsForSystem(systemName) {
    const systemDir = path.join(ROMS_DIR, systemName);
    if (!fs.existsSync(systemDir)) return [];
    const platform = getPlatformInfo(systemDir, systemName);
    return findGameFiles(systemDir, platform.extensions);
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
        } catch (e) { }
    }

    // Build Switch TitleID -> title map from common filename patterns.
    const switchFiles = findRomsForSystem('switch');
    for (const romPath of switchFiles) {
        try {
            const relPath = path.relative(ROMS_DIR, romPath).replace(/\\/g, '/');
            const base = path.basename(romPath);
            const title = getDisplayTitleFromRomPath(romPath);
            const match = base.match(/\[([0-9a-fA-F]{16})\]/);
            const metadataTitleId = getSwitchTitleIdFromMetadata(relPath);
            const tid = match ? match[1].toUpperCase() : metadataTitleId;
            if (tid) {
                if (!switchMap[tid]) switchMap[tid] = title;
            }
        } catch (e) { }
    }

    return { wiiMap, switchMap };
}

function countSaveVersions(userSavesDir, relPath) {
    const safeVersionDir = resolveContainedSavePath(path.join(userSavesDir, '.versions'), relPath);
    if (!safeVersionDir) return 0;
    const versionDir = safeVersionDir.fullPath;
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

function getSwitchTitleIdFromSaveRelPath(saveRelPath, userSavesDir, slotTitleMap) {
    const currentSwitchSaveMap = loadSwitchSaveMap();
    const discoveredMap = slotTitleMap || (userSavesDir
        ? buildRyujinxSlotTitleMap(userSavesDir, currentSwitchSaveMap)
        : {});
    return getSwitchTitleIdFromSavePath(saveRelPath, discoveredMap, currentSwitchSaveMap);
}

function buildGameSaveMatcher(gameRelPath, options = {}) {
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
        const titleId = normalizeSwitchTitleId(options.titleIdOverride)
            || getSwitchTitleIdFromRelPath(gameRelPath)
            || getSwitchTitleIdFromMetadata(gameRelPath);
        if (titleId) {
            return save => getSwitchTitleIdFromSaveRelPath(
                save.relPath,
                options.userSavesDir,
                options.slotTitleMap
            ) === titleId;
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
    const token = req.get('X-Session-Token');
    if (token && req.sessionStore) {
        req.sessionStore.destroy(token, () => { });
    }
    if (req.session) req.session.destroy();
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
    const derivedMap = userSavesDir ? buildRyujinxSlotTitleMap(userSavesDir) : {};
    const allSaves = userSavesDir ? scanDir(userSavesDir, { skipTextFiles: false }) : [];
    const unresolvedSlotIds = [...new Set(
        allSaves
            .flatMap(file => String(file.relPath || '').split('/'))
            .filter(part => /^[0-9A-Fa-f]{16}$/.test(part))
            .map(part => part.toUpperCase())
            .filter(id => !id.startsWith('0100') && !id.startsWith('8000') && !derivedMap[id] && !map[id])
    )].sort();

    res.json({
        map,
        derivedMap,
        unresolvedSlotIds
    });
});

app.get('/api/admin/save-path-health', requireAuth, requireAdmin, (req, res) => {
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    const legacy = inventoryLegacyBackslashFiles(userSavesDir);
    res.json({
        legacyCount: legacy.length,
        missingCanonicalCount: legacy.filter(item => !item.canonicalExists).length,
        existingCanonicalCount: legacy.filter(item => item.canonicalExists).length,
        paths: legacy.map(item => ({ relPath: item.relPath, canonicalExists: item.canonicalExists, size: item.size }))
    });
});

app.post('/api/admin/save-path-health/materialize', requireAuth, requireAdmin, (req, res) => {
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    const report = materializeLegacyBackslashFiles(userSavesDir);
    res.json({
        copied: report.copied.map(item => item.relPath),
        preservedExisting: report.existing.map(item => item.relPath),
        failed: report.failed.map(item => ({ relPath: item.relPath, error: item.error }))
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

app.post('/api/games/switch-title-id', requireAuth, requireAdmin, (req, res) => {
    const relPath = normalizeSaveRelativePath(req.body?.relPath);
    const titleId = normalizeSwitchTitleId(req.body?.titleId);
    const remove = !!req.body?.remove;
    const safeGamePath = relPath ? resolveContainedSavePath(ROMS_DIR, relPath) : null;
    if (!safeGamePath || !fs.existsSync(safeGamePath.fullPath) || relPath.split('/')[0].toLowerCase() !== 'switch') {
        return res.status(400).json({ error: 'Invalid Switch game path' });
    }
    if (!remove && !titleId) return res.status(400).json({ error: 'Invalid Switch titleId' });

    gameMetadata[relPath] = { ...(gameMetadata[relPath] || {}) };
    if (remove) {
        delete gameMetadata[relPath].titleId;
        delete gameMetadata[relPath].switchTitleId;
    } else {
        gameMetadata[relPath].titleId = titleId;
    }
    fs.writeFileSync(METADATA_FILE, JSON.stringify(gameMetadata, null, 2));
    res.json({ success: true, relPath, titleId: remove ? null : titleId });
});

app.get('/api/switch-save-candidates', requireAuth, (req, res) => {
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    const slotTitleMap = buildRyujinxSlotTitleMap(userSavesDir, loadSwitchSaveMap());
    const titleLookup = buildSaveTitleLookup();
    const candidates = new Map();

    for (const file of scanDir(userSavesDir, { skipTextFiles: false })) {
        const slotId = getRyujinxSlotId(file.relPath);
        const titleId = getSwitchTitleIdFromSaveRelPath(file.relPath, userSavesDir, slotTitleMap);
        if (!slotId || !titleId) continue;
        const key = `${titleId}:${slotId}`;
        const current = candidates.get(key) || {
            titleId,
            slotId,
            gameTitle: titleLookup.switchMap[titleId] || null,
            fileCount: 0,
            sizeBytes: 0,
            mtime: null
        };
        current.fileCount += 1;
        current.sizeBytes += Number(file.sizeBytes) || 0;
        if (!current.mtime || new Date(file.mtime) > new Date(current.mtime)) current.mtime = file.mtime;
        candidates.set(key, current);
    }
    res.json([...candidates.values()].sort((a, b) => new Date(b.mtime) - new Date(a.mtime)));
});

// --- API ROUTES ---

// 1. List Games (ROMs) with Metadata
function buildGameList() {
    if (!fs.existsSync(ROMS_DIR)) return [];
    const systems = listPlatforms(ROMS_DIR);
    const games = [];

    const findArtwork = (systemPath, gamePath) => {
        const baseName = path.parse(gamePath).name;
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
            const systemPath = path.join(ROMS_DIR, system.system);
            const files = findGameFiles(systemPath, system.extensions);
            files.forEach(filePath => {
                const fileName = path.basename(filePath);
                const relPath = path.relative(ROMS_DIR, filePath).replace(/\\/g, '/');
                const stats = fs.statSync(filePath);
                let artPath = findArtwork(systemPath, filePath);

                // Apply Metadata
                let displayName = fileName;
                let description = '';
                let meta = gameMetadata[relPath];

                if (meta) {
                    if (meta.title) displayName = meta.title;
                    if (meta.summary) description = meta.summary;
                    // If metadata implies we downloaded art, findArtwork should have found it in media/boxart
                    // But we can check specifically if needed. For now, standard folders work.
                }

                const isSwitchGame = system.system.toLowerCase() === 'switch';
                const filenameSwitchTitleId = isSwitchGame ? getSwitchTitleIdFromRelPath(relPath) : null;
                const metadataSwitchTitleId = isSwitchGame ? getSwitchTitleIdFromMetadata(relPath) : null;

                games.push({
                    name: displayName,
                    originalName: fileName,
                    system: system.system,
                    systemName: system.fullName,
                    relPath: relPath,
                    size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                    mtime: stats.mtime,
                    artworkPath: artPath,
                    description: description,
                    hasMetadata: !!meta,
                    switchTitleId: filenameSwitchTitleId || metadataSwitchTitleId,
                    switchTitleIdSource: filenameSwitchTitleId ? 'filename' : (metadataSwitchTitleId ? 'metadata' : null),
                    isDlc: isDlcRelPath(relPath)
                });
            });
        } catch (e) { }
    });
    return games;
}

app.get('/api/games', requireAuth, (req, res) => {
    res.json(buildGameList());
});

// 2. List Saves
app.get('/api/saves', requireAuth, (req, res) => {
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });
    const titleLookup = buildSaveTitleLookup();
    const slotTitleMap = buildRyujinxSlotTitleMap(userSavesDir, loadSwitchSaveMap());
    let files = scanDir(userSavesDir, { skipTextFiles: false });
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
            const switchId = getSwitchTitleIdFromSaveRelPath(file.relPath, userSavesDir, slotTitleMap);
            if (switchId) {
                system = 'Switch';
                const knownTitle = titleLookup.switchMap[switchId];
                gameTitle = knownTitle
                    ? `Switch: ${knownTitle} (${switchId})`
                    : `Switch TitleID: ${switchId}`;
            }
        }
        if (!system && /^ryujinx\//i.test(file.relPath)) {
            system = 'Switch';
            gameTitle = 'Switch save (unmapped)';
        }
        if (!system && (file.name.includes('MemoryCard') || file.name.endsWith('.gci'))) { system = 'GameCube'; gameTitle = 'GameCube Memory Card'; }
        if (!system) { system = parts.length > 1 ? parts[0] : 'Unknown'; gameTitle = system; }

        return {
            ...file,
            system,
            gameTitle: gameTitle || file.name,
            switchTitleId: getSwitchTitleIdFromSaveRelPath(file.relPath, userSavesDir, slotTitleMap),
            switchSlotId: getRyujinxSlotId(file.relPath)
        };
    });
    res.json(files);
});

app.get('/api/game-saves', requireAuth, (req, res) => {
    const { relPath: requestedGameRelPath, titleId: rawTitleId } = req.query;
    if (!requestedGameRelPath) return res.status(400).json({ error: 'Missing game relPath' });

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const safeGamePath = resolveContainedSavePath(ROMS_DIR, requestedGameRelPath);
    if (!safeGamePath || !fs.existsSync(safeGamePath.fullPath)) {
        return res.status(404).json({ error: 'Game not found' });
    }
    const gameRelPath = safeGamePath.relativePath;
    const titleIdOverride = rawTitleId ? normalizeSwitchTitleId(rawTitleId) : null;
    if (rawTitleId && !titleIdOverride) return res.status(400).json({ error: 'Invalid Switch titleId' });

    const titleLookup = buildSaveTitleLookup();
    const slotTitleMap = buildRyujinxSlotTitleMap(userSavesDir, loadSwitchSaveMap());
    let saves = scanDir(userSavesDir, { skipTextFiles: false }).map(file => {
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
            const switchId = getSwitchTitleIdFromSaveRelPath(file.relPath, userSavesDir, slotTitleMap);
            if (switchId) {
                system = 'Switch';
                const knownTitle = titleLookup.switchMap[switchId];
                gameTitle = knownTitle ? `Switch: ${knownTitle} (${switchId})` : `Switch TitleID: ${switchId}`;
            }
        }
        if (!system && /^ryujinx\//i.test(file.relPath)) {
            system = 'Switch';
            gameTitle = 'Switch save (unmapped)';
        }
        if (!system && (file.name.includes('MemoryCard') || file.name.endsWith('.gci'))) { system = 'GameCube'; gameTitle = 'GameCube Memory Card'; }
        if (!system) { system = parts.length > 1 ? parts[0] : 'Unknown'; gameTitle = system; }

        return {
            ...file,
            system,
            gameTitle: gameTitle || file.name,
            switchTitleId: getSwitchTitleIdFromSaveRelPath(file.relPath, userSavesDir, slotTitleMap),
            switchSlotId: getRyujinxSlotId(file.relPath)
        };
    });

    const matcher = buildGameSaveMatcher(gameRelPath, {
        titleIdOverride,
        userSavesDir,
        slotTitleMap
    });
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
    const safePath = resolveContainedSavePath(base, relPath);
    if (!safePath) return res.status(403).send('Invalid Path');
    const fullPath = type === 'saves'
        ? (findCanonicalFile(base, safePath.relativePath, {
            skipEntry: entry => entry.name.startsWith('.')
        }) || safePath.fullPath)
        : safePath.fullPath;
    if (!fs.existsSync(fullPath)) return res.status(404).send('File not found');
    res.download(fullPath);
});

// 5. Artwork Serving
app.get('/api/artwork', requireAuth, (req, res) => {
    const { path: relPath } = req.query;
    if (!relPath) return res.status(400).send('No path provided');
    const safePath = resolveContainedSavePath(ROMS_DIR, relPath);
    if (!safePath || !fs.existsSync(safePath.fullPath)) return res.status(404).send('Image not found');
    res.sendFile(safePath.fullPath);
});

// 6. Upload
// DLC is add-on content, not a game, and mixing it into the platform root is
// what buries a library under a hundred Smash costume packs. Uploads whose name
// carries a DLC marker are filed under <system>/DLC/ instead.
function resolveUploadTargetDir(system, fileName) {
    const baseDir = resolveUploadDirectory(ROMS_DIR, system);
    return looksLikeDlcFileName(fileName) ? path.join(baseDir, 'DLC') : baseDir;
}

app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    console.log(`[Upload] Request started (single) - path=${req.query.path || 'none'} - user=${req.session?.user?.username || 'unknown'}`);
    if (!req.file) return res.status(400).json({ error: 'Missing file' });

    const rawSystem = String(req.query.path || '').trim().toLowerCase();
    const safeSystem = rawSystem.replace(/[^a-z0-9_-]/g, '');
    if (!safeSystem) {
        try { if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); } catch (e) { }
        return res.status(400).json({ error: 'Invalid or missing target system folder' });
    }

    const fileName = path.basename(req.file.originalname || req.file.filename);
    const targetDir = resolveUploadTargetDir(safeSystem, fileName);
    const targetPath = path.join(targetDir, fileName);

    if (!path.resolve(targetPath).startsWith(path.resolve(targetDir) + path.sep)) {
        try { if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); } catch (e) { }
        return res.status(403).json({ error: 'Invalid upload path' });
    }

    try {
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
        fs.copyFileSync(req.file.path, targetPath);
        fs.unlinkSync(req.file.path);
        console.log(`[Upload] Saved ${fileName} -> ${safeSystem} (${targetPath})`);
        res.json({
            success: true,
            message: 'File uploaded successfully',
            relPath: path.relative(ROMS_DIR, targetPath).replace(/\\/g, '/')
        });
    } catch (e) {
        console.error('[Upload] Failed to finalize upload:', e.message);
        try { if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); } catch (err) { }
        res.status(500).json({ error: 'Failed to save uploaded file' });
    }
});

app.post('/api/upload/chunk', requireAuth, chunkUpload.single('chunk'), (req, res) => {
    const rawSystem = String(req.query.path || '').trim().toLowerCase();
    const safeSystem = rawSystem.replace(/[^a-z0-9_-]/g, '');
    const uploadId = String(req.body.uploadId || '').trim();
    const originalName = String(req.body.fileName || '').trim();
    const chunkIndex = Number.parseInt(String(req.body.chunkIndex || ''), 10);
    const totalChunks = Number.parseInt(String(req.body.totalChunks || ''), 10);
    const safeFileName = path.basename(originalName || `upload-${Date.now()}.bin`);

    console.log(`[UploadChunk] Start - user=${req.session?.user?.username || 'unknown'} path=${safeSystem || 'invalid'} uploadId=${uploadId || 'none'} chunk=${chunkIndex}/${totalChunks}`);

    if (!safeSystem) return res.status(400).json({ error: 'Invalid or missing target system folder' });
    if (!uploadId || !/^[a-zA-Z0-9_-]{8,128}$/.test(uploadId)) return res.status(400).json({ error: 'Invalid uploadId' });
    if (!req.file || !req.file.buffer) return res.status(400).json({ error: 'Missing chunk payload' });
    if (!Number.isInteger(chunkIndex) || !Number.isInteger(totalChunks) || chunkIndex < 0 || totalChunks < 1 || chunkIndex >= totalChunks) {
        return res.status(400).json({ error: 'Invalid chunk index' });
    }

    const chunksDir = path.join(ROMS_DIR, '.tmp_chunks');
    const assembledPath = path.join(chunksDir, `${uploadId}.part`);
    const targetDir = resolveUploadTargetDir(safeSystem, safeFileName);
    const targetPath = path.join(targetDir, safeFileName);

    if (!path.resolve(assembledPath).startsWith(path.resolve(chunksDir) + path.sep) ||
        !path.resolve(targetPath).startsWith(path.resolve(targetDir) + path.sep)) {
        return res.status(403).json({ error: 'Invalid upload path' });
    }

    try {
        if (!fs.existsSync(chunksDir)) fs.mkdirSync(chunksDir, { recursive: true });
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
        fs.appendFileSync(assembledPath, req.file.buffer);

        if (chunkIndex === totalChunks - 1) {
            fs.copyFileSync(assembledPath, targetPath);
            fs.unlinkSync(assembledPath);
            console.log(`[UploadChunk] Complete - saved ${safeFileName} -> ${safeSystem} (${targetPath})`);
            return res.json({
                success: true,
                complete: true,
                relPath: path.relative(ROMS_DIR, targetPath).replace(/\\/g, '/')
            });
        }

        return res.json({
            success: true,
            complete: false,
            receivedChunk: chunkIndex + 1,
            totalChunks
        });
    } catch (e) {
        console.error(`[UploadChunk] Failed - uploadId=${uploadId} chunk=${chunkIndex}: ${e.message}`);
        return res.status(500).json({ error: 'Failed to process upload chunk' });
    }
});

// --- SAVE MANAGEMENT (Versioning) ---

app.post('/api/saves/switch-bundle/upload', requireAuth, upload.array('files', 500), (req, res) => {
    const uploadedFiles = Array.isArray(req.files) ? req.files : [];
    const cleanup = () => {
        for (const file of uploadedFiles) {
            try { if (file.path && fs.existsSync(file.path)) fs.unlinkSync(file.path); } catch (error) { }
        }
    };

    try {
        let relPaths;
        try { relPaths = JSON.parse(String(req.body.relPaths || '[]')); } catch (error) { relPaths = null; }
        if (!Array.isArray(relPaths) || relPaths.length !== uploadedFiles.length || !uploadedFiles.length) {
            cleanup();
            return res.status(400).json({ error: 'Bundle file manifest does not match the upload.' });
        }

        const userSavesDir = getUserSavesDir(req);
        if (!userSavesDir) {
            cleanup();
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const result = activateBundleUpload({
            userSavesDir,
            slotId: req.body.slotId,
            titleId: req.body.titleId,
            files: uploadedFiles.map((file, index) => ({
                relPath: relPaths[index],
                tempPath: file.path
            }))
        });
        cleanup();
        return res.json(result);
    } catch (error) {
        cleanup();
        console.error('[Switch Bundle] Upload failed:', error);
        return res.status(400).json({ error: error.message });
    }
});

app.post('/api/saves/upload', requireAuth, upload.single('file'), (req, res) => {
    const relPath = normalizeSaveRelativePath(req.body.relPath);
    if (!relPath || !req.file) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Missing file or invalid relPath' });
    }

    console.log(`[SaveSync] Upload request for: ${relPath}`);
    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const safePath = resolveContainedSavePath(userSavesDir, relPath);
    if (!safePath) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Invalid path' });
    }
    const fullPath = safePath.fullPath;

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
                    try { fs.unlinkSync(path.join(versionDir, v.name)); } catch (e) { }
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
        const savedStats = fs.statSync(fullPath);
        res.json({
            success: true,
            message: 'Save uploaded and versioned',
            relPath,
            mtime: savedStats.mtime,
            hash: getFileHash(fullPath)
        });
    } catch (e) {
        console.error(`[SaveSync] Save failed for ${relPath}:`, e);
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: 'Failed to save file: ' + e.message });
    }
});

app.get('/api/saves/versions', requireAuth, (req, res) => {
    const relPath = normalizeSaveRelativePath(req.query.relPath);
    if (!relPath) return res.status(400).json({ error: 'Missing or invalid relPath' });

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const safeVersionDir = resolveContainedSavePath(path.join(userSavesDir, '.versions'), relPath);
    if (!safeVersionDir) return res.status(403).json({ error: 'Invalid path' });
    const versionDir = safeVersionDir.fullPath;
    if (!fs.existsSync(versionDir)) return res.json([]);

    const versions = fs.readdirSync(versionDir).map(f => ({
        name: f,
        time: fs.statSync(path.join(versionDir, f)).mtime
    })).sort((a, b) => b.time - a.time);

    res.json(versions);
});

app.post('/api/saves/restore', requireAuth, (req, res) => {
    const relPath = normalizeSaveRelativePath(req.body.relPath);
    const versionName = String(req.body.versionName || '');
    if (!relPath || !versionName || path.basename(versionName) !== versionName) {
        return res.status(400).json({ error: 'Missing or invalid params' });
    }

    const userSavesDir = getUserSavesDir(req);
    if (!userSavesDir) return res.status(401).json({ error: 'Unauthorized' });

    const safeFullPath = resolveContainedSavePath(userSavesDir, relPath);
    const safeVersionDir = resolveContainedSavePath(path.join(userSavesDir, '.versions'), relPath);
    if (!safeFullPath || !safeVersionDir) return res.status(403).json({ error: 'Invalid path' });
    const fullPath = safeFullPath.fullPath;
    const versionPath = path.join(safeVersionDir.fullPath, versionName);

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
    try {
        const systems = listPlatforms(ROMS_DIR).map(platform => platform.system).sort();
        res.json(systems);
    } catch (e) {
        res.status(500).json({ error: "Failed to list systems" });
    }
});

// Platform details are used by the desktop uploader and EmuDeck integration.
app.get('/api/platforms', requireAuth, (req, res) => {
    try {
        res.json(listPlatforms(ROMS_DIR));
    } catch (e) {
        res.status(500).json({ error: 'Failed to list platform definitions' });
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
async function searchIgdb(rawQuery) {
    const query = cleanSearchQuery(rawQuery);
    if (!query) return { query, results: [] };

    const token = await getIgdbToken();
    // Quotes would terminate the Apicalypse string literal early.
    const escaped = query.replace(/["\\]/g, ' ').replace(/\s+/g, ' ').trim();
    const response = await fetch('https://api.igdb.com/v4/games', {
        method: 'POST',
        headers: {
            'Client-ID': apiKeys.clientId,
            'Authorization': `Bearer ${token}`
        },
        body: `search "${escaped}"; fields name, cover.url, summary, first_release_date, platforms.name; limit 10;`
    });

    if (!response.ok) throw new Error(`IGDB request failed (${response.status})`);
    const data = await response.json();

    // Fix cover URLs (they come as //images.igdb.com...)
    return {
        query,
        results: data.map(g => ({
            ...g,
            coverUrl: g.cover ? `https:${g.cover.url}`.replace('t_thumb', 't_cover_big') : null
        }))
    };
}

app.get('/api/metadata/search', requireAuth, async (req, res) => {
    const rawQuery = req.query.q;
    if (!rawQuery) return res.status(400).json({ error: "Missing query" });

    try {
        const { query, results } = await searchIgdb(rawQuery);
        console.log(`[IGDB] "${rawQuery}" -> "${query}" (${results.length} results)`);
        res.json(results);
    } catch (err) {
        console.error('[IGDB] Search failed:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Apply Metadata
async function applyMetadataToGame(relPath, igdbData) {
    // 1. Download Cover if exists
    if (igdbData.coverUrl) {
        const system = relPath.split('/')[0];
        const gameFileName = path.basename(relPath);
        const gameBaseName = path.parse(gameFileName).name;
        // Target: roms/[system]/media/boxart/[gameName].png
        const targetDir = path.join(ROMS_DIR, system, 'media', 'boxart');

        // Check ext from url
        const ext = path.extname(igdbData.coverUrl) || '.jpg';
        const finalPath = path.join(targetDir, `${gameBaseName}${ext}`);

        await downloadFile(igdbData.coverUrl, finalPath);
    }

    // 2. Save to Metadata JSON
    gameMetadata[relPath] = {
        ...(gameMetadata[relPath] || {}),
        title: igdbData.name,
        summary: igdbData.summary,
        igdbId: igdbData.id,
        releaseDate: igdbData.first_release_date
    };
    fs.writeFileSync(METADATA_FILE, JSON.stringify(gameMetadata, null, 2));
}

app.post('/api/metadata/apply', requireAuth, async (req, res) => {
    const relPath = normalizeSaveRelativePath(req.body.relPath);
    const { igdbData } = req.body;
    if (!relPath || !igdbData) return res.status(400).json({ error: "Missing or invalid data" });

    console.log(`[Apply] Applying to ${relPath}`);

    try {
        await applyMetadataToGame(relPath, igdbData);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to apply metadata" });
    }
});

// --- Unattended artwork/metadata scan ---
// The scan is a background job rather than one long request: a full library is
// hundreds of IGDB round trips at a rate limit of 4/second, far past any
// sensible HTTP timeout. Clients start it, then poll for progress.
const IGDB_REQUEST_SPACING_MS = 300;
let autoScanJob = null;

function autoScanSnapshot() {
    if (!autoScanJob) return { running: false, started: false };
    return {
        running: autoScanJob.running,
        started: true,
        startedAt: autoScanJob.startedAt,
        finishedAt: autoScanJob.finishedAt,
        cancelled: autoScanJob.cancelled,
        total: autoScanJob.total,
        processed: autoScanJob.processed,
        applied: autoScanJob.applied,
        failed: autoScanJob.failed,
        current: autoScanJob.current,
        error: autoScanJob.error,
        // Everything the confidence check refused to decide, for manual review.
        review: autoScanJob.review
    };
}

async function runAutoScan(job) {
    for (const game of job.queue) {
        if (job.cancelled) break;
        job.current = game.name;

        try {
            const { query, results } = await searchIgdb(game.originalName || game.name);
            if (results.length === 0) {
                job.review.push({ relPath: game.relPath, name: game.name, query, candidates: [], reason: 'no-results' });
            } else {
                const match = pickConfidentMatch(query, results, game.system);
                if (match) {
                    await applyMetadataToGame(game.relPath, match);
                    job.applied += 1;
                } else {
                    job.review.push({ relPath: game.relPath, name: game.name, query, candidates: results.slice(0, 10), reason: 'ambiguous' });
                }
            }
        } catch (err) {
            console.error(`[AutoScan] ${game.relPath}: ${err.message}`);
            job.failed += 1;
            job.review.push({ relPath: game.relPath, name: game.name, query: game.originalName, candidates: [], reason: 'error' });
        }

        job.processed += 1;
        if (!job.cancelled) await new Promise(resolve => setTimeout(resolve, IGDB_REQUEST_SPACING_MS));
    }

    job.running = false;
    job.current = null;
    job.finishedAt = Date.now();
    console.log(`[AutoScan] Finished: ${job.applied} applied, ${job.review.length} for review, ${job.failed} failed`);
}

app.post('/api/metadata/autoscan', requireAuth, (req, res) => {
    if (autoScanJob && autoScanJob.running) return res.status(409).json({ error: 'A scan is already running', status: autoScanSnapshot() });

    const includeDlc = req.body && req.body.includeDlc === true;
    const queue = buildGameList().filter(game => {
        if (!includeDlc && game.isDlc) return false;
        return !game.hasMetadata || !game.artworkPath;
    });

    autoScanJob = {
        running: true,
        cancelled: false,
        startedAt: Date.now(),
        finishedAt: null,
        queue,
        total: queue.length,
        processed: 0,
        applied: 0,
        failed: 0,
        current: null,
        error: null,
        review: []
    };

    console.log(`[AutoScan] Starting for ${queue.length} items (includeDlc=${includeDlc})`);
    runAutoScan(autoScanJob).catch(err => {
        console.error('[AutoScan] Aborted:', err.message);
        autoScanJob.running = false;
        autoScanJob.error = err.message;
        autoScanJob.finishedAt = Date.now();
    });

    res.status(202).json(autoScanSnapshot());
});

app.get('/api/metadata/autoscan/status', requireAuth, (req, res) => {
    res.json(autoScanSnapshot());
});

app.post('/api/metadata/autoscan/cancel', requireAuth, (req, res) => {
    if (autoScanJob && autoScanJob.running) autoScanJob.cancelled = true;
    res.json(autoScanSnapshot());
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
    manifest.saves = scanDir(userSavesDir, { skipTextFiles: false });

    // 3. Bios
    manifest.bios = scanDir(BIOS_DIR);

    res.json(manifest);
});

app.get('/api/system', (req, res) => res.json({ status: 'online', mode: 'native_api', storage_root: EMULATION_DIR }));

app.listen(PORT, () => {
    console.log(`RomStore Native Backend running on port ${PORT}`);
});
