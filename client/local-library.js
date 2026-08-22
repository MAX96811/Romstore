const fs = require('fs');
const path = require('path');

const LIBRARY_SECTIONS = ['roms', 'bios', 'saves'];

function normalizeLibraryPath(value) {
    return String(value || '')
        .replace(/\\/g, '/')
        .replace(/^\.\//, '')
        .replace(/^\/+/, '')
        .replace(/\/{2,}/g, '/')
        .toLowerCase();
}

function normalizeSaveRelativePath(value) {
    if (typeof value !== 'string' || !value || value.includes('\0')) return null;
    const slashPath = value.replace(/\\/g, '/');
    if (slashPath.startsWith('/') || /^[A-Za-z]:\//.test(slashPath)) return null;
    const parts = slashPath.split('/').filter(Boolean);
    if (!parts.length || parts.some(part => part === '.' || part === '..')) return null;
    return parts.join('/');
}

function scanLocalEmulation(baseDir) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];

    let resolvedBase;
    try {
        resolvedBase = fs.realpathSync(baseDir);
    } catch (error) {
        return [];
    }

    const results = [];
    const visitedDirectories = new Set();

    function walk(physicalDir, logicalParts) {
        let resolvedDir;
        try {
            resolvedDir = fs.realpathSync(physicalDir);
        } catch (error) {
            return;
        }
        if (visitedDirectories.has(resolvedDir)) return;
        visitedDirectories.add(resolvedDir);

        let entries;
        try {
            entries = fs.readdirSync(resolvedDir, { withFileTypes: true });
        } catch (error) {
            return;
        }

        for (const entry of entries) {
            if (entry.name.startsWith('.') || entry.name.toLowerCase().endsWith('.txt')) continue;

            const physicalPath = path.join(resolvedDir, entry.name);
            const logicalPath = [...logicalParts, entry.name];
            let stats;
            try {
                stats = entry.isSymbolicLink() ? fs.statSync(physicalPath) : fs.lstatSync(physicalPath);
            } catch (error) {
                continue;
            }

            if (stats.isDirectory()) {
                walk(physicalPath, logicalPath);
            } else if (stats.isFile()) {
                results.push(logicalPath.join('/'));
            }
        }
    }

    for (const section of LIBRARY_SECTIONS) {
        const sectionPath = path.join(resolvedBase, section);
        if (fs.existsSync(sectionPath)) walk(sectionPath, [section]);
    }

    return results;
}

function scanDirectoryStats(baseDir) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];

    let resolvedBase;
    try {
        resolvedBase = fs.realpathSync(baseDir);
    } catch (error) {
        return [];
    }

    const results = [];
    const visitedDirectories = new Set();

    function walk(physicalDir, logicalParts) {
        let resolvedDir;
        try {
            resolvedDir = fs.realpathSync(physicalDir);
        } catch (error) {
            return;
        }
        if (visitedDirectories.has(resolvedDir)) return;
        visitedDirectories.add(resolvedDir);

        let entries;
        try {
            entries = fs.readdirSync(resolvedDir, { withFileTypes: true });
        } catch (error) {
            return;
        }

        for (const entry of entries) {
            if (entry.name.startsWith('.') || entry.name.toLowerCase().endsWith('.txt')) continue;

            const physicalPath = path.join(resolvedDir, entry.name);
            const logicalPath = [...logicalParts, entry.name];
            let stats;
            try {
                stats = entry.isSymbolicLink() ? fs.statSync(physicalPath) : fs.lstatSync(physicalPath);
            } catch (error) {
                continue;
            }

            if (stats.isDirectory()) {
                walk(physicalPath, logicalPath);
            } else if (stats.isFile()) {
                results.push({ relPath: logicalPath.join('/'), mtime: stats.mtime });
            }
        }
    }

    walk(resolvedBase, []);
    return results;
}

function buildInstalledPathSet(paths) {
    return new Set((paths || []).map(normalizeLibraryPath).filter(Boolean));
}

function isLibraryItemInstalled(installedPaths, section, relativePath) {
    const normalizedSection = normalizeLibraryPath(section).replace(/\/$/, '');
    const normalizedRelativePath = normalizeLibraryPath(relativePath);
    if (!normalizedSection || !normalizedRelativePath) return false;
    return installedPaths.has(`${normalizedSection}/${normalizedRelativePath}`);
}

// Offline listing. The server decides what counts as a game in
// lib/rom-library.js, driven by each platform's systeminfo.txt; that file is
// on this disk too, so the same rules can be applied locally when the server
// cannot be reached. Keep these rules in step with lib/rom-library.js.
const OFFLINE_IGNORED_DIRECTORIES = new Set([
    '.tmp', '.tmp_chunks', 'artwork', 'boxart', 'covers', 'downloaded_media',
    'emulators', 'images', 'manuals', 'media', 'screenshots', 'videos'
]);
const OFFLINE_IGNORED_FILES = new Set(['metadata.txt', 'systeminfo.txt']);

function readSupportedExtensions(systemPath) {
    const infoPath = path.join(systemPath, 'systeminfo.txt');
    let text;
    try { text = fs.readFileSync(infoPath, 'utf8'); } catch (error) { return []; }

    const lines = String(text).split(/\r?\n/);
    const index = lines.findIndex(line => line.trim().toLowerCase() === 'supported file extensions:');
    if (index === -1) return [];

    const collected = [];
    for (let i = index + 1; i < lines.length; i++) {
        const value = lines[i].trim();
        if (!value) { if (collected.length) break; continue; }
        if (/^[A-Za-z][A-Za-z ()/-]*:$/.test(value)) break;
        collected.push(value);
    }
    return Array.from(new Set(collected.join(' ').split(/\s+/)
        .map(value => value.trim().toLowerCase())
        .filter(value => /^\.[a-z0-9][a-z0-9+_-]*$/.test(value))));
}

function scanLocalGames(baseDir) {
    const romsDir = path.join(String(baseDir || ''), 'roms');
    if (!baseDir || !fs.existsSync(romsDir)) return [];

    const games = [];
    let systems = [];
    try {
        systems = fs.readdirSync(romsDir, { withFileTypes: true })
            .filter(entry => entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'emulators');
    } catch (error) { return []; }

    for (const systemEntry of systems) {
        const systemPath = path.join(romsDir, systemEntry.name);
        const supported = new Set(readSupportedExtensions(systemPath));

        (function walk(currentPath) {
            let entries;
            try { entries = fs.readdirSync(currentPath, { withFileTypes: true }); } catch (error) { return; }
            for (const entry of entries) {
                const lowerName = entry.name.toLowerCase();
                if (entry.name.startsWith('.') || OFFLINE_IGNORED_FILES.has(lowerName)) continue;
                if (entry.isSymbolicLink()) continue;
                const fullPath = path.join(currentPath, entry.name);
                if (entry.isDirectory()) {
                    if (!OFFLINE_IGNORED_DIRECTORIES.has(lowerName)) walk(fullPath);
                    continue;
                }
                if (!entry.isFile()) continue;
                const extension = path.extname(entry.name).toLowerCase();
                if (supported.size && !supported.has(extension)) continue;
                if (!supported.size && /\.(?:jpe?g|png|gif|webp|mp4|webm|pdf|txt|sh|bat|cfg|ini|json|log)$/i.test(entry.name)) continue;
                games.push({
                    relPath: path.relative(romsDir, fullPath).replace(/\\/g, '/'),
                    name: entry.name,
                    originalName: entry.name,
                    system: systemEntry.name
                });
            }
        })(systemPath);
    }
    return games.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

module.exports = {
    scanLocalGames,
    LIBRARY_SECTIONS,
    buildInstalledPathSet,
    isLibraryItemInstalled,
    normalizeLibraryPath,
    normalizeSaveRelativePath,
    scanDirectoryStats,
    scanLocalEmulation
};
