const fs = require('fs');
const path = require('path');

const IGNORED_DIRECTORIES = new Set([
    '.tmp',
    '.tmp_chunks',
    'artwork',
    'boxart',
    'covers',
    'downloaded_media',
    'emulators',
    'images',
    'manuals',
    'media',
    'screenshots',
    'videos'
]);

// Folders whose contents are add-on content rather than games. They are still
// scanned and served -- DLC has to be downloadable to be installable -- but
// everything inside is tagged so the library can keep it out of the main grid.
const DLC_DIRECTORIES = new Set(['dlc', 'dlcs', 'updates', 'update']);

const IGNORED_FILES = new Set([
    'metadata.txt',
    'systeminfo.txt'
]);

// True when any directory segment of the path is a DLC folder. The filename
// itself is deliberately not consulted: the folder is what the user controls.
function isDlcRelPath(relPath) {
    const segments = String(relPath || '').split(/[\\/]+/).slice(0, -1);
    return segments.some(segment => DLC_DIRECTORIES.has(segment.toLowerCase()));
}

// Used on upload, where there is no folder to read yet, only the name the file
// arrived under. Matches the `[DLC ...]` marker the common Switch dump tools
// write, and a bare `(DLC)`/`[DLC]` tag.
function looksLikeDlcFileName(fileName) {
    return /[\[\(]\s*dlc\b/i.test(String(fileName || ''));
}

function readSection(lines, heading) {
    const index = lines.findIndex(line => line.trim().toLowerCase() === heading.toLowerCase());
    if (index === -1) return [];

    const values = [];
    for (let i = index + 1; i < lines.length; i++) {
        const value = lines[i].trim();
        if (!value) {
            if (values.length) break;
            continue;
        }
        if (/^[A-Za-z][A-Za-z ()/-]*:$/.test(value)) break;
        values.push(value);
    }
    return values;
}

function parseSystemInfo(text) {
    const lines = String(text || '').split(/\r?\n/);
    const system = readSection(lines, 'System name:')[0] || '';
    const fullName = readSection(lines, 'Full system name:')[0] || system;
    const extensionLine = readSection(lines, 'Supported file extensions:').join(' ');
    const extensions = Array.from(new Set(
        extensionLine
            .split(/\s+/)
            .map(value => value.trim().toLowerCase())
            .filter(value => /^\.[a-z0-9][a-z0-9+_-]*$/.test(value))
    ));

    return { system, fullName, extensions };
}

function getPlatformInfo(systemPath, fallbackSystem) {
    const infoPath = path.join(systemPath, 'systeminfo.txt');
    if (!fs.existsSync(infoPath)) {
        return { system: fallbackSystem, fullName: fallbackSystem, extensions: [] };
    }

    try {
        const parsed = parseSystemInfo(fs.readFileSync(infoPath, 'utf8'));
        return {
            system: parsed.system || fallbackSystem,
            fullName: parsed.fullName || parsed.system || fallbackSystem,
            extensions: parsed.extensions
        };
    } catch (error) {
        return { system: fallbackSystem, fullName: fallbackSystem, extensions: [] };
    }
}

function listPlatforms(romsDir) {
    if (!fs.existsSync(romsDir)) return [];

    return fs.readdirSync(romsDir, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'emulators')
        .map(entry => {
            const systemPath = path.join(romsDir, entry.name);
            const info = getPlatformInfo(systemPath, entry.name);
            const uploadDir = resolveUploadDirectory(romsDir, entry.name);
            return {
                system: entry.name,
                fullName: info.fullName,
                extensions: info.extensions,
                uploadSubdir: path.relative(systemPath, uploadDir).replace(/\\/g, '/') || ''
            };
        })
        .sort((a, b) => a.fullName.localeCompare(b.fullName));
}

function resolveUploadDirectory(romsDir, systemName) {
    const systemPath = path.join(romsDir, systemName);
    const nestedRomsPath = path.join(systemPath, 'roms');
    if (fs.existsSync(nestedRomsPath)) {
        try {
            if (fs.statSync(nestedRomsPath).isDirectory()) return nestedRomsPath;
        } catch (error) { }
    }
    return systemPath;
}

function findGameFiles(systemPath, extensions = []) {
    if (!fs.existsSync(systemPath)) return [];
    const supported = new Set((extensions || []).map(value => value.toLowerCase()));
    const results = [];

    function walk(currentPath) {
        let entries;
        try {
            entries = fs.readdirSync(currentPath, { withFileTypes: true });
        } catch (error) {
            return;
        }

        for (const entry of entries) {
            const lowerName = entry.name.toLowerCase();
            if (entry.name.startsWith('.') || IGNORED_FILES.has(lowerName)) continue;
            if (entry.isSymbolicLink()) continue;

            const fullPath = path.join(currentPath, entry.name);
            if (entry.isDirectory()) {
                if (!IGNORED_DIRECTORIES.has(lowerName)) walk(fullPath);
                continue;
            }
            if (!entry.isFile()) continue;

            const extension = path.extname(entry.name).toLowerCase();
            if (supported.size && !supported.has(extension)) continue;
            if (!supported.size && /\.(?:jpe?g|png|gif|webp|mp4|webm|pdf|txt)$/i.test(entry.name)) continue;
            results.push(fullPath);
        }
    }

    walk(systemPath);
    return results;
}

module.exports = {
    DLC_DIRECTORIES,
    findGameFiles,
    isDlcRelPath,
    looksLikeDlcFileName,
    getPlatformInfo,
    listPlatforms,
    parseSystemInfo,
    resolveUploadDirectory
};
