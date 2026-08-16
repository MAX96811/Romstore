const fs = require('fs');
const path = require('path');

function normalizeSaveRelativePath(value) {
    if (typeof value !== 'string' || !value || value.includes('\0')) return null;

    const slashPath = value.replace(/\\/g, '/');
    if (slashPath.startsWith('/') || /^[A-Za-z]:\//.test(slashPath)) return null;

    const parts = slashPath.split('/').filter(Boolean);
    if (!parts.length || parts.some(part => part === '.' || part === '..')) return null;
    return parts.join('/');
}

function resolveContainedSavePath(baseDir, relativePath) {
    const normalized = normalizeSaveRelativePath(relativePath);
    if (!normalized) return null;

    const base = path.resolve(baseDir);
    const resolved = path.resolve(base, ...normalized.split('/'));
    if (resolved !== base && !resolved.startsWith(base + path.sep)) return null;

    // A lexical prefix is not sufficient: an existing symlink anywhere below
    // the storage root could redirect reads or writes outside that root.
    let current = base;
    for (const part of normalized.split('/')) {
        current = path.join(current, part);
        if (!fs.existsSync(current)) continue;
        try {
            if (fs.lstatSync(current).isSymbolicLink()) return null;
        } catch (error) {
            return null;
        }
    }
    return { relativePath: normalized, fullPath: resolved };
}

function scanCanonicalFiles(baseDir, options = {}) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];

    const skipEntry = typeof options.skipEntry === 'function' ? options.skipEntry : () => false;
    const byLogicalPath = new Map();

    function walk(physicalDir, rawParts) {
        let entries;
        try {
            entries = fs.readdirSync(physicalDir, { withFileTypes: true });
        } catch (error) {
            return;
        }

        for (const entry of entries) {
            const nextRawParts = [...rawParts, entry.name];
            if (skipEntry(entry, nextRawParts)) continue;

            const physicalPath = path.join(physicalDir, entry.name);
            let stats;
            try {
                if (entry.isSymbolicLink()) continue;
                stats = fs.lstatSync(physicalPath);
            } catch (error) {
                continue;
            }

            if (stats.isDirectory()) {
                walk(physicalPath, nextRawParts);
                continue;
            }
            if (!stats.isFile()) continue;

            const rawRelativePath = nextRawParts.join('/');
            const logicalPath = normalizeSaveRelativePath(rawRelativePath);
            if (!logicalPath) continue;

            const isCanonical = nextRawParts.every(part => !part.includes('\\'));
            const candidate = {
                relPath: logicalPath,
                rawRelativePath,
                physicalPath,
                stats,
                isLegacyBackslashPath: !isCanonical
            };
            const current = byLogicalPath.get(logicalPath);

            // Always trust a genuinely nested path over a legacy Linux filename that
            // contains literal Windows separators. Never pick based on timestamps.
            if (!current || (current.isLegacyBackslashPath && isCanonical)) {
                byLogicalPath.set(logicalPath, candidate);
            }
        }
    }

    walk(path.resolve(baseDir), []);
    return [...byLogicalPath.values()].sort((a, b) => a.relPath.localeCompare(b.relPath));
}

function findCanonicalFile(baseDir, relativePath, options = {}) {
    const normalized = normalizeSaveRelativePath(relativePath);
    if (!normalized) return null;
    const direct = resolveContainedSavePath(baseDir, normalized);
    if (direct && fs.existsSync(direct.fullPath)) {
        try {
            if (fs.statSync(direct.fullPath).isFile()) return direct.fullPath;
        } catch (error) { }
    }

    const match = scanCanonicalFiles(baseDir, options).find(file => file.relPath === normalized);
    return match ? match.physicalPath : null;
}

function inventoryLegacyBackslashFiles(baseDir) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];
    const legacy = [];

    function walk(physicalDir, rawParts) {
        let entries;
        try {
            entries = fs.readdirSync(physicalDir, { withFileTypes: true });
        } catch (error) {
            return;
        }

        for (const entry of entries) {
            if (entry.name.startsWith('.')) continue;
            const parts = [...rawParts, entry.name];
            const physicalPath = path.join(physicalDir, entry.name);
            let stats;
            try {
                if (entry.isSymbolicLink()) continue;
                stats = fs.lstatSync(physicalPath);
            } catch (error) { continue; }
            if (stats.isDirectory()) {
                walk(physicalPath, parts);
                continue;
            }
            if (!stats.isFile() || !parts.some(part => part.includes('\\'))) continue;

            const relPath = normalizeSaveRelativePath(parts.join('/'));
            const target = relPath ? resolveContainedSavePath(baseDir, relPath) : null;
            if (!relPath || !target) continue;
            legacy.push({
                relPath,
                physicalPath,
                canonicalPath: target.fullPath,
                canonicalExists: fs.existsSync(target.fullPath),
                size: stats.size
            });
        }
    }

    walk(path.resolve(baseDir), []);
    return legacy.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

function materializeLegacyBackslashFiles(baseDir) {
    const report = { copied: [], existing: [], failed: [] };
    for (const item of inventoryLegacyBackslashFiles(baseDir)) {
        if (item.canonicalExists) {
            report.existing.push(item);
            continue;
        }

        try {
            fs.mkdirSync(path.dirname(item.canonicalPath), { recursive: true });
            fs.copyFileSync(item.physicalPath, item.canonicalPath, fs.constants.COPYFILE_EXCL);
            const sourceStats = fs.statSync(item.physicalPath);
            const copiedStats = fs.statSync(item.canonicalPath);
            if (sourceStats.size !== copiedStats.size) {
                throw new Error('Copied size does not match source');
            }
            fs.utimesSync(item.canonicalPath, sourceStats.atime, sourceStats.mtime);
            report.copied.push(item);
        } catch (error) {
            report.failed.push({ ...item, error: error.message });
        }
    }
    return report;
}

module.exports = {
    findCanonicalFile,
    inventoryLegacyBackslashFiles,
    materializeLegacyBackslashFiles,
    normalizeSaveRelativePath,
    resolveContainedSavePath,
    scanCanonicalFiles
};
