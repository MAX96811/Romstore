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

module.exports = {
    LIBRARY_SECTIONS,
    buildInstalledPathSet,
    isLibraryItemInstalled,
    normalizeLibraryPath,
    scanDirectoryStats,
    scanLocalEmulation
};
