const fs = require('fs');
const path = require('path');

function normalizeSwitchTitleId(value) {
    const titleId = String(value || '').trim().toUpperCase();
    return /^[0-9A-F]{16}$/.test(titleId) ? titleId : null;
}

function normalizeGameTitle(value) {
    return String(value || '')
        .replace(/\.(?:xci|xcz|nsp|nsz|nro|zip|7z)$/i, '')
        .replace(/\[[0-9a-f]{16}\]/ig, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
}

function parseRyujinxTitleId(extraData) {
    if (!Buffer.isBuffer(extraData) || extraData.length < 0x48) return null;
    const applicationId = extraData.readBigUInt64LE(0);
    const ownerId = extraData.readBigUInt64LE(0x40);
    if (applicationId !== ownerId) return null;
    const titleId = applicationId.toString(16).padStart(16, '0').toUpperCase();
    return titleId.startsWith('0100') ? normalizeSwitchTitleId(titleId) : null;
}

function discoverMetadataRoots(homeDir, emulationDir) {
    return [
        path.join(homeDir, '.config', 'Ryujinx', 'games'),
        path.join(homeDir, '.config', 'Ryubing', 'games'),
        path.join(homeDir, '.var', 'app', 'io.github.ryubing.Ryujinx', 'config', 'Ryujinx', 'games'),
        path.join(homeDir, '.var', 'app', 'org.ryujinx.Ryujinx', 'config', 'Ryujinx', 'games'),
        emulationDir ? path.join(emulationDir, 'storage', 'ryujinx', 'games') : null
    ].filter(Boolean);
}

function discoverSwitchAssociations({ homeDir, emulationDir } = {}) {
    const gamesById = new Map();
    const slotsById = new Map();

    for (const root of discoverMetadataRoots(homeDir || '', emulationDir)) {
        if (!fs.existsSync(root)) continue;
        let entries = [];
        try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (error) { entries = []; }
        for (const entry of entries) {
            const titleId = normalizeSwitchTitleId(entry.name);
            if (!titleId || !entry.isDirectory()) continue;
            const metadataPath = path.join(root, entry.name, 'gui', 'metadata.json');
            try {
                const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
                const title = String(metadata.title || metadata.name || '').trim();
                if (title && !gamesById.has(titleId)) gamesById.set(titleId, { titleId, title });
            } catch (error) { }
        }
    }

    const slotsRoot = emulationDir ? path.join(emulationDir, 'saves', 'ryujinx', 'saves') : null;
    if (slotsRoot && fs.existsSync(slotsRoot)) {
        let entries = [];
        try { entries = fs.readdirSync(slotsRoot, { withFileTypes: true }); } catch (error) { entries = []; }
        for (const entry of entries) {
            const slotId = normalizeSwitchTitleId(entry.name);
            if (!slotId || !entry.isDirectory()) continue;
            for (const extraDataName of ['ExtraData0', 'ExtraData1']) {
                try {
                    const titleId = parseRyujinxTitleId(fs.readFileSync(path.join(slotsRoot, entry.name, extraDataName)));
                    if (titleId) {
                        slotsById.set(slotId, { slotId, titleId });
                        break;
                    }
                } catch (error) { }
            }
        }
    }

    return {
        games: [...gamesById.values()].sort((a, b) => a.title.localeCompare(b.title)),
        slots: [...slotsById.values()].sort((a, b) => a.slotId.localeCompare(b.slotId))
    };
}

function collectSwitchBundleFiles(emulationDir, slotIdValue) {
    const slotId = normalizeSwitchTitleId(slotIdValue);
    if (!emulationDir || !slotId) throw new Error('Invalid local Switch save identity.');
    const files = [];

    for (const componentName of ['saves', 'saveMeta']) {
        const slotRoot = path.join(emulationDir, 'saves', 'ryujinx', componentName, slotId);
        if (!fs.existsSync(slotRoot)) continue;

        function walk(directory, logicalParts) {
            let entries = [];
            try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch (error) { entries = []; }
            for (const entry of entries) {
                if (entry.name.startsWith('.') || entry.name === '.lock') continue;
                const fullPath = path.join(directory, entry.name);
                if (entry.isSymbolicLink()) continue;
                if (entry.isDirectory()) {
                    walk(fullPath, [...logicalParts, entry.name]);
                } else if (entry.isFile()) {
                    const stats = fs.statSync(fullPath);
                    files.push({
                        relPath: ['ryujinx', componentName, slotId, ...logicalParts, entry.name].join('/'),
                        fullPath,
                        sizeBytes: stats.size
                    });
                }
            }
        }

        walk(slotRoot, []);
    }

    files.sort((a, b) => a.relPath.localeCompare(b.relPath));
    if (!files.some(file => /\/ExtraData[01]$/i.test(file.relPath))) {
        throw new Error('The local Ryujinx save candidate is incomplete.');
    }
    return files;
}

function matchSwitchTitleId(game, associations) {
    const explicit = normalizeSwitchTitleId(game && game.switchTitleId);
    if (explicit) return explicit;

    const filenameMatch = `${game?.relPath || ''} ${game?.originalName || ''}`.match(/\[([0-9a-f]{16})\]/i);
    if (filenameMatch) return filenameMatch[1].toUpperCase();

    const candidates = new Set([
        normalizeGameTitle(game && game.name),
        normalizeGameTitle(game && game.originalName)
    ].filter(Boolean));
    const exact = (associations?.games || []).find(item => candidates.has(normalizeGameTitle(item.title)));
    return exact ? exact.titleId : null;
}

module.exports = {
    collectSwitchBundleFiles,
    discoverSwitchAssociations,
    matchSwitchTitleId,
    normalizeGameTitle,
    normalizeSwitchTitleId,
    parseRyujinxTitleId
};
