const fs = require('fs');
const path = require('path');

// Nintendo Switch title IDs encode the relationship between a base game and
// its add-on content in the low 13 bits:
//   base    XXXXXXXXXXXXX000  (bits 0-12 clear)
//   update  base | 0x800      (bit 11 set)
//   DLC     base + 0x1000 + n (bit 12 set, n = 1..0xFFF)
// so every member of a family shares `id & ~0x1FFF`.
const FAMILY_MASK = ~0x1FFFn & ((1n << 64n) - 1n);

function normalizeTitleId(value) {
    const titleId = String(value || '').trim().toUpperCase();
    return /^[0-9A-F]{16}$/.test(titleId) ? titleId : null;
}

function classifySwitchTitleId(value) {
    const titleId = normalizeTitleId(value);
    if (!titleId) return null;
    const id = BigInt(`0x${titleId}`);
    const baseTitleId = (id & FAMILY_MASK).toString(16).toUpperCase().padStart(16, '0');
    let kind = 'base';
    if (id & 0x800n) kind = 'update';
    else if (id & 0x1000n) kind = 'dlc';
    return { titleId, baseTitleId, kind };
}

// Common dump-tool naming: "Name [0100152000022800][v1376256].nsp".
function parseSwitchFileName(fileName) {
    const name = path.basename(String(fileName || ''));
    const idMatch = name.match(/\[([0-9a-fA-F]{16})\]/);
    const versionMatch = name.match(/\[v(\d+)\]/i);
    return {
        titleId: idMatch ? idMatch[1].toUpperCase() : null,
        version: versionMatch ? Number(versionMatch[1]) : null,
        isDlcTagged: /[\[\(]\s*dlc\b/i.test(name)
    };
}

// Reads only the PFS0 header of an NSP. eShop-style updates and DLC carry a
// ticket named <rightsId>.tik whose first 16 hex chars are the title ID, so
// the ID can be recovered without any keys even when the file name lacks it.
function readNspTitleIds(filePath) {
    let fd;
    try {
        fd = fs.openSync(filePath, 'r');
        const header = Buffer.alloc(16);
        if (fs.readSync(fd, header, 0, 16, 0) !== 16) return [];
        if (header.toString('ascii', 0, 4) !== 'PFS0') return [];
        const fileCount = header.readUInt32LE(4);
        const stringTableSize = header.readUInt32LE(8);
        if (fileCount === 0 || fileCount > 4096 || stringTableSize > 1 << 20) return [];
        const entries = Buffer.alloc(fileCount * 24);
        fs.readSync(fd, entries, 0, entries.length, 16);
        const strings = Buffer.alloc(stringTableSize);
        fs.readSync(fd, strings, 0, stringTableSize, 16 + entries.length);
        const ids = new Set();
        for (let i = 0; i < fileCount; i++) {
            const nameOffset = entries.readUInt32LE(i * 24 + 16);
            let end = strings.indexOf(0, nameOffset);
            if (end === -1) end = strings.length;
            const name = strings.toString('utf8', nameOffset, end);
            const match = name.match(/^([0-9a-fA-F]{32})\.tik$/);
            if (match) ids.add(match[1].slice(0, 16).toUpperCase());
        }
        return [...ids];
    } catch (error) {
        return [];
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
}

function nspFileMatches(filePath) {
    return /\.(?:nsp|nsz)$/i.test(filePath);
}

// Resolves the Switch identity of a library file: file name first, then the
// embedded ticket. `metadataTitleId` is the admin override from metadata.json.
function resolveSwitchIdentity({ filePath, relPath, metadataTitleId }) {
    const parsed = parseSwitchFileName(relPath || filePath);
    let titleId = parsed.titleId || normalizeTitleId(metadataTitleId);
    let source = parsed.titleId ? 'filename' : (titleId ? 'metadata' : null);
    if (!titleId && filePath && nspFileMatches(filePath)) {
        const [ticketId] = readNspTitleIds(filePath);
        if (ticketId) {
            titleId = ticketId;
            source = 'ticket';
        }
    }
    const classified = titleId ? classifySwitchTitleId(titleId) : null;
    return {
        titleId,
        source,
        version: parsed.version,
        kind: classified ? classified.kind : null,
        baseTitleId: classified ? classified.baseTitleId : null
    };
}

// Groups add-on entries under their base game. `entries` carry the fields
// resolveSwitchIdentity returns plus whatever the caller wants echoed back.
// Returns Map<baseTitleId, { updates: [...], dlc: [...] }>, updates sorted
// newest-first so [0] is the one an emulator should apply.
function buildAddonIndex(entries) {
    const index = new Map();
    for (const entry of entries) {
        if (!entry || !entry.baseTitleId || entry.kind === 'base' || !entry.kind) continue;
        if (!index.has(entry.baseTitleId)) index.set(entry.baseTitleId, { updates: [], dlc: [] });
        const family = index.get(entry.baseTitleId);
        (entry.kind === 'update' ? family.updates : family.dlc).push(entry);
    }
    for (const family of index.values()) {
        family.updates.sort((a, b) => (b.version || 0) - (a.version || 0));
        family.dlc.sort((a, b) => String(a.titleId).localeCompare(String(b.titleId)));
    }
    return index;
}

// What a client should install for a base game: the newest update plus every
// DLC. Older updates are superseded and skipped.
function selectAddonsForBase(index, baseTitleId) {
    const family = index.get(baseTitleId);
    if (!family) return [];
    const picks = [];
    if (family.updates.length) picks.push(family.updates[0]);
    return picks.concat(family.dlc);
}

module.exports = {
    buildAddonIndex,
    classifySwitchTitleId,
    normalizeTitleId,
    parseSwitchFileName,
    readNspTitleIds,
    resolveSwitchIdentity,
    selectAddonsForBase
};
