const fs = require('fs');
const { scanCanonicalFiles } = require('./save-paths');

const TITLE_ID_PATTERN = /^[0-9A-F]{16}$/;
const RYUJINX_SLOT_PATTERN = /(?:^|\/)ryujinx\/(?:saves|savemeta)\/([0-9a-f]{16})(?:\/|$)/i;

function normalizeSwitchTitleId(value) {
    const titleId = String(value || '').trim().toUpperCase();
    return TITLE_ID_PATTERN.test(titleId) ? titleId : null;
}

function parseRyujinxTitleId(extraData) {
    if (!Buffer.isBuffer(extraData) || extraData.length < 0x48) return null;
    const applicationId = extraData.readBigUInt64LE(0);
    const ownerId = extraData.readBigUInt64LE(0x40);
    if (applicationId !== ownerId) return null;
    const titleId = applicationId.toString(16).padStart(16, '0').toUpperCase();
    // Application IDs are 0100-prefixed. Reject empty/system/slot identifiers.
    return titleId.startsWith('0100') && TITLE_ID_PATTERN.test(titleId) ? titleId : null;
}

function getRyujinxSlotId(saveRelPath) {
    const match = String(saveRelPath || '').replace(/\\/g, '/').match(RYUJINX_SLOT_PATTERN);
    return match ? match[1].toUpperCase() : null;
}

function buildRyujinxSlotTitleMap(userSavesDir, manualMap = {}) {
    const result = {};
    const extraDataFiles = scanCanonicalFiles(userSavesDir, {
        skipEntry: entry => entry.name.startsWith('.')
    }).filter(file => /^ryujinx\/saves\/[0-9a-f]{16}\/ExtraData[01]$/i.test(file.relPath));

    for (const file of extraDataFiles) {
        const slotId = getRyujinxSlotId(file.relPath);
        if (!slotId || result[slotId]) continue;
        try {
            const titleId = parseRyujinxTitleId(fs.readFileSync(file.physicalPath));
            if (titleId) result[slotId] = titleId;
        } catch (error) { }
    }

    // Explicit administrator mappings are the fallback for formats that do not
    // expose ExtraData. Valid explicit mappings intentionally override discovery.
    for (const [rawSlotId, rawTitleId] of Object.entries(manualMap || {})) {
        const slotId = normalizeSwitchTitleId(rawSlotId);
        const titleId = normalizeSwitchTitleId(rawTitleId);
        if (slotId && titleId) result[slotId] = titleId;
    }
    return result;
}

function getSwitchTitleIdFromSavePath(saveRelPath, slotTitleMap = {}, manualMap = {}) {
    const normalizedPath = String(saveRelPath || '').replace(/\\/g, '/');
    const ids = normalizedPath
        .split('/')
        .map(normalizeSwitchTitleId)
        .filter(Boolean);
    const applicationId = ids.find(id => id.startsWith('0100'));
    if (applicationId) return applicationId;

    const slotId = getRyujinxSlotId(normalizedPath);
    if (slotId) {
        return normalizeSwitchTitleId(slotTitleMap[slotId]) || normalizeSwitchTitleId(manualMap[slotId]);
    }

    for (const id of ids) {
        const mapped = normalizeSwitchTitleId(manualMap[id]);
        if (mapped) return mapped;
    }
    return null;
}

module.exports = {
    buildRyujinxSlotTitleMap,
    getRyujinxSlotId,
    getSwitchTitleIdFromSavePath,
    normalizeSwitchTitleId,
    parseRyujinxTitleId
};
