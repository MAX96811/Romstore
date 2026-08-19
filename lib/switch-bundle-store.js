const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { normalizeSaveRelativePath } = require('./save-paths');
const { normalizeSwitchTitleId, parseRyujinxTitleId } = require('./switch-saves');

function validateBundleUpload({ slotId: rawSlotId, titleId: rawTitleId, files }) {
    const slotId = normalizeSwitchTitleId(rawSlotId);
    const titleId = normalizeSwitchTitleId(rawTitleId);
    if (!slotId || !titleId) throw new Error('Invalid Switch bundle identity.');
    if (!Array.isArray(files) || !files.length) throw new Error('Switch bundle is empty.');

    const seen = new Set();
    const normalizedFiles = files.map(file => {
        const relPath = normalizeSaveRelativePath(file && file.relPath);
        if (!relPath || seen.has(relPath)) throw new Error('Switch bundle contains an invalid or duplicate path.');
        seen.add(relPath);

        const parts = relPath.split('/');
        const component = String(parts[1] || '').toLowerCase();
        if (String(parts[0] || '').toLowerCase() !== 'ryujinx'
            || !['saves', 'savemeta'].includes(component)
            || String(parts[2] || '').toUpperCase() !== slotId
            || parts.length < 4
            || parts.slice(3).some(part => part.startsWith('.'))) {
            throw new Error(`Path does not belong to Ryujinx slot ${slotId}.`);
        }
        if (!file.tempPath || !fs.existsSync(file.tempPath)) throw new Error(`Uploaded data is missing for ${relPath}.`);
        return { ...file, relPath, component, insideSlot: parts.slice(3).join('/') };
    });

    const extraDataFiles = normalizedFiles.filter(file => file.component === 'saves' && /^ExtraData[01]$/i.test(file.insideSlot));
    if (!extraDataFiles.length) throw new Error('Switch bundle is missing Ryujinx ExtraData.');
    for (const extraData of extraDataFiles) {
        const embeddedTitleId = parseRyujinxTitleId(fs.readFileSync(extraData.tempPath));
        if (embeddedTitleId !== titleId) throw new Error('Switch bundle Title ID does not match every ExtraData copy.');
    }
    return { slotId, titleId, files: normalizedFiles };
}

function readExistingBundleTitleId(userSavesDir, slotId) {
    for (const name of ['ExtraData0', 'ExtraData1']) {
        try {
            const value = parseRyujinxTitleId(fs.readFileSync(path.join(userSavesDir, 'ryujinx', 'saves', slotId, name)));
            if (value) return value;
        } catch (error) { }
    }
    return null;
}

function pruneBundleGenerations(userSavesDir, titleId, slotId, keep = 10) {
    const generationsRoot = path.join(userSavesDir, '.switch-bundle-versions', titleId, slotId);
    if (!fs.existsSync(generationsRoot)) return [];
    const generations = fs.readdirSync(generationsRoot, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && !entry.isSymbolicLink())
        .map(entry => entry.name)
        .sort((a, b) => b.localeCompare(a));
    const removed = [];
    for (const generation of generations.slice(Math.max(0, keep))) {
        const generationPath = path.join(generationsRoot, generation);
        fs.rmSync(generationPath, { recursive: true, force: true });
        removed.push(generation);
    }
    return removed;
}

function activateBundleUpload({
    userSavesDir,
    slotId,
    titleId,
    files,
    now = () => new Date(),
    nonce = () => crypto.randomBytes(5).toString('hex')
}) {
    const bundle = validateBundleUpload({ slotId, titleId, files });
    const existingTitleId = readExistingBundleTitleId(userSavesDir, bundle.slotId);

    // Ryujinx reuses slot numbers across games, so a slot number is not a stable
    // identity. When a slot has changed hands, the previous contents are archived
    // under THEIR OWN title rather than rejected: neither game loses its history,
    // and the incoming bundle is still the one that goes live. Rejecting instead
    // would strand every future upload for the slot's new owner.
    const adoptedFromTitleId = existingTitleId && existingTitleId !== bundle.titleId ? existingTitleId : null;
    // The archive holds what was there BEFORE this upload, so it is always keyed
    // by the outgoing owner - which equals the incoming title in the normal case.
    const archiveTitleId = existingTitleId || bundle.titleId;

    const stamp = now().toISOString().replace(/[:.]/g, '-');
    const generation = `${stamp}-${nonce()}`;
    const stageRoot = path.join(userSavesDir, '.switch-staging', generation);
    const archiveRoot = path.join(userSavesDir, '.switch-bundle-versions', archiveTitleId, bundle.slotId, generation);
    const componentNames = new Map([['saves', 'saves'], ['savemeta', 'saveMeta']]);
    const components = new Set(['saves', 'saveMeta']);

    for (const file of bundle.files) {
        const componentName = componentNames.get(file.component);
        const stageFile = path.join(stageRoot, componentName, ...file.insideSlot.split('/'));
        fs.mkdirSync(path.dirname(stageFile), { recursive: true });
        fs.copyFileSync(file.tempPath, stageFile);
        if (fs.statSync(stageFile).size !== fs.statSync(file.tempPath).size) {
            throw new Error(`Could not verify staged file ${file.relPath}.`);
        }
    }

    const activated = [];
    try {
        for (const componentName of components) {
            const componentRoot = path.join(userSavesDir, 'ryujinx', componentName);
            const targetPath = path.join(componentRoot, bundle.slotId);
            const stagePath = path.join(stageRoot, componentName);
            const archivePath = path.join(archiveRoot, componentName);
            fs.mkdirSync(componentRoot, { recursive: true });
            fs.mkdirSync(path.dirname(archivePath), { recursive: true });
            const hadExisting = fs.existsSync(targetPath);
            if (hadExisting) fs.renameSync(targetPath, archivePath);
            const hasReplacement = fs.existsSync(stagePath);
            try {
                if (hasReplacement) fs.renameSync(stagePath, targetPath);
            } catch (error) {
                if (hadExisting && fs.existsSync(archivePath) && !fs.existsSync(targetPath)) {
                    fs.renameSync(archivePath, targetPath);
                }
                throw error;
            }
            activated.push({ targetPath, archivePath, hadExisting, componentName });
        }
    } catch (error) {
        for (const item of activated.reverse()) {
            const failedPath = path.join(stageRoot, `${item.componentName}-failed`);
            if (fs.existsSync(item.targetPath)) fs.renameSync(item.targetPath, failedPath);
            if (item.hadExisting && fs.existsSync(item.archivePath)) fs.renameSync(item.archivePath, item.targetPath);
        }
        throw error;
    }

    try { fs.rmSync(stageRoot, { recursive: true, force: true }); } catch (error) { }
    pruneBundleGenerations(userSavesDir, archiveTitleId, bundle.slotId);

    return {
        success: true,
        generation,
        slotId: bundle.slotId,
        titleId: bundle.titleId,
        fileCount: bundle.files.length,
        archivedPrevious: activated.some(item => item.hadExisting),
        adoptedFromTitleId
    };
}

module.exports = {
    activateBundleUpload,
    pruneBundleGenerations,
    readExistingBundleTitleId,
    validateBundleUpload
};
