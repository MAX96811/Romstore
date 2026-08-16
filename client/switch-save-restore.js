const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { normalizeSaveRelativePath } = require('./local-library');

function getSampleFileHash(filePath) {
    const stats = fs.statSync(filePath);
    const buffer = Buffer.alloc(Math.min(stats.size, 2 * 1024 * 1024));
    const fd = fs.openSync(filePath, 'r');
    let bytesRead = 0;
    try {
        const firstLength = Math.min(stats.size, 1024 * 1024, buffer.length);
        bytesRead = fs.readSync(fd, buffer, 0, firstLength, 0);
        if (stats.size > 1024 * 1024) {
            const writePosition = Math.min(1024 * 1024, buffer.length);
            const secondLength = Math.min(1024 * 1024, buffer.length - writePosition);
            if (secondLength > 0) {
                bytesRead += fs.readSync(fd, buffer, writePosition, secondLength, stats.size - 1024 * 1024);
            }
        }
    } finally {
        fs.closeSync(fd);
    }
    return crypto.createHash('md5').update(buffer.subarray(0, bytesRead)).digest('hex');
}

function validateSwitchBundle(slotIdValue, files) {
    const slotId = String(slotIdValue || '').trim().toUpperCase();
    if (!/^[0-9A-F]{16}$/.test(slotId)) throw new Error('Invalid Ryujinx slot ID.');
    if (!Array.isArray(files) || !files.length) throw new Error('This save candidate has no files.');

    const normalizedFiles = files.map(file => {
        const relPath = normalizeSaveRelativePath(file && file.relPath);
        if (!relPath) throw new Error('The save candidate contains an invalid path.');
        const parts = relPath.split('/');
        const component = String(parts[1] || '').toLowerCase();
        if (String(parts[0] || '').toLowerCase() !== 'ryujinx'
            || !['saves', 'savemeta'].includes(component)
            || String(parts[2] || '').toUpperCase() !== slotId
            || parts.length < 4
            || parts.slice(3).some(part => part.startsWith('.'))) {
            throw new Error(`Save path does not belong to Ryujinx slot ${slotId}.`);
        }
        return { ...file, relPath, component, insideSlot: parts.slice(3).join('/') };
    });

    const saveFiles = normalizedFiles.filter(file => file.component === 'saves');
    if (!saveFiles.some(file => /^ExtraData[01]$/i.test(file.insideSlot))) {
        throw new Error('The save candidate is incomplete: Ryujinx ExtraData is missing.');
    }
    return { slotId, files: normalizedFiles };
}

function physicalDirectory(logicalDirectory) {
    if (!fs.existsSync(logicalDirectory)) fs.mkdirSync(logicalDirectory, { recursive: true });
    return fs.realpathSync(logicalDirectory);
}

function pruneRestoreBackups(parent, slotId, keep = 10) {
    const backupRoot = path.join(parent, '.romstore-backups');
    if (!fs.existsSync(backupRoot)) return [];
    const backups = fs.readdirSync(backupRoot, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && !entry.isSymbolicLink() && entry.name.startsWith(`${slotId}-`))
        .map(entry => entry.name)
        .sort((a, b) => b.localeCompare(a));
    const removed = [];
    for (const backup of backups.slice(Math.max(0, keep))) {
        fs.rmSync(path.join(backupRoot, backup), { recursive: true, force: true });
        removed.push(backup);
    }
    return removed;
}

async function restoreSwitchBundle({
    localDir,
    ryujinxUserRoot,
    slotId,
    files,
    downloadFile,
    isRyujinxRunning = () => false,
    now = () => new Date(),
    nonce = () => crypto.randomBytes(5).toString('hex')
}) {
    if (!localDir || typeof downloadFile !== 'function') throw new Error('Restore configuration is incomplete.');
    if (await isRyujinxRunning()) throw new Error('Close Ryujinx before restoring a Switch save.');

    const bundle = validateSwitchBundle(slotId, files);
    const componentGroups = new Map();
    for (const file of bundle.files) {
        if (!componentGroups.has(file.component)) componentGroups.set(file.component, []);
        componentGroups.get(file.component).push(file);
    }

    const timestamp = now().toISOString().replace(/[:.]/g, '-');
    const restoreNonce = nonce();
    const prepared = [];

    for (const component of ['saves', 'savemeta']) {
        const componentFiles = componentGroups.get(component) || [];
        const componentName = component === 'savemeta' ? 'saveMeta' : 'saves';
        const logicalParent = ryujinxUserRoot
            ? path.join(ryujinxUserRoot, component === 'savemeta' ? 'saveMeta' : 'save')
            : path.join(localDir, 'saves', 'ryujinx', componentName);
        const parent = physicalDirectory(logicalParent);
        const stagePath = componentFiles.length
            ? path.join(parent, `.romstore-stage-${bundle.slotId}-${restoreNonce}`)
            : null;
        if (stagePath) fs.mkdirSync(stagePath, { recursive: false });

        for (const file of componentFiles) {
            const destination = path.join(stagePath, ...file.insideSlot.split('/'));
            fs.mkdirSync(path.dirname(destination), { recursive: true });
            await downloadFile(file, destination);
            const stats = fs.statSync(destination);
            if (file.sizeBytes != null && Number(file.sizeBytes) !== stats.size) {
                throw new Error(`Downloaded size verification failed for ${file.relPath}.`);
            }
            if (file.hash && getSampleFileHash(destination) !== file.hash) {
                throw new Error(`Downloaded hash verification failed for ${file.relPath}.`);
            }
        }

        prepared.push({
            component: componentName,
            parent,
            stagePath,
            targetPath: path.join(parent, bundle.slotId),
            backupPath: path.join(parent, '.romstore-backups', `${bundle.slotId}-${timestamp}-${restoreNonce}`)
        });
    }

    if (await isRyujinxRunning()) {
        throw new Error('Ryujinx was opened during the download. Close it and try the restore again.');
    }

    const activated = [];
    try {
        for (const item of prepared) {
            fs.mkdirSync(path.dirname(item.backupPath), { recursive: true });
            const hadExisting = fs.existsSync(item.targetPath);
            if (hadExisting) fs.renameSync(item.targetPath, item.backupPath);
            try {
                if (item.stagePath) fs.renameSync(item.stagePath, item.targetPath);
            } catch (error) {
                if (hadExisting && fs.existsSync(item.backupPath) && !fs.existsSync(item.targetPath)) {
                    fs.renameSync(item.backupPath, item.targetPath);
                }
                throw error;
            }
            activated.push({ ...item, hadExisting });
        }
    } catch (error) {
        for (const item of activated.reverse()) {
            const failedPath = `${item.stagePath}-failed`;
            if (fs.existsSync(item.targetPath)) fs.renameSync(item.targetPath, failedPath);
            if (item.hadExisting && fs.existsSync(item.backupPath)) fs.renameSync(item.backupPath, item.targetPath);
        }
        throw error;
    }

    for (const item of activated) pruneRestoreBackups(item.parent, bundle.slotId);

    return {
        success: true,
        slotId: bundle.slotId,
        fileCount: bundle.files.length,
        backups: activated.filter(item => item.hadExisting).map(item => item.backupPath)
    };
}

module.exports = {
    getSampleFileHash,
    pruneRestoreBackups,
    restoreSwitchBundle,
    validateSwitchBundle
};
