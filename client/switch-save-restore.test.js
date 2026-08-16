const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { getSampleFileHash, pruneRestoreBackups, restoreSwitchBundle, validateSwitchBundle } = require('./switch-save-restore');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-restore-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

test('bundle validation rejects mixed slots and incomplete candidates', () => {
    assert.throws(() => validateSwitchBundle('0000000000000002', [
        { relPath: 'ryujinx/saves/0000000000000003/ExtraData0' }
    ]), /does not belong/);
    assert.throws(() => validateSwitchBundle('0000000000000002', [
        { relPath: 'ryujinx/saves/0000000000000002/0/save.bin' }
    ]), /ExtraData/);
});

test('bundle restore atomically replaces a slot and preserves the previous directory', async t => {
    const localDir = fixture(t);
    const slotId = '0000000000000002';
    const activeDir = path.join(localDir, 'saves', 'ryujinx', 'saves', slotId);
    fs.mkdirSync(activeDir, { recursive: true });
    fs.writeFileSync(path.join(activeDir, 'old.bin'), 'old-progress');
    const staleMeta = path.join(localDir, 'saves', 'ryujinx', 'saveMeta', slotId);
    fs.mkdirSync(staleMeta, { recursive: true });
    fs.writeFileSync(path.join(staleMeta, 'old.meta'), 'stale-meta');

    const sourceDir = path.join(localDir, 'source');
    fs.mkdirSync(sourceDir);
    fs.writeFileSync(path.join(sourceDir, 'ExtraData0'), 'extra-data');
    fs.writeFileSync(path.join(sourceDir, 'save.bin'), 'new-progress');
    const files = [
        { relPath: `ryujinx/saves/${slotId}/ExtraData0`, source: 'ExtraData0' },
        { relPath: `ryujinx/saves/${slotId}/0/save.bin`, source: 'save.bin' }
    ].map(file => ({
        ...file,
        sizeBytes: fs.statSync(path.join(sourceDir, file.source)).size,
        hash: getSampleFileHash(path.join(sourceDir, file.source))
    }));

    const result = await restoreSwitchBundle({
        localDir,
        slotId,
        files,
        now: () => new Date('2026-08-16T12:00:00Z'),
        nonce: () => 'test',
        downloadFile: async (file, destination) => fs.copyFileSync(path.join(sourceDir, file.source), destination)
    });

    assert.equal(result.fileCount, 2);
    assert.equal(fs.readFileSync(path.join(activeDir, '0', 'save.bin'), 'utf8'), 'new-progress');
    assert.equal(fs.readFileSync(path.join(result.backups[0], 'old.bin'), 'utf8'), 'old-progress');
    assert.equal(fs.existsSync(staleMeta), false);
    assert.equal(result.backups.length, 2);
});

test('bundle restore refuses to run while Ryujinx is open', async t => {
    const localDir = fixture(t);
    await assert.rejects(() => restoreSwitchBundle({
        localDir,
        slotId: '0000000000000002',
        files: [{ relPath: 'ryujinx/saves/0000000000000002/ExtraData0' }],
        downloadFile: async () => {},
        isRyujinxRunning: () => true
    }), /Close Ryujinx/);
});

test('bundle restore rechecks Ryujinx before activating downloaded files', async t => {
    const localDir = fixture(t);
    const source = path.join(localDir, 'extra');
    fs.writeFileSync(source, 'extra');
    let checks = 0;
    await assert.rejects(() => restoreSwitchBundle({
        localDir,
        slotId: '0000000000000002',
        files: [{ relPath: 'ryujinx/saves/0000000000000002/ExtraData0' }],
        downloadFile: async (file, destination) => fs.copyFileSync(source, destination),
        isRyujinxRunning: () => ++checks > 1
    }), /opened during the download/);
    assert.equal(fs.existsSync(path.join(localDir, 'saves', 'ryujinx', 'saves', '0000000000000002')), false);
});

test('local restore retention only prunes old backups for the selected slot', t => {
    const root = fixture(t);
    const backupRoot = path.join(root, '.romstore-backups');
    fs.mkdirSync(backupRoot);
    for (let index = 0; index < 12; index += 1) {
        fs.mkdirSync(path.join(backupRoot, `0000000000000002-2026-${String(index).padStart(2, '0')}`));
    }
    fs.mkdirSync(path.join(backupRoot, '0000000000000003-keep'));
    assert.equal(pruneRestoreBackups(root, '0000000000000002', 10).length, 2);
    assert.equal(fs.existsSync(path.join(backupRoot, '0000000000000003-keep')), true);
});
