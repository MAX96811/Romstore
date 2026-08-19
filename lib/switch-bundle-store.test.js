const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { activateBundleUpload, pruneBundleGenerations, validateBundleUpload } = require('./switch-bundle-store');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-store-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

function extraDataFile(root, titleId = 0x010015100B514000n) {
    const file = path.join(root, `extra-${Date.now()}-${Math.random()}`);
    const buffer = Buffer.alloc(512);
    buffer.writeBigUInt64LE(titleId, 0);
    buffer.writeBigUInt64LE(titleId, 0x40);
    fs.writeFileSync(file, buffer);
    return file;
}

test('bundle uploads reject path mixing and mismatched embedded title IDs', t => {
    const root = fixture(t);
    const extra = extraDataFile(root);
    assert.throws(() => validateBundleUpload({
        slotId: '0000000000000002',
        titleId: '010015100B514000',
        files: [{ relPath: 'ryujinx/saves/0000000000000003/ExtraData0', tempPath: extra }]
    }), /does not belong/);
    assert.throws(() => validateBundleUpload({
        slotId: '0000000000000002',
        titleId: '01009D901BC56000',
        files: [{ relPath: 'ryujinx/saves/0000000000000002/ExtraData0', tempPath: extra }]
    }), /does not match/);

    const conflicting = extraDataFile(root, 0x01009D901BC56000n);
    assert.throws(() => validateBundleUpload({
        slotId: '0000000000000002',
        titleId: '010015100B514000',
        files: [
            { relPath: 'ryujinx/saves/0000000000000002/ExtraData0', tempPath: extra },
            { relPath: 'ryujinx/saves/0000000000000002/ExtraData1', tempPath: conflicting }
        ]
    }), /every ExtraData/);
});

test('bundle upload archives the previous server slot before activation', t => {
    const root = fixture(t);
    const slotId = '0000000000000002';
    const active = path.join(root, 'ryujinx', 'saves', slotId);
    fs.mkdirSync(active, { recursive: true });
    fs.writeFileSync(path.join(active, 'old.bin'), 'old-cloud');
    fs.copyFileSync(extraDataFile(root), path.join(active, 'ExtraData0'));
    const staleMeta = path.join(root, 'ryujinx', 'saveMeta', slotId);
    fs.mkdirSync(staleMeta, { recursive: true });
    fs.writeFileSync(path.join(staleMeta, 'old.meta'), 'stale-meta');

    const uploadedExtra = extraDataFile(root);
    const uploadedSave = path.join(root, 'new.bin');
    fs.writeFileSync(uploadedSave, 'new-cloud');
    const result = activateBundleUpload({
        userSavesDir: root,
        slotId,
        titleId: '010015100B514000',
        files: [
            { relPath: `ryujinx/saves/${slotId}/ExtraData0`, tempPath: uploadedExtra },
            { relPath: `ryujinx/saves/${slotId}/0/save.bin`, tempPath: uploadedSave }
        ],
        now: () => new Date('2026-08-16T12:00:00Z'),
        nonce: () => 'test'
    });

    assert.equal(fs.readFileSync(path.join(active, '0', 'save.bin'), 'utf8'), 'new-cloud');
    const archived = path.join(root, '.switch-bundle-versions', result.titleId, slotId, result.generation, 'saves');
    assert.equal(fs.readFileSync(path.join(archived, 'old.bin'), 'utf8'), 'old-cloud');
    const archivedMeta = path.join(root, '.switch-bundle-versions', result.titleId, slotId, result.generation, 'saveMeta');
    assert.equal(fs.readFileSync(path.join(archivedMeta, 'old.meta'), 'utf8'), 'stale-meta');
    assert.equal(fs.existsSync(staleMeta), false);
});

test('bundle archive retention only removes old RomStore generations', t => {
    const root = fixture(t);
    const versions = path.join(root, '.switch-bundle-versions', '010015100B514000', '0000000000000002');
    for (let index = 0; index < 12; index += 1) {
        fs.mkdirSync(path.join(versions, `2026-08-${String(index + 1).padStart(2, '0')}`), { recursive: true });
    }
    const removed = pruneBundleGenerations(root, '010015100B514000', '0000000000000002', 10);
    assert.equal(removed.length, 2);
    assert.equal(fs.readdirSync(versions).length, 10);
});

test('a slot that changed hands adopts the new title and archives the old owner separately', t => {
    const root = fixture(t);
    const slotId = '0000000000000006';
    const OLD_TITLE = 0x0100B99019412000n;
    const NEW_TITLE = 0x0100000000010000n;

    // The slot is already occupied by the previous game, exactly as the NAS
    // holds a slot Ryujinx has since reassigned.
    const active = path.join(root, 'ryujinx', 'saves', slotId);
    fs.mkdirSync(active, { recursive: true });
    fs.copyFileSync(extraDataFile(root, OLD_TITLE), path.join(active, 'ExtraData0'));
    fs.mkdirSync(path.join(active, '0'), { recursive: true });
    fs.writeFileSync(path.join(active, '0', 'game_data.sav'), 'previous-owner-progress');

    const uploadedExtra = extraDataFile(root, NEW_TITLE);
    const uploadedSave = path.join(root, 'incoming.bin');
    fs.writeFileSync(uploadedSave, 'new-owner-progress');

    const result = activateBundleUpload({
        userSavesDir: root,
        slotId,
        titleId: '0100000000010000',
        files: [
            { relPath: `ryujinx/saves/${slotId}/ExtraData0`, tempPath: uploadedExtra },
            { relPath: `ryujinx/saves/${slotId}/0/File1.bin`, tempPath: uploadedSave }
        ],
        now: () => new Date('2026-08-19T04:00:00Z'),
        nonce: () => 'adopt'
    });

    assert.equal(result.success, true);
    assert.equal(result.adoptedFromTitleId, '0100B99019412000', 'reports which title the slot was taken from');

    // The incoming bundle is live.
    assert.equal(fs.readFileSync(path.join(active, '0', 'File1.bin'), 'utf8'), 'new-owner-progress');
    assert.equal(fs.existsSync(path.join(active, '0', 'game_data.sav')), false, 'previous files are not left mixed in');

    // The previous owner's data is archived under ITS OWN title, not the new one.
    const oldArchive = path.join(root, '.switch-bundle-versions', '0100B99019412000', slotId, result.generation, 'saves', '0', 'game_data.sav');
    assert.equal(fs.readFileSync(oldArchive, 'utf8'), 'previous-owner-progress', 'old save is recoverable under its real title');
    assert.equal(
        fs.existsSync(path.join(root, '.switch-bundle-versions', '0100000000010000', slotId, result.generation)),
        false,
        'the outgoing data is never misfiled under the incoming title'
    );
});

test('an unchanged slot still archives under its own title and reports no adoption', t => {
    const root = fixture(t);
    const slotId = '0000000000000002';
    const TITLE = 0x010015100B514000n;

    const active = path.join(root, 'ryujinx', 'saves', slotId);
    fs.mkdirSync(path.join(active, '0'), { recursive: true });
    fs.copyFileSync(extraDataFile(root, TITLE), path.join(active, 'ExtraData0'));
    fs.writeFileSync(path.join(active, '0', 'save.bin'), 'generation-one');

    const uploadedSave = path.join(root, 'gen2.bin');
    fs.writeFileSync(uploadedSave, 'generation-two');
    const result = activateBundleUpload({
        userSavesDir: root,
        slotId,
        titleId: '010015100B514000',
        files: [
            { relPath: `ryujinx/saves/${slotId}/ExtraData0`, tempPath: extraDataFile(root, TITLE) },
            { relPath: `ryujinx/saves/${slotId}/0/save.bin`, tempPath: uploadedSave }
        ],
        now: () => new Date('2026-08-19T04:00:00Z'),
        nonce: () => 'same'
    });

    assert.equal(result.adoptedFromTitleId, null);
    assert.equal(fs.readFileSync(path.join(active, '0', 'save.bin'), 'utf8'), 'generation-two');
    const archived = path.join(root, '.switch-bundle-versions', '010015100B514000', slotId, result.generation, 'saves', '0', 'save.bin');
    assert.equal(fs.readFileSync(archived, 'utf8'), 'generation-one');
});
