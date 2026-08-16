const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    buildRyujinxSlotTitleMap,
    getSwitchTitleIdFromSavePath,
    parseRyujinxTitleId
} = require('./switch-saves');

test('Ryujinx ExtraData exposes the application Title ID as little endian', () => {
    const extraData = Buffer.alloc(512);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0x40);
    assert.equal(parseRyujinxTitleId(extraData), '010015100B514000');
    assert.equal(parseRyujinxTitleId(Buffer.alloc(7)), null);
    assert.equal(parseRyujinxTitleId(Buffer.alloc(512)), null);
});

test('slot maps match every file in a Ryujinx save slot to the real game ID', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-save-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const slotId = '0000000000000002';
    const slotDir = path.join(root, 'ryujinx', 'saves', slotId);
    fs.mkdirSync(slotDir, { recursive: true });
    const extraData = Buffer.alloc(512);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0x40);
    fs.writeFileSync(path.join(slotDir, 'ExtraData0'), extraData);

    const map = buildRyujinxSlotTitleMap(root);
    assert.deepEqual(map, { [slotId]: '010015100B514000' });
    assert.equal(getSwitchTitleIdFromSavePath(`ryujinx/saves/${slotId}/0/game_data.sav`, map), '010015100B514000');
    assert.equal(getSwitchTitleIdFromSavePath('ryujinx/saves/0000000000000003/0/other.sav', map), null);
});

test('legacy flat ExtraData paths are still discoverable without migration', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-flat-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const extraData = Buffer.alloc(512);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0x40);
    fs.writeFileSync(path.join(root, 'ryujinx\\saves\\0000000000000002\\ExtraData0'), extraData);
    assert.deepEqual(buildRyujinxSlotTitleMap(root), { '0000000000000002': '010015100B514000' });
});
