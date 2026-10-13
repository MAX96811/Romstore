const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    buildRyujinxSlotTitleMap,
    getRyujinxSlotId,
    getSwitchTitleIdFromSavePath,
    normalizeSwitchTitleId,
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


test('normalizeSwitchTitleId uppercases valid IDs and rejects the rest', () => {
    assert.equal(normalizeSwitchTitleId(' 010015100b514000 '), '010015100B514000');
    assert.equal(normalizeSwitchTitleId('0100'), null);
    assert.equal(normalizeSwitchTitleId('ZZ0015100B514000'), null);
    assert.equal(normalizeSwitchTitleId(null), null);
});

test('ExtraData with a different owner ID is not trusted', () => {
    const extraData = Buffer.alloc(512);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0);
    extraData.writeBigUInt64LE(0x010015100B515000n, 0x40);
    assert.equal(parseRyujinxTitleId(extraData), null);
});

test('getRyujinxSlotId reads slots from saves and savemeta, with either slash style', () => {
    assert.equal(getRyujinxSlotId('ryujinx/saves/00000000000000ab/0/x.sav'), '00000000000000AB');
    assert.equal(getRyujinxSlotId('ryujinx\\savemeta\\00000000000000ab\\y'), '00000000000000AB');
    assert.equal(getRyujinxSlotId('yuzu/nand/user/save/0/x'), null);
});

test('a 0100 application ID in the path wins over slot and manual maps', () => {
    const p = 'yuzu/nand/user/save/0000000000000000/ABCDEF/010015100B514000/data.sav';
    assert.equal(getSwitchTitleIdFromSavePath(p, {}, { '010015100B514000': '0100AAAAAAAAAAAA' }), '010015100B514000');
});

test('manual mappings resolve unknown slots and override discovered ones', t => {
    const slotId = '0000000000000005';
    const savePath = `ryujinx/saves/${slotId}/0/g.sav`;
    assert.equal(getSwitchTitleIdFromSavePath(savePath, {}, { [slotId]: '0100aaaaaaaaaaaa' }), '0100AAAAAAAAAAAA');

    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-manual-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const map = buildRyujinxSlotTitleMap(root, { [slotId]: '0100BBBBBBBBBBBB', bad: 'nope' });
    assert.deepEqual(map, { [slotId]: '0100BBBBBBBBBBBB' });
});
