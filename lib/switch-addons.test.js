const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
    buildAddonIndex,
    classifySwitchTitleId,
    parseSwitchFileName,
    readNspTitleIds,
    resolveSwitchIdentity,
    selectAddonsForBase
} = require('./switch-addons');

test('classifySwitchTitleId recognises base, update and DLC of one family', () => {
    assert.deepStrictEqual(classifySwitchTitleId('0100152000022000'), {
        titleId: '0100152000022000', baseTitleId: '0100152000022000', kind: 'base'
    });
    assert.deepStrictEqual(classifySwitchTitleId('0100152000022800'), {
        titleId: '0100152000022800', baseTitleId: '0100152000022000', kind: 'update'
    });
    assert.deepStrictEqual(classifySwitchTitleId('0100152000023001'), {
        titleId: '0100152000023001', baseTitleId: '0100152000022000', kind: 'dlc'
    });
    // Odd family: base ends in E000, DLC rolls into the next 0x1000 block.
    assert.strictEqual(classifySwitchTitleId('01006A800016F001').baseTitleId, '01006A800016E000');
    assert.strictEqual(classifySwitchTitleId('bad'), null);
});

test('parseSwitchFileName reads id, version and DLC tag', () => {
    assert.deepStrictEqual(
        parseSwitchFileName('switch/updates/Mario Kart 8 Deluxe [0100152000022800][v1376256].nsp'),
        { titleId: '0100152000022800', version: 1376256, isDlcTagged: false }
    );
    assert.deepStrictEqual(
        parseSwitchFileName('Mario Kart 8 Deluxe [DLC Booster Course Pass] [0100152000023001][v65536].nsp'),
        { titleId: '0100152000023001', version: 65536, isDlcTagged: true }
    );
    assert.deepStrictEqual(parseSwitchFileName('Mario Kart 8 Deluxe.nsp'),
        { titleId: null, version: null, isDlcTagged: false });
});

function writeNsp(dir, name, entryNames) {
    const stringTable = Buffer.concat(entryNames.map(entry => Buffer.from(`${entry}\0`)));
    const header = Buffer.alloc(16);
    header.write('PFS0', 0, 'ascii');
    header.writeUInt32LE(entryNames.length, 4);
    header.writeUInt32LE(stringTable.length, 8);
    const entries = Buffer.alloc(entryNames.length * 24);
    let offset = 0;
    entryNames.forEach((entry, index) => {
        entries.writeUInt32LE(offset, index * 24 + 16);
        offset += Buffer.byteLength(entry) + 1;
    });
    const file = path.join(dir, name);
    fs.writeFileSync(file, Buffer.concat([header, entries, stringTable, Buffer.from('payload')]));
    return file;
}

test('readNspTitleIds recovers the title id from an embedded ticket', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'switch-addons-'));
    const file = writeNsp(dir, 'update.nsp', [
        'a3e030a30e112d39de059a24f7c80b63.nca',
        '01001520000228000000000000000005.tik',
        '01001520000228000000000000000005.cert',
        '1fa7f2036e3aabdede91fa1cd78705ca.cnmt.nca'
    ]);
    assert.deepStrictEqual(readNspTitleIds(file), ['0100152000022800']);
    const plain = path.join(dir, 'plain.nsp');
    fs.writeFileSync(plain, Buffer.from('not a pfs0 file at all'));
    assert.deepStrictEqual(readNspTitleIds(plain), []);
    assert.deepStrictEqual(readNspTitleIds(path.join(dir, 'missing.nsp')), []);
});

test('resolveSwitchIdentity prefers the file name, then metadata, then the ticket', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'switch-addons-'));
    const ticketOnly = writeNsp(dir, 'Booster Pass.nsp', ['01001520000230010000000000000005.tik']);
    assert.deepStrictEqual(resolveSwitchIdentity({ filePath: ticketOnly, relPath: 'switch/DLC/Booster Pass.nsp' }), {
        titleId: '0100152000023001', source: 'ticket', version: null, kind: 'dlc', baseTitleId: '0100152000022000'
    });
    assert.strictEqual(resolveSwitchIdentity({
        filePath: ticketOnly, relPath: 'switch/x.nsp', metadataTitleId: '0100152000022000'
    }).source, 'metadata');
    assert.strictEqual(resolveSwitchIdentity({
        filePath: ticketOnly, relPath: 'switch/x [0100152000022800][v3].nsp'
    }).source, 'filename');
    assert.strictEqual(resolveSwitchIdentity({ filePath: null, relPath: 'switch/x.xci' }).titleId, null);
});

test('buildAddonIndex groups by base and selectAddonsForBase picks newest update plus all DLC', () => {
    const index = buildAddonIndex([
        { relPath: 'u1', titleId: '0100152000022800', baseTitleId: '0100152000022000', kind: 'update', version: 65536 },
        { relPath: 'u2', titleId: '0100152000022800', baseTitleId: '0100152000022000', kind: 'update', version: 1376256 },
        { relPath: 'd2', titleId: '0100152000023002', baseTitleId: '0100152000022000', kind: 'dlc', version: 0 },
        { relPath: 'd1', titleId: '0100152000023001', baseTitleId: '0100152000022000', kind: 'dlc', version: 65536 },
        { relPath: 'base', titleId: '0100152000022000', baseTitleId: '0100152000022000', kind: 'base' },
        { relPath: 'nothing', titleId: null }
    ]);
    assert.deepStrictEqual(selectAddonsForBase(index, '0100152000022000').map(entry => entry.relPath), ['u2', 'd1', 'd2']);
    assert.deepStrictEqual(selectAddonsForBase(index, '0100000000000000'), []);
});
