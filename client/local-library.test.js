const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    buildInstalledPathSet,
    isLibraryItemInstalled,
    scanDirectoryStats,
    scanLocalEmulation
} = require('./local-library');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-library-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    fs.mkdirSync(path.join(root, 'roms', 'switch'), { recursive: true });
    fs.mkdirSync(path.join(root, 'tools', 'launchers'), { recursive: true });
    fs.writeFileSync(path.join(root, 'roms', 'switch', 'Game.xci'), 'game');
    fs.writeFileSync(path.join(root, 'roms', 'switch', 'systeminfo.txt'), 'metadata');
    fs.writeFileSync(path.join(root, 'tools', 'launchers', 'ryujinx.sh'), 'launcher');
    return root;
}

test('local scan includes game content without crawling EmuDeck tools', t => {
    const root = fixture(t);
    assert.deepEqual(scanLocalEmulation(root), ['roms/switch/Game.xci']);
});

test('installed matching is case-insensitive and section-aware', () => {
    const installed = buildInstalledPathSet(['roms/Switch/Super Mario Bros Wonder.xci']);
    assert.equal(isLibraryItemInstalled(installed, 'roms', 'switch/super mario bros wonder.XCI'), true);
    assert.equal(isLibraryItemInstalled(installed, 'bios', 'switch/super mario bros wonder.XCI'), false);
});

test('directory symlinks keep their logical library path', t => {
    const root = fixture(t);
    const external = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-external-'));
    t.after(() => fs.rmSync(external, { recursive: true, force: true }));
    fs.writeFileSync(path.join(external, 'Linked Game.rvz'), 'game');
    fs.symlinkSync(external, path.join(root, 'roms', 'wii'));

    assert.ok(scanLocalEmulation(root).includes('roms/wii/Linked Game.rvz'));
});

test('stat scans do not leak physical paths through symlinked save folders', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-save-root-'));
    const external = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-save-target-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    t.after(() => fs.rmSync(external, { recursive: true, force: true }));
    fs.mkdirSync(path.join(external, 'profiles'), { recursive: true });
    fs.writeFileSync(path.join(external, 'profiles', 'save.bin'), 'save');
    fs.symlinkSync(external, path.join(root, 'ryujinx'));

    const files = scanDirectoryStats(root);
    assert.equal(files.length, 1);
    assert.equal(files[0].relPath, 'ryujinx/profiles/save.bin');
    assert.equal(files[0].relPath.includes('..'), false);
    assert.ok(files[0].mtime instanceof Date);
});
