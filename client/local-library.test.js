const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    buildInstalledPathSet,
    isLibraryItemInstalled,
    normalizeSaveRelativePath,
    scanDirectoryStats,
    scanLocalEmulation, scanLocalGames } = require('./local-library');

test('save upload paths normalize one Windows separator and reject traversal', () => {
    assert.equal(normalizeSaveRelativePath('ryujinx\\saves\\0000000000000002\\save.bin'), 'ryujinx/saves/0000000000000002/save.bin');
    assert.equal(normalizeSaveRelativePath('ryujinx\\..\\outside.bin'), null);
    assert.equal(normalizeSaveRelativePath('/outside.bin'), null);
});

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

test('offline game scan applies the same rules the server uses', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-offline-scan-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));

    const switchDir = path.join(root, 'roms', 'switch');
    fs.mkdirSync(path.join(switchDir, 'media', 'boxart'), { recursive: true });
    fs.writeFileSync(path.join(switchDir, 'systeminfo.txt'),
        'System name:\nswitch\n\nSupported file extensions:\n.nsp .xci\n');
    fs.writeFileSync(path.join(switchDir, 'Mario.xci'), 'rom');
    fs.writeFileSync(path.join(switchDir, 'Zelda.nsp'), 'rom');
    fs.writeFileSync(path.join(switchDir, 'notes.txt'), 'x');
    fs.writeFileSync(path.join(switchDir, 'cover.png'), 'x');
    fs.writeFileSync(path.join(switchDir, 'media', 'boxart', 'Mario.png'), 'art');

    // Config-only tree with no systeminfo.txt must not masquerade as games.
    const model2 = path.join(root, 'roms', 'model2', 'CFG');
    fs.mkdirSync(model2, { recursive: true });
    fs.writeFileSync(path.join(model2, 'daytona.input'), 'cfg');
    fs.writeFileSync(path.join(model2, 'readme.txt'), 'x');

    // Emulator launchers are never games.
    fs.mkdirSync(path.join(root, 'roms', 'emulators'), { recursive: true });
    fs.writeFileSync(path.join(root, 'roms', 'emulators', 'cemu.sh'), '#!/bin/sh');

    const games = scanLocalGames(root).map(game => game.relPath);
    assert.deepEqual(games.filter(p => p.startsWith('switch/')), ['switch/Mario.xci', 'switch/Zelda.nsp']);
    assert.equal(games.some(p => p.includes('media/')), false, 'artwork directories are skipped');
    assert.equal(games.some(p => p.startsWith('emulators/')), false, 'emulator launchers are skipped');
    assert.equal(games.some(p => p.endsWith('.txt') || p.endsWith('.png')), false);
});

test('offline game scan returns nothing when there is no local library', () => {
    assert.deepEqual(scanLocalGames('/nonexistent-romstore-path'), []);
    assert.deepEqual(scanLocalGames(''), []);
});
