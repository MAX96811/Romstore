const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    findGameFiles,
    getPlatformInfo,
    isDlcRelPath,
    listPlatforms,
    looksLikeDlcFileName,
    parseSystemInfo,
    resolveUploadDirectory
} = require('./rom-library');

function temporaryLibrary() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-library-'));
}

test('parseSystemInfo reads EmuDeck names and extensions', () => {
    const parsed = parseSystemInfo(`System name:\nwii\n\nFull system name:\nNintendo Wii\n\nSupported file extensions:\n.iso .ISO .rvz .RVZ\n`);
    assert.equal(parsed.system, 'wii');
    assert.equal(parsed.fullName, 'Nintendo Wii');
    assert.deepEqual(parsed.extensions, ['.iso', '.rvz']);
});

test('nested EmuDeck rom folders are used for uploads and game discovery', t => {
    const root = temporaryLibrary();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const systemPath = path.join(root, 'wiiu');
    fs.mkdirSync(path.join(systemPath, 'roms'), { recursive: true });
    fs.mkdirSync(path.join(systemPath, 'media', 'boxart'), { recursive: true });
    fs.writeFileSync(path.join(systemPath, 'systeminfo.txt'), `System name:\nwiiu\n\nFull system name:\nNintendo Wii U\n\nSupported file extensions:\n.wua .WUA\n`);
    fs.writeFileSync(path.join(systemPath, 'roms', 'Example Game.wua'), 'game');
    fs.writeFileSync(path.join(systemPath, 'media', 'boxart', 'Example Game.png'), 'art');

    assert.equal(resolveUploadDirectory(root, 'wiiu'), path.join(systemPath, 'roms'));
    assert.deepEqual(findGameFiles(systemPath, ['.wua']), [path.join(systemPath, 'roms', 'Example Game.wua')]);
    assert.deepEqual(listPlatforms(root), [{
        system: 'wiiu',
        fullName: 'Nintendo Wii U',
        extensions: ['.wua'],
        uploadSubdir: 'roms'
    }]);
});

test('unknown platforms include game-like files but skip metadata and media', t => {
    const root = temporaryLibrary();
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const systemPath = path.join(root, 'newconsole');
    fs.mkdirSync(path.join(systemPath, 'media'), { recursive: true });
    fs.writeFileSync(path.join(systemPath, 'game.custom'), 'game');
    fs.writeFileSync(path.join(systemPath, 'metadata.txt'), 'metadata');
    fs.writeFileSync(path.join(systemPath, 'cover.png'), 'cover');
    fs.writeFileSync(path.join(systemPath, 'media', 'game.jpg'), 'art');

    assert.deepEqual(findGameFiles(systemPath).map(file => path.basename(file)), ['game.custom']);
});

test('DLC folders are still scanned, so add-on content stays downloadable', () => {
    const romsDir = temporaryLibrary();
    const systemPath = path.join(romsDir, 'switch');
    fs.mkdirSync(path.join(systemPath, 'DLC'), { recursive: true });
    fs.writeFileSync(path.join(systemPath, 'Metroid Dread.xci'), 'rom');
    fs.writeFileSync(path.join(systemPath, 'DLC', 'Smash [DLC Creeper].nsp'), 'dlc');

    const found = findGameFiles(systemPath, ['.xci', '.nsp']).map(file => path.basename(file)).sort();
    assert.deepEqual(found, ['Metroid Dread.xci', 'Smash [DLC Creeper].nsp']);
});

test('a DLC folder segment marks the entry as add-on content', () => {
    assert.equal(isDlcRelPath('switch/DLC/Smash [DLC Creeper].nsp'), true);
    assert.equal(isDlcRelPath('switch/dlc/nested/pack.nsp'), true);
    assert.equal(isDlcRelPath('switch\\DLC\\pack.nsp'), true);
    assert.equal(isDlcRelPath('switch/Updates/patch.nsp'), true);
    assert.equal(isDlcRelPath('switch/Metroid Dread.xci'), false);
    // The marker has to be a folder: a game merely named after DLC is a game.
    assert.equal(isDlcRelPath('switch/Game [DLC Included].nsp'), false);
});

test('an upload is recognised as DLC from its filename tag', () => {
    assert.equal(looksLikeDlcFileName('Super Smash Bros Ultimate [DLC Creeper] [01006A8].nsp'), true);
    assert.equal(looksLikeDlcFileName('Some Game (DLC Pack 1).nsp'), true);
    assert.equal(looksLikeDlcFileName('Metroid Dread.xci'), false);
    assert.equal(looksLikeDlcFileName('DLC Quest.nsp'), false);
});

test('3DS .cia files count as games even though EmuDeck never lists them', () => {
    const systemPath = fs.mkdtempSync(path.join(os.tmpdir(), 'n3ds-'));
    // The real file from the library: every 3DS extension except the one that
    // 82 of the games actually use.
    fs.writeFileSync(path.join(systemPath, 'systeminfo.txt'),
        `System name:\nn3ds\n\nFull system name:\nNintendo 3DS\n\nSupported file extensions:\n` +
        `.3ds .3DS .3dsx .3DSX .app .APP .cci .CCI .cxi .CXI .zip .ZIP\n`);

    const info = getPlatformInfo(systemPath, 'n3ds');
    assert.ok(info.extensions.includes('.cia'), '.cia must be playable');
    // What the info file does declare is kept, not replaced.
    assert.ok(info.extensions.includes('.3ds'));
    assert.ok(info.extensions.includes('.cci'));

    fs.writeFileSync(path.join(systemPath, 'Game A.cia'), 'x');
    fs.writeFileSync(path.join(systemPath, 'Game B.3ds'), 'x');
    const found = findGameFiles(systemPath, info.extensions).map(p => path.basename(p)).sort();
    assert.deepEqual(found, ['Game A.cia', 'Game B.3ds']);

    fs.rmSync(systemPath, { recursive: true, force: true });
});

test('platforms without an extras entry are unchanged', () => {
    const systemPath = fs.mkdtempSync(path.join(os.tmpdir(), 'wii-'));
    fs.writeFileSync(path.join(systemPath, 'systeminfo.txt'),
        `System name:\nwii\n\nFull system name:\nNintendo Wii\n\nSupported file extensions:\n.iso .ISO .rvz .RVZ\n`);
    assert.deepEqual(getPlatformInfo(systemPath, 'wii').extensions, ['.iso', '.rvz']);
    fs.rmSync(systemPath, { recursive: true, force: true });
});
