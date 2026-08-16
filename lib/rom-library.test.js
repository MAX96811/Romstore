const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    findGameFiles,
    listPlatforms,
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
