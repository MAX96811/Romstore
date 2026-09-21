const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ensureAutoloadDirs, prepareSwitchAddons } = require('./switch-addons-sync');

function tempDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'switch-addons-sync-'));
}

function writeConfig(dir, autoload) {
    const file = path.join(dir, 'Config.json');
    fs.writeFileSync(file, JSON.stringify({ version: 70, autoload_dirs: autoload, game_dirs: [] }, null, 2));
    return file;
}

const update = { relPath: 'switch/updates/MK8D [0100152000022800][v1376256].nsp', kind: 'update', sizeBytes: 5 };
const dlc = { relPath: 'switch/DLC/MK8D [DLC] [0100152000023001][v65536].nsp', kind: 'dlc', sizeBytes: 3 };

test('ensureAutoloadDirs appends only missing folders and keeps the file pretty-printed', () => {
    const dir = tempDir();
    const file = writeConfig(dir, ['/existing']);
    assert.deepStrictEqual(ensureAutoloadDirs(file, ['/existing', '/new']), { changed: true, added: ['/new'] });
    const text = fs.readFileSync(file, 'utf8');
    assert.deepStrictEqual(JSON.parse(text).autoload_dirs, ['/existing', '/new']);
    assert.ok(text.includes('\n  "autoload_dirs"'));
    assert.deepStrictEqual(ensureAutoloadDirs(file, ['/new']), { changed: false, added: [] });
});

test('prepareSwitchAddons downloads missing add-ons, skips present ones and registers their folders', async () => {
    const emulationDir = tempDir();
    const configDir = tempDir();
    const configFile = writeConfig(configDir, []);
    const dlcPath = path.join(emulationDir, 'roms', dlc.relPath);
    fs.mkdirSync(path.dirname(dlcPath), { recursive: true });
    fs.writeFileSync(dlcPath, 'dlc');

    const calls = [];
    const result = await prepareSwitchAddons({
        serverUrl: 'http://nas/',
        sessionToken: 'tok',
        emulationDir,
        relPath: 'switch/MK8D.nsp',
        configFiles: [configFile],
        fetchJson: async url => {
            calls.push(url);
            return { baseTitleId: '0100152000022000', addons: [update, dlc] };
        },
        download: async (url, destPath) => {
            calls.push(url);
            fs.mkdirSync(path.dirname(destPath), { recursive: true });
            fs.writeFileSync(destPath, 'patch');
            return { destPath, bytes: 5 };
        }
    });

    assert.strictEqual(calls[0], 'http://nas/api/switch/addons?relPath=switch%2FMK8D.nsp');
    assert.strictEqual(calls[1], `http://nas/api/download?type=roms&path=${encodeURIComponent(update.relPath)}`);
    assert.strictEqual(result.downloaded.length, 1);
    assert.strictEqual(result.skipped.length, 1);
    assert.deepStrictEqual(result.failed, []);
    assert.deepStrictEqual(
        JSON.parse(fs.readFileSync(configFile, 'utf8')).autoload_dirs.sort(),
        [path.join(emulationDir, 'roms', 'switch', 'DLC'), path.join(emulationDir, 'roms', 'switch', 'updates')].sort()
    );
});

test('prepareSwitchAddons re-downloads a file whose size does not match the server', async () => {
    const emulationDir = tempDir();
    const dest = path.join(emulationDir, 'roms', update.relPath);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, 'truncated-file');
    let downloads = 0;
    const result = await prepareSwitchAddons({
        serverUrl: 'http://nas', emulationDir, relPath: 'x', configFiles: [],
        fetchJson: async () => ({ addons: [update] }),
        download: async (url, destPath) => { downloads += 1; fs.writeFileSync(destPath, '12345'); }
    });
    assert.strictEqual(downloads, 1);
    assert.strictEqual(result.downloaded.length, 1);
});

test('prepareSwitchAddons defers the config edit while Ryujinx is running and tolerates a missing game', async () => {
    const emulationDir = tempDir();
    const configFile = writeConfig(tempDir(), []);
    const deferred = await prepareSwitchAddons({
        serverUrl: 'http://nas', emulationDir, relPath: 'x', configFiles: [configFile],
        isEmulatorRunning: () => true,
        fetchJson: async () => ({ addons: [update] }),
        download: async (url, destPath) => { fs.mkdirSync(path.dirname(destPath), { recursive: true }); fs.writeFileSync(destPath, '12345'); }
    });
    assert.strictEqual(deferred.autoload.deferred, true);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(configFile, 'utf8')).autoload_dirs, []);

    const none = await prepareSwitchAddons({
        serverUrl: 'http://nas', emulationDir, relPath: 'x', configFiles: [configFile],
        fetchJson: async () => null
    });
    assert.deepStrictEqual(none.addons, []);
});

test('prepareSwitchAddons records a failed download without touching the config', async () => {
    const emulationDir = tempDir();
    const configFile = writeConfig(tempDir(), []);
    const result = await prepareSwitchAddons({
        serverUrl: 'http://nas', emulationDir, relPath: 'x', configFiles: [configFile],
        fetchJson: async () => ({ addons: [update] }),
        download: async () => { throw new Error('boom'); }
    });
    assert.strictEqual(result.failed.length, 1);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(configFile, 'utf8')).autoload_dirs, []);
});
