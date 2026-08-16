const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    collectSwitchBundleFiles,
    discoverSwitchAssociations,
    matchSwitchTitleId,
    resolveRyujinxUserRoot
} = require('./switch-library');

test('Ryujinx metadata and ExtraData associate an EmuDeck game with its save slot', t => {
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-home-'));
    const emulationDir = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-switch-emulation-'));
    t.after(() => fs.rmSync(homeDir, { recursive: true, force: true }));
    t.after(() => fs.rmSync(emulationDir, { recursive: true, force: true }));

    const titleId = '010015100B514000';
    const metadataDir = path.join(homeDir, '.config', 'Ryujinx', 'games', titleId.toLowerCase(), 'gui');
    fs.mkdirSync(metadataDir, { recursive: true });
    fs.writeFileSync(path.join(metadataDir, 'metadata.json'), JSON.stringify({ title: 'Super Mario Bros. Wonder' }));

    const slotId = '0000000000000002';
    const slotDir = path.join(emulationDir, 'saves', 'ryujinx', 'saves', slotId);
    fs.mkdirSync(slotDir, { recursive: true });
    const extraData = Buffer.alloc(512);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0);
    extraData.writeBigUInt64LE(0x010015100B514000n, 0x40);
    fs.writeFileSync(path.join(slotDir, 'ExtraData0'), extraData);

    const associations = discoverSwitchAssociations({ homeDir, emulationDir });
    assert.deepEqual(associations.games, [{ titleId, title: 'Super Mario Bros. Wonder' }]);
    assert.deepEqual(associations.slots, [{ slotId, titleId }]);
    assert.equal(matchSwitchTitleId({ name: 'Super Mario Bros Wonder', relPath: 'switch/Super Mario Bros Wonder.xci' }, associations), titleId);
    fs.mkdirSync(path.join(slotDir, '0'), { recursive: true });
    fs.mkdirSync(path.join(slotDir, '.oldsave'), { recursive: true });
    fs.writeFileSync(path.join(slotDir, '0', 'game.sav'), 'current');
    fs.writeFileSync(path.join(slotDir, '.oldsave', 'game.sav'), 'backup');
    assert.deepEqual(
        collectSwitchBundleFiles(emulationDir, slotId).map(file => file.relPath),
        [
            `ryujinx/saves/${slotId}/0/game.sav`,
            `ryujinx/saves/${slotId}/ExtraData0`
        ]
    );
});

test('Flatpak Ryujinx selected by EmuDeck uses its live user-save root', t => {
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-flatpak-home-'));
    const emulationDir = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-flatpak-emulation-'));
    t.after(() => fs.rmSync(homeDir, { recursive: true, force: true }));
    t.after(() => fs.rmSync(emulationDir, { recursive: true, force: true }));
    const userRoot = path.join(homeDir, '.var', 'app', 'io.github.ryubing.Ryujinx', 'config', 'Ryujinx', 'bis', 'user');
    fs.mkdirSync(path.join(userRoot, 'save'), { recursive: true });
    const launcher = path.join(emulationDir, 'tools', 'launchers', 'ryujinx.sh');
    fs.mkdirSync(path.dirname(launcher), { recursive: true });
    fs.writeFileSync(launcher, 'flatpak run io.github.ryubing.Ryujinx');
    assert.equal(resolveRyujinxUserRoot({ homeDir, emulationDir }), userRoot);
});
