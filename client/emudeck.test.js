const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    parseCustomSystemsXml,
    resolveCommand,
    sanitizeLaunchEnvironment,
    selectProfile,
    tokenizeCommand
} = require('./emudeck');

function fixture(t) {
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-emudeck-'));
    t.after(() => fs.rmSync(homeDir, { recursive: true, force: true }));
    const emulationDir = path.join(homeDir, 'Emulation');
    const launcherDir = path.join(emulationDir, 'tools', 'launchers');
    const backendDir = path.join(homeDir, '.config', 'EmuDeck', 'backend');
    fs.mkdirSync(launcherDir, { recursive: true });
    fs.mkdirSync(path.join(backendDir, 'roms', 'wii'), { recursive: true });
    fs.writeFileSync(path.join(launcherDir, 'dolphin-emu.sh'), '#!/bin/bash\n');
    fs.writeFileSync(path.join(launcherDir, 'retroarch.sh'), '#!/bin/bash\n');
    fs.writeFileSync(path.join(backendDir, 'roms', 'wii', 'systeminfo.txt'), `System name:\nwii\n\nFull system name:\nNintendo Wii\n\nSupported file extensions:\n.iso .rvz\n\nLaunch command:\n%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/dolphin_libretro.so %ROM%\n\nAlternative launch command:\n%EMULATOR_DOLPHIN% -b -e %ROM%\n`);
    return { homeDir, emulationDir, backendDir };
}

test('tokenizeCommand keeps quoted paths together', () => {
    assert.deepEqual(tokenizeCommand(`launcher --name "Game Name" '%ROM%'`), ['launcher', '--name', 'Game Name', '%ROM%']);
});

test('custom ES-DE definitions preserve command order and labels', () => {
    const parsed = parseCustomSystemsXml(`<systemList><system><name>switch</name><fullname>Nintendo Switch</fullname><extension>.nsp .xci</extension><command label="Ryujinx">%EMULATOR_RYUJINX% %ROM%</command></system></systemList>`);
    assert.equal(parsed.switch.fullName, 'Nintendo Switch');
    assert.deepEqual(parsed.switch.extensions, ['.nsp', '.xci']);
    assert.equal(parsed.switch.commands[0].label, 'Ryujinx');
});

test('profile selection falls back from a missing RetroArch core to standalone EmuDeck', t => {
    const paths = fixture(t);
    const romPath = path.join(paths.emulationDir, 'roms', 'wii', 'Game Name.iso');
    const profile = selectProfile('wii', { ...paths, romPath });
    assert.equal(profile.available, true);
    assert.equal(profile.label, 'EmuDeck alternative');
    assert.equal(profile.resolved.command, '/bin/bash');
    // EmuDeck's template is `-b -e %ROM%`; the batch flag is dropped so Dolphin
    // still shows a window and its Controller settings stay reachable.
    assert.deepEqual(profile.resolved.args, [path.join(paths.emulationDir, 'tools', 'launchers', 'dolphin-emu.sh'), '-e', romPath]);
});

test('the batch flag is dropped only for the emulators it makes windowless', t => {
    const paths = fixture(t);
    const romPath = path.join(paths.emulationDir, 'roms', 'wii', 'Game.iso');

    const dolphin = resolveCommand('%EMULATOR_DOLPHIN% -b -e %ROM%', { ...paths, romPath, system: 'wii' });
    assert.equal(dolphin.args.includes('-b'), false);
    assert.equal(dolphin.args.includes('-e'), true);

    // Other emulators use the same letter for something harmless, so the flag
    // is only stripped from the launchers it actually makes windowless.
    const retroarch = resolveCommand('%EMULATOR_RETROARCH% -b %ROM%', { ...paths, romPath, system: 'wii' });
    assert.equal(retroarch.args.includes('-b'), true);
});

test('custom profiles support the Retrom-style {rom} placeholder', t => {
    const paths = fixture(t);
    const romPath = path.join(paths.emulationDir, 'roms', 'wii', 'Game.iso');
    const resolved = resolveCommand('%EMULATOR_DOLPHIN% --custom {rom}', { ...paths, romPath, system: 'wii' });
    assert.deepEqual(resolved.args, [path.join(paths.emulationDir, 'tools', 'launchers', 'dolphin-emu.sh'), '--custom', romPath]);
});

test('AppImage mount paths are removed without losing desktop session variables', () => {
    const cleaned = sanitizeLaunchEnvironment({
        PATH: '/tmp/.mount_RomSto/usr/bin:/usr/bin',
        LD_LIBRARY_PATH: '/tmp/.mount_RomSto/usr/lib:/usr/lib',
        APPDIR: '/tmp/.mount_RomSto',
        DISPLAY: ':0'
    });
    assert.equal(cleaned.PATH, '/usr/bin');
    assert.equal(cleaned.LD_LIBRARY_PATH, '/usr/lib');
    assert.equal(cleaned.APPDIR, undefined);
    assert.equal(cleaned.DISPLAY, ':0');
});
