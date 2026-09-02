const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    buildInputConfig,
    detectControllers,
    parseInputDevices,
    sameConfiguration,
    sdlGuid
} = require('./ryujinx-input');

// Two Xbox One S pads and the virtual pointer a streaming host installs. The
// pointer claims a js node, which is exactly why the joystick node alone is not
// enough to identify a controller.
const PROC_DEVICES = `
I: Bus=0003 Vendor=045e Product=02ea Version=0408
N: Name="Microsoft X-Box One S pad"
P: Phys=usb-0000:00:14.0-1/input0
S: Sysfs=/devices/pci0000:00/0000:00:14.0/usb1/1-1/input/input25
U: Uniq=
H: Handlers=event20 js1
B: PROP=0
B: EV=20000b
B: KEY=7cdb000000000000 0 0 0 0
B: ABS=3003f

I: Bus=0003 Vendor=045e Product=02ea Version=0408
N: Name="Microsoft X-Box One S pad"
P: Phys=usb-0000:00:14.0-2/input0
S: Sysfs=/devices/pci0000:00/0000:00:14.0/usb1/1-2/input/input27
U: Uniq=
H: Handlers=event21 js2
B: PROP=0
B: EV=20000b
B: KEY=7cdb000000000000 0 0 0 0
B: ABS=3003f

I: Bus=0003 Vendor=beef Product=dead Version=0111
N: Name="Mouse passthrough (absolute)"
P: Phys=
S: Sysfs=/devices/virtual/input/input40
U: Uniq=
H: Handlers=event31 js0 mouse3
B: PROP=2
B: EV=b
B: KEY=10000 0 0 0 0
B: ABS=3

I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech K800 Keyboard"
P: Phys=usb-0000:00:14.0-3/input0
S: Sysfs=/devices/virtual/input/input5
U: Uniq=
H: Handlers=sysrq kbd event3
B: PROP=0
B: EV=120013
B: KEY=1000000000007 ff9f207ac14057ff febeffdfffefffff fffffffffffffffe
`;

test('the SDL GUID matches the one Ryujinx already stores', () => {
    // Taken verbatim from a Ryujinx Config.json written by the emulator itself
    // for an Xbox One S pad; if this drifts, no binding will ever match.
    assert.equal(
        sdlGuid({ bus: 0x0003, vendor: 0x045e, product: 0x02ea, version: 0x0408 }),
        '00000003-045e-0000-ea02-000008040000'
    );
});

test('only real gamepads are detected', () => {
    const controllers = parseInputDevices(PROC_DEVICES);
    assert.equal(controllers.length, 2);
    assert.deepEqual(controllers.map(c => c.joystickIndex), [1, 2]);
    // The virtual pointer holds js0 and would otherwise have taken Player1.
    assert.ok(controllers.every(c => c.name === 'Microsoft X-Box One S pad'));
});

test('a keyboard without a joystick node is ignored', () => {
    assert.equal(parseInputDevices(PROC_DEVICES).some(c => /keyboard/i.test(c.name)), false);
});

test('a missing or unreadable device list yields no controllers', () => {
    assert.deepEqual(detectControllers(path.join(os.tmpdir(), 'romstore-no-such-devices')), []);
    assert.deepEqual(parseInputDevices(''), []);
});

test('two pads become two players, numbered in enumeration order', () => {
    const controllers = parseInputDevices(PROC_DEVICES);
    const config = buildInputConfig([], controllers);

    assert.deepEqual(config.map(entry => entry.player_index), ['Player1', 'Player2']);
    assert.equal(config[0].id, '0-00000003-045e-0000-ea02-000008040000');
    assert.equal(config[1].id, '1-00000003-045e-0000-ea02-000008040000');
    assert.ok(config.every(entry => entry.backend === 'GamepadSDL2'));
    assert.ok(config.every(entry => entry.controller_type === 'ProController'));
});

test('a pad keeps the mapping it already had', () => {
    const controllers = parseInputDevices(PROC_DEVICES);
    const existing = [{
        backend: 'GamepadSDL2',
        controller_type: 'ProController',
        id: '0-00000003-045e-0000-ea02-000008040000',
        name: 'Xbox One S Controller (0)',
        player_index: 'Player1',
        deadzone_left: 0.42,
        right_joycon: { button_a: 'B', button_b: 'A' }
    }];

    const config = buildInputConfig(existing, controllers);
    // Both pads share a GUID here, so the customised mapping reaches both: the
    // stored entry for the first, the same entry as template for the second.
    assert.equal(config[0].deadzone_left, 0.42);
    assert.deepEqual(config[0].right_joycon, { button_a: 'B', button_b: 'A' });
    assert.equal(config[1].deadzone_left, 0.42);
    // Identity is still rewritten to match what is plugged in now.
    assert.equal(config[1].id, '1-00000003-045e-0000-ea02-000008040000');
    assert.equal(config[1].player_index, 'Player2');
});

test('an unrecognised pad inherits the first configured mapping', () => {
    const existing = [{ backend: 'GamepadSDL2', id: '0-aaaa', player_index: 'Player1', deadzone_left: 0.3 }];
    const config = buildInputConfig(existing, [{ joystickIndex: 4, name: 'New Pad', guid: 'bbbb' }]);
    assert.equal(config[0].deadzone_left, 0.3);
    assert.equal(config[0].id, '0-bbbb');
    assert.equal(config[0].name, 'New Pad');
});

test('with nothing configured the built-in mapping is used', () => {
    const config = buildInputConfig(undefined, [{ joystickIndex: 0, name: 'Pad', guid: 'cccc' }]);
    assert.equal(config[0].controller_type, 'ProController');
    assert.equal(config[0].right_joycon.button_a, 'A');
    assert.equal(config[0].left_joycon.dpad_up, 'DpadUp');
});

test('a template mapping is copied, not shared', () => {
    const existing = [{ backend: 'GamepadSDL2', id: '0-aaaa', player_index: 'Player1', right_joycon: { button_a: 'A' } }];
    const config = buildInputConfig(existing, [
        { joystickIndex: 0, name: 'One', guid: 'dddd' },
        { joystickIndex: 1, name: 'Two', guid: 'eeee' }
    ]);
    config[0].right_joycon.button_a = 'CHANGED';
    assert.equal(config[1].right_joycon.button_a, 'A');
    assert.equal(existing[0].right_joycon.button_a, 'A');
});

test('an unchanged controller set is recognised, so the config is left alone', () => {
    const controllers = parseInputDevices(PROC_DEVICES);
    const config = buildInputConfig([], controllers);
    assert.equal(sameConfiguration(config, buildInputConfig(config, controllers)), true);
    assert.equal(sameConfiguration(config, buildInputConfig(config, controllers.slice(0, 1))), false);
});

test('applying writes a backup and leaves valid JSON behind', () => {
    const { setupControllers } = require('./ryujinx-input');
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-ryujinx-'));
    const configDir = path.join(home, '.config', 'Ryujinx');
    fs.mkdirSync(configDir, { recursive: true });
    const configPath = path.join(configDir, 'Config.json');
    fs.writeFileSync(configPath, JSON.stringify({ version: 70, input_config: [], docked_mode: true }, null, 2));

    const procPath = path.join(home, 'devices');
    fs.writeFileSync(procPath, PROC_DEVICES);

    const result = setupControllers({ homeDir: home, isEmulatorRunning: () => false, procPath });
    assert.equal(result.success, true);
    assert.equal(result.changed, true);

    const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.equal(written.input_config.length, 2);
    // Settings that have nothing to do with input survive untouched.
    assert.equal(written.docked_mode, true);
    assert.equal(written.version, 70);
    assert.ok(fs.existsSync(`${configPath}.romstore-backup`));

    // Running it again with the same pads must not rewrite anything.
    assert.equal(setupControllers({ homeDir: home, isEmulatorRunning: () => false, procPath }).changed, false);
});

test('nothing is written while Ryujinx is open', () => {
    const { setupControllers } = require('./ryujinx-input');
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-ryujinx-'));
    const configDir = path.join(home, '.config', 'Ryujinx');
    fs.mkdirSync(configDir, { recursive: true });
    const configPath = path.join(configDir, 'Config.json');
    const original = JSON.stringify({ version: 70, input_config: [] }, null, 2);
    fs.writeFileSync(configPath, original);
    const procPath = path.join(home, 'devices');
    fs.writeFileSync(procPath, PROC_DEVICES);

    // Ryujinx keeps the config in memory and writes it back when it exits, so
    // anything written underneath it would simply be discarded.
    const result = setupControllers({ homeDir: home, isEmulatorRunning: () => true, procPath });
    assert.equal(result.success, false);
    assert.equal(result.reason, 'emulator-running');
    assert.equal(fs.readFileSync(configPath, 'utf8'), original);
});

test('with no controllers plugged in the config is left alone', () => {
    const { setupControllers } = require('./ryujinx-input');
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-ryujinx-'));
    const procPath = path.join(home, 'devices');
    fs.writeFileSync(procPath, '');
    const result = setupControllers({ homeDir: home, isEmulatorRunning: () => false, procPath });
    assert.equal(result.success, false);
    assert.equal(result.reason, 'no-controllers');
});
