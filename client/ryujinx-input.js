const fs = require('fs');
const path = require('path');

// Ryujinx binds each pad by SDL GUID, and that GUID changes with the device and
// the order it was plugged in. Configuring a second controller therefore means
// opening the emulator, adding a player, and picking the pad by hand every time
// the set of controllers changes. All of that information is already on the
// system, so this builds the input configuration from what is actually plugged
// in and writes it to Ryujinx's config.

const BTN_SOUTH = 0x130; // The A/cross button: present on gamepads, on nothing else.
const PLAYER_SLOTS = ['Player1', 'Player2', 'Player3', 'Player4', 'Player5', 'Player6', 'Player7', 'Player8'];

// Devices that expose a joystick node without being something you play with.
// Remote-desktop and streaming hosts install these, and they would otherwise
// take Player1 and leave the real controller unbound.
const NON_GAMEPAD_NAMES = /passthrough|virtual core|uinput-|mouse|keyboard|touchpad|trackpad|consumer control|system control/i;

function parseHexWords(value) {
    return String(value || '')
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map(word => BigInt('0x' + word));
}

// /proc/bus/input/devices prints capability bitmaps as space-separated words,
// most significant first, each covering 64 bits.
function hasCapabilityBit(bitmapWords, bit) {
    const wordIndex = Math.floor(bit / 64);
    const fromEnd = bitmapWords.length - 1 - wordIndex;
    if (fromEnd < 0) return false;
    return ((bitmapWords[fromEnd] >> BigInt(bit % 64)) & 1n) === 1n;
}

// SDL derives a joystick GUID from the evdev identity, and Ryujinx stores it in
// .NET's Guid rendering: a little-endian uint32, two little-endian uint16s,
// then six bytes verbatim.
function formatDotNetGuid(bytes) {
    const hex = offset => bytes.subarray(offset, offset + 2).toString('hex');
    return [
        bytes.readUInt32LE(0).toString(16).padStart(8, '0'),
        bytes.readUInt16LE(4).toString(16).padStart(4, '0'),
        bytes.readUInt16LE(6).toString(16).padStart(4, '0'),
        hex(8),
        bytes.subarray(10, 16).toString('hex')
    ].join('-');
}

function sdlGuid({ bus, vendor, product, version }) {
    const bytes = Buffer.alloc(16);
    bytes.writeUInt16LE(bus & 0xffff, 0);
    // Bytes 2-3 hold a CRC of the device name in some SDL builds and zero in
    // others; the pads Ryujinx has stored on this machine use zero.
    bytes.writeUInt16LE(vendor & 0xffff, 4);
    bytes.writeUInt16LE(product & 0xffff, 8);
    bytes.writeUInt16LE(version & 0xffff, 12);
    return formatDotNetGuid(bytes);
}

function parseInputDevices(text) {
    const devices = [];
    for (const block of String(text || '').split(/\n\s*\n/)) {
        if (!block.trim()) continue;

        const identity = block.match(/^I:\s*Bus=([0-9a-f]+)\s+Vendor=([0-9a-f]+)\s+Product=([0-9a-f]+)\s+Version=([0-9a-f]+)/mi);
        const name = block.match(/^N:\s*Name="([^"]*)"/mi);
        const handlers = block.match(/^H:\s*Handlers=(.*)$/mi);
        const keys = block.match(/^B:\s*KEY=(.*)$/mi);
        if (!identity || !handlers) continue;

        const joystickHandler = (handlers[1].match(/\bjs(\d+)\b/) || [])[1];
        if (joystickHandler === undefined) continue;
        if (!keys || !hasCapabilityBit(parseHexWords(keys[1]), BTN_SOUTH)) continue;

        const deviceName = name ? name[1] : '';
        if (NON_GAMEPAD_NAMES.test(deviceName)) continue;

        devices.push({
            joystickIndex: Number(joystickHandler),
            name: deviceName,
            guid: sdlGuid({
                bus: parseInt(identity[1], 16),
                vendor: parseInt(identity[2], 16),
                product: parseInt(identity[3], 16),
                version: parseInt(identity[4], 16)
            })
        });
    }

    // SDL numbers controllers in joystick-node order, and so does Ryujinx's id.
    return devices.sort((a, b) => a.joystickIndex - b.joystickIndex);
}

function detectControllers(procPath = '/proc/bus/input/devices') {
    try {
        return parseInputDevices(fs.readFileSync(procPath, 'utf8'));
    } catch (error) {
        return [];
    }
}

// Ryujinx counts controllers from zero in the order SDL enumerated them, which
// is not the joystick node number once a device has been unplugged.
function controllerId(controller, order) {
    return `${order}-${controller.guid}`;
}

// A default Pro Controller mapping, used only when Ryujinx has never had a pad
// configured. Anything already in the config is a better template than this,
// because it carries whatever the user changed.
function defaultMapping() {
    return {
        left_joycon_stick: { joystick: 'Left', invert_stick_x: false, invert_stick_y: false, rotate90_cw: false, stick_button: 'LeftStick' },
        right_joycon_stick: { joystick: 'Right', invert_stick_x: false, invert_stick_y: false, rotate90_cw: false, stick_button: 'RightStick' },
        deadzone_left: 0.1,
        deadzone_right: 0.1,
        range_left: 1.0,
        range_right: 1.0,
        trigger_threshold: 0.5,
        motion: { motion_backend: 'GamepadDriver', sensitivity: 100, gyro_deadzone: 1.0, enable_motion: true },
        rumble: { strong_rumble: 1.0, weak_rumble: 1.0, enable_rumble: false },
        led: { enable_led: false, turn_off_led: false, use_rainbow: false, led_color: 0 },
        left_joycon: { button_minus: 'Minus', button_l: 'LeftShoulder', button_zl: 'LeftTrigger', button_sl: 'Unbound', button_sr: 'Unbound', dpad_up: 'DpadUp', dpad_down: 'DpadDown', dpad_left: 'DpadLeft', dpad_right: 'DpadRight' },
        right_joycon: { button_plus: 'Plus', button_r: 'RightShoulder', button_zr: 'RightTrigger', button_sl: 'Unbound', button_sr: 'Unbound', button_x: 'X', button_b: 'B', button_y: 'Y', button_a: 'A' },
        version: 1,
        backend: 'GamepadSDL2',
        controller_type: 'ProController'
    };
}

// Each connected pad keeps the mapping it already had, matched by GUID, so a
// controller that was customised in Ryujinx is not reset by being re-detected.
// A pad seen for the first time inherits the first configured mapping.
function buildInputConfig(existingConfig, controllers) {
    const existing = Array.isArray(existingConfig) ? existingConfig : [];
    const byGuid = new Map();
    for (const entry of existing) {
        const guid = String((entry && entry.id) || '').split('-').slice(1).join('-');
        if (guid && !byGuid.has(guid)) byGuid.set(guid, entry);
    }
    const template = existing.find(entry => entry && entry.backend === 'GamepadSDL2') || null;

    return controllers.slice(0, PLAYER_SLOTS.length).map((controller, order) => {
        const base = byGuid.get(controller.guid) || template || defaultMapping();
        return {
            ...JSON.parse(JSON.stringify(base)),
            backend: 'GamepadSDL2',
            id: controllerId(controller, order),
            name: controller.name,
            player_index: PLAYER_SLOTS[order]
        };
    });
}

function sameConfiguration(existing, next) {
    const identity = list => (Array.isArray(list) ? list : [])
        .map(entry => `${entry && entry.player_index}|${entry && entry.id}`)
        .join(',');
    return identity(existing) === identity(next);
}

// Every Ryujinx installation on the machine gets the same treatment: EmuDeck
// can launch either the AppImage or the Flatpak, and which one runs is decided
// by the launcher at play time, not here.
function configPaths(homeDir) {
    return [
        path.join(homeDir, '.config', 'Ryujinx', 'Config.json'),
        path.join(homeDir, '.config', 'Ryubing', 'Config.json'),
        path.join(homeDir, '.var', 'app', 'io.github.ryubing.Ryujinx', 'config', 'Ryujinx', 'Config.json'),
        path.join(homeDir, '.var', 'app', 'org.ryujinx.Ryujinx', 'config', 'Ryujinx', 'Config.json')
    ].filter(candidate => fs.existsSync(candidate));
}

function applyToConfigFile(configPath, controllers) {
    const raw = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(raw);
    const next = buildInputConfig(config.input_config, controllers);

    if (sameConfiguration(config.input_config, next)) return { path: configPath, changed: false, players: next.length };

    config.input_config = next;
    // Ryujinx rewrites this file on exit, so the backup is the way back to a
    // mapping the user built by hand.
    fs.writeFileSync(`${configPath}.romstore-backup`, raw);
    const temporaryPath = `${configPath}.romstore-tmp`;
    fs.writeFileSync(temporaryPath, JSON.stringify(config, null, 2));
    fs.renameSync(temporaryPath, configPath);
    return { path: configPath, changed: true, players: next.length };
}

function setupControllers({ homeDir, isEmulatorRunning, procPath } = {}) {
    const controllers = detectControllers(procPath);
    if (!controllers.length) return { success: false, reason: 'no-controllers', controllers, results: [] };

    // Ryujinx holds the configuration in memory and writes it back on exit,
    // which would undo anything written underneath it.
    if (typeof isEmulatorRunning === 'function' && isEmulatorRunning()) {
        return { success: false, reason: 'emulator-running', controllers, results: [] };
    }

    const targets = configPaths(homeDir);
    if (!targets.length) return { success: false, reason: 'no-config', controllers, results: [] };

    const results = [];
    for (const target of targets) {
        try {
            results.push(applyToConfigFile(target, controllers));
        } catch (error) {
            results.push({ path: target, changed: false, error: error.message });
        }
    }

    return {
        success: results.some(result => !result.error),
        controllers,
        changed: results.some(result => result.changed),
        results
    };
}

module.exports = {
    buildInputConfig,
    configPaths,
    defaultMapping,
    detectControllers,
    parseInputDevices,
    sameConfiguration,
    sdlGuid,
    setupControllers
};
