const fs = require('fs');
const os = require('os');
const path = require('path');

const LAUNCHER_ALIASES = {
    AZAHAR: ['azahar.sh'],
    CEMU: ['cemu.sh'],
    CITRA: ['azahar.sh', 'citra.sh'],
    DESMUME: ['melonds.sh', 'desmume.sh'],
    DOLPHIN: ['dolphin-emu.sh'],
    DUCKSTATION: ['duckstation.sh'],
    EDEN: ['eden.sh'],
    FLYCAST: ['flycast.sh'],
    MAME: ['mame.sh'],
    MEDNAFEN: ['mednafen.sh'],
    MELONDS: ['melonds.sh'],
    MGBA: ['mgba.sh'],
    MODEL2: ['model-2-emulator.sh'],
    'OS-SHELL': ['bash', 'sh'],
    PCSX2: ['pcsx2-qt.sh'],
    'PCSX2-LEGACY': ['pcsx2-legacy.sh'],
    PCSX2QT: ['pcsx2-qt.sh'],
    PLAY: ['play.sh'],
    PPSSPP: ['ppsspp.sh'],
    PRIMEHACK: ['primehack.sh'],
    RETROARCH: ['retroarch.sh'],
    RMG: ['rosaliesmupengui.sh', 'rmg.sh'],
    RPCS3: ['rpcs3.sh'],
    RYUJINX: ['ryujinx.sh'],
    SCUMMVM: ['scummvm.sh'],
    SHADPS4: ['shadps4.sh'],
    SNES9X: ['snes9x.sh'],
    SUPERMODEL: ['supermodel.sh'],
    VITA3K: ['vita3k.sh'],
    XEMU: ['xemu-emu.sh', 'xemu.sh'],
    XENIA: ['xenia.sh'],
    YUZU: ['yuzu.sh']
};

const FALLBACK_DEFINITIONS = {
    gc: { fullName: 'Nintendo GameCube', commands: [{ label: 'Dolphin', template: '%EMULATOR_DOLPHIN% -b -e %ROM%' }] },
    n3ds: { fullName: 'Nintendo 3DS', commands: [{ label: 'Azahar', template: '%EMULATOR_AZAHAR% %ROM%' }] },
    nds: { fullName: 'Nintendo DS', commands: [{ label: 'melonDS', template: '%EMULATOR_MELONDS% %ROM%' }] },
    ps2: { fullName: 'Sony PlayStation 2', commands: [{ label: 'PCSX2', template: '%EMULATOR_PCSX2% -batch %ROM%' }] },
    ps3: { fullName: 'Sony PlayStation 3', commands: [{ label: 'RPCS3', template: '%EMULATOR_RPCS3% --no-gui %ROM%' }] },
    psp: { fullName: 'Sony PSP', commands: [{ label: 'PPSSPP', template: '%EMULATOR_PPSSPP% %ROM%' }] },
    psx: { fullName: 'Sony PlayStation', commands: [{ label: 'DuckStation', template: '%EMULATOR_DUCKSTATION% -batch %ROM%' }] },
    switch: { fullName: 'Nintendo Switch', commands: [{ label: 'Ryujinx', template: '%EMULATOR_RYUJINX% %ROM%' }] },
    wii: { fullName: 'Nintendo Wii', commands: [{ label: 'Dolphin', template: '%EMULATOR_DOLPHIN% -b -e %ROM%' }] },
    wiiu: { fullName: 'Nintendo Wii U', commands: [{ label: 'Cemu', template: '%EMULATOR_CEMU% -f -g %ROM%' }] },
    xbox: { fullName: 'Microsoft Xbox', commands: [{ label: 'xemu', template: '%EMULATOR_XEMU% -dvd_path %ROM%' }] }
};

function decodeXml(value) {
    return String(value || '')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
}

function readSection(lines, heading) {
    const index = lines.findIndex(line => line.trim().toLowerCase() === heading.toLowerCase());
    if (index === -1) return [];
    const values = [];
    for (let i = index + 1; i < lines.length; i++) {
        const value = lines[i].trim();
        if (!value) {
            if (values.length) break;
            continue;
        }
        if (/^[A-Za-z][A-Za-z ()/-]*:$/.test(value)) break;
        values.push(value);
    }
    return values;
}

function parseSystemInfo(text) {
    const lines = String(text || '').split(/\r?\n/);
    const system = readSection(lines, 'System name:')[0] || '';
    const fullName = readSection(lines, 'Full system name:')[0] || system;
    const extensionLine = readSection(lines, 'Supported file extensions:').join(' ');
    const extensions = Array.from(new Set(extensionLine.split(/\s+/).map(value => value.toLowerCase()).filter(value => /^\.[a-z0-9]/.test(value))));
    const commandHeadings = ['Launch command:', 'Alternative launch command:', 'Alternative launch commands:'];
    const commands = [];
    for (const heading of commandHeadings) {
        for (const template of readSection(lines, heading)) {
            commands.push({ label: heading.startsWith('Launch') ? 'EmuDeck default' : 'EmuDeck alternative', template });
        }
    }
    return { system, fullName, extensions, commands };
}

function parseCustomSystemsXml(text) {
    const definitions = {};
    const systemPattern = /<system>([\s\S]*?)<\/system>/gi;
    let systemMatch;
    while ((systemMatch = systemPattern.exec(String(text || ''))) !== null) {
        const block = systemMatch[1];
        const field = name => {
            const match = block.match(new RegExp(`<${name}>([\\s\\S]*?)<\\/${name}>`, 'i'));
            return match ? decodeXml(match[1].trim()) : '';
        };
        const system = field('name').toLowerCase();
        if (!system) continue;
        const commands = [];
        const commandPattern = /<command(?:\s+label="([^"]*)")?>([\s\S]*?)<\/command>/gi;
        let commandMatch;
        while ((commandMatch = commandPattern.exec(block)) !== null) {
            commands.push({
                label: decodeXml(commandMatch[1] || 'ES-DE'),
                template: decodeXml(commandMatch[2].trim())
            });
        }
        definitions[system] = {
            system,
            fullName: field('fullname') || system,
            extensions: field('extension').split(/\s+/).map(value => value.toLowerCase()).filter(Boolean),
            commands
        };
    }
    return definitions;
}

function tokenizeCommand(command) {
    const tokens = [];
    let current = '';
    let quote = null;
    let escaped = false;
    for (const character of String(command || '')) {
        if (escaped) {
            current += character;
            escaped = false;
            continue;
        }
        if (character === '\\' && quote !== "'") {
            escaped = true;
            continue;
        }
        if (quote) {
            if (character === quote) quote = null;
            else current += character;
            continue;
        }
        if (character === '"' || character === "'") {
            quote = character;
            continue;
        }
        if (/\s/.test(character)) {
            if (current) {
                tokens.push(current);
                current = '';
            }
            continue;
        }
        current += character;
    }
    if (escaped) current += '\\';
    if (quote) throw new Error('Unclosed quote in emulator command');
    if (current) tokens.push(current);
    return tokens;
}

function expandHome(value, homeDir) {
    if (value === '~') return homeDir;
    if (value.startsWith('~/')) return path.join(homeDir, value.slice(2));
    return value;
}

function findOnPath(command, envPath = process.env.PATH || '') {
    if (!command) return null;
    if (path.isAbsolute(command)) return fs.existsSync(command) ? command : null;
    for (const directory of envPath.split(path.delimiter)) {
        const candidate = path.join(directory, command);
        try {
            if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
        } catch (error) { }
    }
    return null;
}

function findLauncher(macroName, launcherDir) {
    const normalized = macroName.replace(/^EMULATOR_/, '').replace(/!/g, '').replace(/_/g, '-');
    const aliases = LAUNCHER_ALIASES[normalized] || LAUNCHER_ALIASES[normalized.replace(/-/g, '_')] || [];
    for (const alias of aliases) {
        if (!alias.endsWith('.sh')) {
            const executable = findOnPath(alias);
            if (executable) return executable;
            continue;
        }
        const candidate = path.join(launcherDir, alias);
        if (fs.existsSync(candidate)) return candidate;
    }
    return null;
}

function findRetroArchCoreDir(homeDir) {
    const candidates = [
        path.join(homeDir, '.var/app/org.libretro.RetroArch/config/retroarch/cores'),
        path.join(homeDir, '.config/retroarch/cores')
    ];
    return candidates.find(candidate => fs.existsSync(candidate)) || candidates[0];
}

function replaceWithMarkers(template, values) {
    let marked = template;
    const markers = [];
    for (const [needle, value] of values) {
        const marker = `__ROMSTORE_VALUE_${markers.length}__`;
        marked = marked.split(needle).join(marker);
        markers.push({ marker, value });
    }
    return { marked, markers };
}

function normalizeLauncherPath(token, launcherDir) {
    const normalized = token.replace(/\\/g, '/');
    const marker = '/Emulation/tools/launchers/';
    const index = normalized.lastIndexOf(marker);
    if (index === -1) return token;
    const relative = normalized.slice(index + marker.length);
    const candidate = path.join(launcherDir, relative);
    return fs.existsSync(candidate) ? candidate : token;
}

function resolveCommand(template, options = {}) {
    const homeDir = options.homeDir || os.homedir();
    const emulationDir = options.emulationDir || path.join(homeDir, 'Emulation');
    const launcherDir = path.join(emulationDir, 'tools', 'launchers');
    const romPath = options.romPath || path.join(emulationDir, 'roms', 'unknown', 'game.rom');
    const system = options.system || path.basename(path.dirname(romPath));
    const romRoot = path.join(emulationDir, 'roms');
    const coreDir = findRetroArchCoreDir(homeDir);

    let normalizedTemplate = String(template || '')
        .trim()
        .replace(/\{(?:file|rom)\}/gi, '%ROM%')
        .replace(/%CORE_RETROARCH%\\/gi, '%CORE_RETROARCH%/')
        .replace(/%ROMPATH%\\/gi, '%ROMPATH%/');
    if (!normalizedTemplate) throw new Error('No emulator command is configured');
    if (/%(?:INJECT|ENABLESHORTCUTS)%/i.test(normalizedTemplate)) {
        throw new Error('This ES-DE command requires an unsupported injection helper');
    }

    const replacements = [
        ['%ROM%', romPath],
        ['%BASENAME%', path.parse(romPath).name],
        ['%GAMEDIR%', path.dirname(romPath)],
        ['%ROMPATH%', romRoot],
        ['%CORE_RETROARCH%', coreDir]
    ];

    const emulatorMacros = Array.from(new Set(normalizedTemplate.match(/%EMULATOR_[A-Z0-9!_-]+%/gi) || []));
    for (const macro of emulatorMacros) {
        const launcher = findLauncher(macro.slice(1, -1).toUpperCase(), launcherDir);
        if (!launcher) throw new Error(`EmuDeck launcher not found for ${macro}`);
        replacements.push([macro, launcher]);
    }

    const unresolvedSpecial = normalizedTemplate.match(/%[A-Z][A-Z0-9!_-]*%/gi) || [];
    const supported = new Set(replacements.map(([key]) => key.toUpperCase()).concat(['%STARTDIR%']));
    const unknown = unresolvedSpecial.find(macro => !supported.has(macro.toUpperCase()));
    if (unknown) throw new Error(`Unsupported ES-DE command macro ${unknown}`);

    const { marked, markers } = replaceWithMarkers(normalizedTemplate, replacements);
    let tokens = tokenizeCommand(marked).map(token => {
        let value = token;
        for (const replacement of markers) value = value.split(replacement.marker).join(replacement.value);
        return normalizeLauncherPath(expandHome(value, homeDir), launcherDir);
    });

    let cwd = homeDir;
    tokens = tokens.filter(token => {
        if (!token.startsWith('%STARTDIR%=')) return true;
        cwd = expandHome(token.slice('%STARTDIR%='.length), homeDir);
        return false;
    });
    if (!tokens.length) throw new Error('Emulator command is empty after resolving its macros');

    for (const token of tokens) {
        if (token.startsWith(coreDir) && token.includes('_libretro') && !fs.existsSync(token)) {
            throw new Error(`RetroArch core is not installed: ${path.basename(token)}`);
        }
    }

    let command = tokens.shift();
    let args = tokens;
    if (command.endsWith('.sh') && fs.existsSync(command)) {
        args = [command, ...args];
        command = '/bin/bash';
    }
    if (!findOnPath(command)) throw new Error(`Emulator executable not found: ${command}`);

    return { command, args, cwd, system };
}

function findBackendDir(homeDir) {
    const candidates = [
        path.join(homeDir, '.config/EmuDeck/backend'),
        path.join(homeDir, '.config/emudeck/backend')
    ];
    return candidates.find(candidate => fs.existsSync(path.join(candidate, 'roms'))) || null;
}

function customSystemFiles(homeDir) {
    return [
        path.join(homeDir, 'ES-DE/custom_systems/es_systems.xml'),
        path.join(homeDir, '.config/ES-DE/custom_systems/es_systems.xml'),
        path.join(homeDir, '.emulationstation/custom_systems/es_systems.xml'),
        path.join(homeDir, '.var/app/org.es_de.frontend/config/ES-DE/custom_systems/es_systems.xml')
    ].filter(candidate => fs.existsSync(candidate));
}

function loadDefinitions(options = {}) {
    const homeDir = options.homeDir || os.homedir();
    const definitions = {};
    for (const [system, definition] of Object.entries(FALLBACK_DEFINITIONS)) {
        definitions[system] = { system, extensions: [], ...definition };
    }

    const backendDir = options.backendDir || findBackendDir(homeDir);
    if (backendDir) {
        const systemsDir = path.join(backendDir, 'roms');
        for (const entry of fs.readdirSync(systemsDir, { withFileTypes: true })) {
            if (!entry.isDirectory()) continue;
            const infoPath = path.join(systemsDir, entry.name, 'systeminfo.txt');
            if (!fs.existsSync(infoPath)) continue;
            try {
                const parsed = parseSystemInfo(fs.readFileSync(infoPath, 'utf8'));
                const system = (parsed.system || entry.name).toLowerCase();
                definitions[system] = { ...definitions[system], ...parsed, system };
            } catch (error) { }
        }
    }

    for (const configPath of customSystemFiles(homeDir)) {
        try {
            const custom = parseCustomSystemsXml(fs.readFileSync(configPath, 'utf8'));
            for (const [system, definition] of Object.entries(custom)) {
                const existing = definitions[system] || { system, commands: [], extensions: [] };
                definitions[system] = {
                    ...existing,
                    ...definition,
                    commands: [...definition.commands, ...(existing.commands || [])]
                };
            }
        } catch (error) { }
    }

    return { backendDir, definitions };
}

function selectProfile(system, options = {}) {
    const normalizedSystem = String(system || '').toLowerCase();
    const loaded = options.definitions
        ? { backendDir: options.backendDir || null, definitions: options.definitions }
        : loadDefinitions(options);
    const { backendDir, definitions } = loaded;
    const definition = definitions[normalizedSystem];
    if (!definition) {
        return { system: normalizedSystem, available: false, error: `No EmuDeck definition found for ${normalizedSystem}`, backendDir };
    }

    const override = options.overrides && options.overrides[normalizedSystem];
    const candidates = [];
    if (override && override.command) candidates.push({ label: override.label || 'Custom profile', template: override.command, custom: true });
    candidates.push(...(definition.commands || []));

    const errors = [];
    for (const candidate of candidates) {
        try {
            const resolved = resolveCommand(candidate.template, { ...options, system: normalizedSystem });
            return {
                system: normalizedSystem,
                fullName: definition.fullName || normalizedSystem,
                extensions: definition.extensions || [],
                available: true,
                label: candidate.label,
                template: candidate.template,
                custom: !!candidate.custom,
                resolved,
                backendDir
            };
        } catch (error) {
            errors.push(`${candidate.label}: ${error.message}`);
        }
    }

    return {
        system: normalizedSystem,
        fullName: definition.fullName || normalizedSystem,
        extensions: definition.extensions || [],
        available: false,
        error: errors[0] || `No usable emulator profile found for ${normalizedSystem}`,
        errors,
        backendDir
    };
}

function listProfiles(options = {}) {
    const { backendDir, definitions } = loadDefinitions(options);
    const profiles = Object.keys(definitions).sort().map(system => selectProfile(system, {
        ...options,
        backendDir,
        definitions
    }));
    return {
        detected: !!backendDir,
        backendDir,
        emulationDir: options.emulationDir,
        profiles
    };
}

function sanitizeLaunchEnvironment(sourceEnvironment = process.env) {
    const environment = { ...sourceEnvironment };
    const directAppImageKeys = [
        'APPDIR', 'APPIMAGE', 'ARGV0', 'GDK_PIXBUF_MODULE_FILE', 'GIO_MODULE_DIR',
        'GTK_PATH', 'LD_PRELOAD', 'OWD', 'QT_PLUGIN_PATH', 'QML2_IMPORT_PATH'
    ];
    for (const key of directAppImageKeys) delete environment[key];

    for (const [key, value] of Object.entries(environment)) {
        if (typeof value !== 'string' || !value.includes('/tmp/.mount_')) continue;
        if (value.includes(path.delimiter)) {
            const filtered = value.split(path.delimiter).filter(entry => !entry.includes('/tmp/.mount_'));
            if (filtered.length) environment[key] = filtered.join(path.delimiter);
            else delete environment[key];
        } else {
            delete environment[key];
        }
    }
    return environment;
}

module.exports = {
    listProfiles,
    loadDefinitions,
    parseCustomSystemsXml,
    parseSystemInfo,
    resolveCommand,
    sanitizeLaunchEnvironment,
    selectProfile,
    tokenizeCommand
};
