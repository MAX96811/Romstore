#!/usr/bin/env node
// thorsync — syncs emulator saves between the AYN Thor (over ADB) and the
// RomStore server, so progress follows between the PC and the handheld.
//
// Android 13 blocks apps (even with all-files access) from reading other apps'
// Android/data folders, so the on-device RomStore client cannot reach Dolphin
// or Eden saves; ADB can, which is why this runs from the desktop.
//
// Usage: node thorsync.js [--dry-run] [--prefer-thor | --prefer-server] [--addr IP:PORT]

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const THOR_IP = '192.168.2.38';
const STATE_DIR = path.join(os.homedir(), '.local', 'state', 'thorsync');
const STATE_FILE = path.join(STATE_DIR, 'state.json');
const CLIENT_CONFIG = path.join(os.homedir(), '.config', 'romstore-client', 'config.json');

// Thor-side base directory <=> server relPath prefix. Eden is handled
// separately because the profile UUID differs per device.
const MAPPINGS = [
    { thor: '/sdcard/Android/data/org.dolphinemu.dolphinemu/files/Wii/title', server: 'dolphin/Wii/title' },
    { thor: '/sdcard/Android/data/org.dolphinemu.dolphinemu/files/GC', server: 'dolphin/GC' },
    { thor: '/sdcard/Android/data/me.magnum.melondualds/files/saves', server: 'melonds/saves' },
];
const EDEN_THOR_BASE = '/sdcard/Android/data/com.miHoYo.Yuanshen/files/nand/user/save/0000000000000000';
const EDEN_SERVER_BASE = 'eden/saves/0000000000000000';

const args = process.argv.slice(2);
const DRY = args.includes('--dry-run');
const PREFER = args.includes('--prefer-thor') ? 'thor' : args.includes('--prefer-server') ? 'server' : null;
const addrArg = args.find(a => a.startsWith('--addr'));

function log(msg) { console.log(msg); }

// --- config / auth ---
const clientCfg = JSON.parse(fs.readFileSync(CLIENT_CONFIG, 'utf8'));
const SERVER = (clientCfg.serverUrl || 'http://192.168.2.70:1567').replace(/\/$/, '');
const TOKEN = clientCfg.savedSessionToken;
if (!TOKEN) { console.error('No savedSessionToken in romstore-client config; log into the desktop client once.'); process.exit(1); }
const HEADERS = { 'X-Session-Token': TOKEN };

// --- adb ---
function adb(argv, opts = {}) {
    return execFileSync('adb', ['-s', ADDR, ...argv], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
}
function shq(p) { return `'${p.replace(/'/g, `'\\''`)}'`; }

function findThorAddr() {
    if (addrArg) return addrArg.split('=')[1] || args[args.indexOf(addrArg) + 1];
    const devices = execFileSync('adb', ['devices'], { encoding: 'utf8' });
    const line = devices.split('\n').find(l => l.startsWith(THOR_IP) && l.includes('\tdevice'));
    if (line) return line.split('\t')[0];
    // wireless debugging port moves around; scan for it
    log('Scanning for the Thor’s ADB port…');
    let out = '';
    try { out = execFileSync('nmap', ['-p', '30000-49999', '--open', '-T4', THOR_IP], { encoding: 'utf8' }); } catch (e) { }
    const m = out.match(/(\d+)\/tcp open/);
    if (!m) { console.error('Thor not reachable (is Wireless debugging on?)'); process.exit(1); }
    const addr = `${THOR_IP}:${m[1]}`;
    execFileSync('adb', ['connect', addr], { encoding: 'utf8' });
    return addr;
}
const ADDR = findThorAddr();

function listThorFiles(base) {
    let out;
    try {
        out = adb(['shell', `find ${shq(base)} -type f -exec stat -c '%s|%Y|%n' {} + 2>/dev/null`]);
    } catch (e) { return []; }
    return out.split('\n').filter(Boolean).map(line => {
        const [size, mtime, ...rest] = line.split('|');
        const full = rest.join('|');
        if (!full || !/^\d+$/.test(size)) return null;
        return { fullPath: full, rel: full.slice(base.length + 1), size: Number(size), mtimeMs: Number(mtime) * 1000 };
    }).filter(Boolean);
}

// --- server ---
async function serverSaves() {
    const res = await fetch(`${SERVER}/api/saves`, { headers: HEADERS });
    if (res.status === 401) { console.error('Session token rejected; log into the desktop client to refresh it.'); process.exit(1); }
    if (!res.ok) throw new Error(`GET /api/saves -> ${res.status}`);
    return res.json();
}

async function downloadSave(relPath, destTmp) {
    const url = `${SERVER}/api/download?type=saves&path=${encodeURIComponent(relPath)}`;
    const res = await fetch(url, { headers: HEADERS });
    if (!res.ok) throw new Error(`download ${relPath} -> ${res.status}`);
    fs.writeFileSync(destTmp, Buffer.from(await res.arrayBuffer()));
}

async function uploadSave(relPath, localTmp) {
    const form = new FormData();
    form.append('relPath', relPath);
    form.append('file', new Blob([fs.readFileSync(localTmp)]), path.posix.basename(relPath));
    const res = await fetch(`${SERVER}/api/saves/upload`, { method: 'POST', headers: HEADERS, body: form });
    if (!res.ok) throw new Error(`upload ${relPath} -> ${res.status}: ${await res.text()}`);
    return res.json();
}

// --- state ---
let state = {};
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (e) { }
function saveState() {
    if (DRY) return;
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 1));
}

// --- planning ---
// Builds the work list for one prefix pair from thor files, server files and
// the last-sync state, using the same conservative rules as the desktop client.
function plan(pairs) {
    const actions = [];
    for (const p of pairs) {
        const rec = state[p.serverRel];
        const thorChanged = p.thor && (!rec || rec.thorMtimeMs !== p.thor.mtimeMs || rec.thorSize !== p.thor.size);
        const serverChanged = p.server && (!rec || rec.serverHash !== p.server.hash);

        if (p.thor && !p.server) { actions.push({ type: 'upload', ...p }); continue; }
        if (!p.thor && p.server) { actions.push({ type: 'download', ...p }); continue; }

        if (!rec) {
            // First contact on both sides: newest copy wins unless forced.
            const serverMs = new Date(p.server.mtime).getTime();
            const pick = PREFER || (p.thor.mtimeMs > serverMs ? 'thor' : 'server');
            if (p.thor.size === p.server.sizeBytes && Math.abs(p.thor.mtimeMs - serverMs) < 2000) {
                actions.push({ type: 'record', ...p });
            } else {
                actions.push({ type: pick === 'thor' ? 'upload' : 'download', firstRun: true, ...p });
            }
            continue;
        }
        if (thorChanged && serverChanged) { actions.push({ type: PREFER ? (PREFER === 'thor' ? 'upload' : 'download') : 'conflict', ...p }); continue; }
        if (thorChanged) { actions.push({ type: 'upload', ...p }); continue; }
        if (serverChanged) { actions.push({ type: 'download', ...p }); continue; }
    }
    return actions;
}

function pairUp(thorFiles, serverFiles, thorBase, serverPrefix) {
    const byRel = new Map();
    for (const t of thorFiles) byRel.set(t.rel, { thor: t });
    for (const s of serverFiles) {
        const rel = s.relPath.slice(serverPrefix.length + 1);
        byRel.set(rel, { ...(byRel.get(rel) || {}), server: s });
    }
    return [...byRel.entries()].map(([rel, v]) => ({
        rel,
        thorPath: `${thorBase}/${rel}`,
        serverRel: `${serverPrefix}/${rel}`,
        thor: v.thor || null,
        server: v.server || null,
    }));
}

async function execute(actions) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'thorsync-'));
    let up = 0, down = 0, conflicts = [];
    for (const a of actions) {
        if (a.type === 'record') {
            state[a.serverRel] = { thorMtimeMs: a.thor.mtimeMs, thorSize: a.thor.size, serverHash: a.server.hash };
            continue;
        }
        if (a.type === 'conflict') { conflicts.push(a.serverRel); continue; }
        const tag = a.firstRun ? ' (first sync, newer copy)' : '';
        if (a.type === 'upload') {
            log(`  ⬆ ${a.serverRel}${tag}`);
            if (!DRY) {
                const tmp = path.join(tmpDir, 'up.bin');
                execFileSync('adb', ['-s', ADDR, 'pull', a.thorPath, tmp], { stdio: 'pipe' });
                const resp = await uploadSave(a.serverRel, tmp);
                if (a.alsoUploadTo) await uploadSave(a.alsoUploadTo, tmp);
                state[a.serverRel] = { thorMtimeMs: a.thor.mtimeMs, thorSize: a.thor.size, serverHash: resp.hash };
            }
            up++;
        } else if (a.type === 'download') {
            log(`  ⬇ ${a.serverRel}${tag}`);
            if (!DRY) {
                const tmp = path.join(tmpDir, 'down.bin');
                await downloadSave(a.serverRel, tmp);
                adb(['shell', `mkdir -p ${shq(path.posix.dirname(a.thorPath))}`]);
                execFileSync('adb', ['-s', ADDR, 'push', tmp, a.thorPath], { stdio: 'pipe' });
                const st = adb(['shell', `stat -c '%s|%Y' ${shq(a.thorPath)}`]).trim().split('|');
                state[a.serverRel] = { thorMtimeMs: Number(st[1]) * 1000, thorSize: Number(st[0]), serverHash: a.server.hash };
            }
            down++;
        }
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
    return { up, down, conflicts };
}

(async () => {
    log(`thorsync: ${ADDR} <-> ${SERVER}${DRY ? '  [DRY RUN]' : ''}`);
    const saves = await serverSaves();
    let allActions = [];

    // Plain prefix mappings
    for (const m of MAPPINGS) {
        const thorFiles = listThorFiles(m.thor);
        const serverFiles = saves.filter(s => s.relPath.startsWith(m.server + '/'));
        allActions.push(...plan(pairUp(thorFiles, serverFiles, m.thor, m.server)));
    }

    // Eden: join on title id, profile UUID differs per device.
    const localUuids = adb(['shell', `ls ${shq(EDEN_THOR_BASE)} 2>/dev/null`]).split('\n')
        .map(s => s.trim()).filter(s => /^[0-9A-Fa-f]{32}$/.test(s) && !/^0+$/.test(s));
    const localUuid = localUuids[0] || null;

    // Ryujinx bridge: the PC plays through Ryujinx (per-slot layout), the Thor
    // through Eden (per-title layout). Join the two on the title id the server
    // resolves from each slot's ExtraData, so one game shares one save.
    if (localUuid) {
        const slotByTitle = {};
        for (const s of saves) {
            const m = s.relPath.match(/^ryujinx\/saves\/([0-9a-f]{16})\/([01])\/(.+)$/i);
            if (!m || !s.switchTitleId) continue;
            const t = s.switchTitleId.toUpperCase();
            (slotByTitle[t] ||= { slot: m[1], gens: {} });
            (slotByTitle[t].gens[m[2]] ||= []).push({ ...s, file: m[3] });
        }
        for (const [title, info] of Object.entries(slotByTitle)) {
            // Newest generation directory is Ryujinx's committed state.
            const gens = Object.entries(info.gens);
            if (!gens.length) continue;
            const newest = gens.sort((a, b) =>
                Math.max(...b[1].map(f => new Date(f.mtime).getTime())) -
                Math.max(...a[1].map(f => new Date(f.mtime).getTime())))[0];
            const [gen, files] = newest;
            const thorBase = `${EDEN_THOR_BASE}/${localUuid}/${title}`;
            const thorFiles = listThorFiles(thorBase);
            const pairs = pairUp(thorFiles, files.map(f => ({ ...f, relPath: f.relPath })),
                thorBase, `ryujinx/saves/${info.slot}/${gen}`);
            // Uploads must land in BOTH generation dirs so Ryujinx sees a
            // consistent committed state whichever one it opens.
            for (const a of plan(pairs)) {
                if (a.type === 'upload') a.alsoUploadTo = `ryujinx/saves/${info.slot}/${gen === '0' ? '1' : '0'}/${a.rel}`;
                allActions.push(a);
            }
        }
    }

    const serverEden = saves.filter(s => s.relPath.startsWith(EDEN_SERVER_BASE + '/'));
    const titleToServerUuid = {};
    for (const s of serverEden) {
        const parts = s.relPath.split('/');
        if (parts.length >= 5 && /^[0-9A-Fa-f]{32}$/.test(parts[3])) titleToServerUuid[parts[4].toUpperCase()] = parts[3];
    }
    if (localUuid) {
        const thorEdenBase = `${EDEN_THOR_BASE}/${localUuid}`;
        const thorFiles = listThorFiles(thorEdenBase);
        const titles = new Set([
            ...thorFiles.map(f => f.rel.split('/')[0].toUpperCase()),
            ...Object.keys(titleToServerUuid),
        ]);
        for (const title of titles) {
            const serverUuid = titleToServerUuid[title] || localUuid;
            const serverPrefix = `${EDEN_SERVER_BASE}/${serverUuid}/${title}`;
            const thorBase = `${thorEdenBase}/${title}`;
            const tFiles = thorFiles.filter(f => f.rel.toUpperCase().startsWith(title + '/'))
                .map(f => ({ ...f, rel: f.rel.split('/').slice(1).join('/') }));
            const sFiles = serverEden.filter(s => s.relPath.toUpperCase().startsWith(serverPrefix.toUpperCase() + '/'));
            allActions.push(...plan(pairUp(tFiles, sFiles, thorBase, serverPrefix)));
        }
    }

    const todo = allActions.filter(a => a.type !== 'record');
    log(`${todo.filter(a => a.type === 'upload').length} to upload, ${todo.filter(a => a.type === 'download').length} to download, ${todo.filter(a => a.type === 'conflict').length} conflicts`);
    const res = await execute(allActions);
    saveState();
    log(`Done: ${res.up} uploaded, ${res.down} downloaded.`);
    if (res.conflicts.length) {
        log(`CONFLICTS (changed on both sides) — re-run with --prefer-thor or --prefer-server:`);
        res.conflicts.forEach(c => log(`  ! ${c}`));
    }
})().catch(e => { console.error('thorsync failed:', e.message); process.exit(1); });
