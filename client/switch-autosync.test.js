const assert = require('node:assert/strict');
const test = require('node:test');

const { createSwitchAutoSync, slotIdFromRelativePath } = require('./switch-autosync');

const SLOT_A = '0000000000000004';
const SLOT_B = '0000000000000005';

function harness(overrides = {}) {
    const calls = [];
    const results = [];
    let clock = 100000;
    const state = { running: true, uploads: new Map() };

    const sync = createSwitchAutoSync({
        isEmulatorRunning: () => state.running,
        uploadBundle: async slotId => {
            calls.push(slotId);
            const planned = state.uploads.get(slotId);
            return planned || { success: true, fileCount: 7 };
        },
        onResult: result => results.push(result),
        now: () => clock,
        setTimer: () => null,
        clearTimer: () => { },
        settleMs: 4000,
        ...overrides
    });

    return {
        sync,
        calls,
        results,
        state,
        advance: ms => { clock += ms; },
        stopEmulator: () => { state.running = false; }
    };
}

test('a slot that changes while Ryujinx runs is held, not uploaded', async () => {
    const h = harness();
    h.sync.markDirty(SLOT_A);

    const tick = await h.sync.tick();

    assert.equal(tick.reason, 'emulator-running');
    assert.deepEqual(h.calls, []);
    assert.deepEqual(h.sync.pendingSlots(), [SLOT_A]);
});

test('slots upload as whole bundles once the emulator exits and settles', async () => {
    const h = harness();
    h.sync.markDirty(SLOT_A);
    h.sync.markDirty(SLOT_B);
    await h.sync.tick();

    h.stopEmulator();
    const settling = await h.sync.tick();
    assert.equal(settling.reason, 'settling', 'must not snapshot the instant the process disappears');
    assert.deepEqual(h.calls, []);

    h.advance(5000);
    const flushed = await h.sync.tick();

    assert.equal(flushed.reason, 'flushed');
    assert.deepEqual(h.calls, [SLOT_A, SLOT_B]);
    assert.deepEqual(h.sync.pendingSlots(), []);
    assert.deepEqual(h.results.map(r => r.success), [true, true]);
});

test('a failed upload is retried and abandoned only after maxAttempts', async () => {
    const h = harness({ maxAttempts: 2 });
    h.state.uploads.set(SLOT_A, { success: false, error: 'server offline' });
    h.sync.markDirty(SLOT_A);
    h.stopEmulator();
    h.advance(5000);

    await h.sync.tick();
    assert.deepEqual(h.sync.pendingSlots(), [SLOT_A], 'first failure keeps the slot queued');

    await h.sync.tick();
    assert.deepEqual(h.sync.pendingSlots(), [], 'slot is dropped once attempts are exhausted');
    assert.equal(h.results.at(-1).giveUp, true);
});

test('an emulator-inspection failure fails closed and never snapshots live files', async () => {
    const h = harness({
        isEmulatorRunning: () => { throw new Error('/proc unreadable'); }
    });
    h.sync.markDirty(SLOT_A);

    const tick = await h.sync.tick();

    assert.equal(tick.reason, 'emulator-running');
    assert.deepEqual(h.calls, []);
});

test('relaunching Ryujinx mid-flush stops the remaining uploads', async () => {
    const uploaded = [];
    // Ryujinx is closed for the first check, then comes back up while the
    // first bundle is being sent.
    const runningSequence = [false, true];
    let checks = 0;

    const sync = createSwitchAutoSync({
        isEmulatorRunning: () => runningSequence[Math.min(checks++, runningSequence.length - 1)],
        uploadBundle: async slotId => { uploaded.push(slotId); return { success: true, fileCount: 3 }; },
        now: () => 200000,
        setTimer: () => null,
        clearTimer: () => { },
        settleMs: 0
    });
    sync.markDirty(SLOT_A);
    sync.markDirty(SLOT_B);

    await sync.tick();

    assert.equal(uploaded.length, 1, 'only the bundle already in flight is sent');
    assert.deepEqual(sync.pendingSlots(), [SLOT_B], 'the untouched slot stays queued for the next tick');
});

test('slot ids are derived only from committed bundle paths', () => {
    assert.equal(slotIdFromRelativePath('0000000000000004/0/userdata.dat'), SLOT_A);
    assert.equal(slotIdFromRelativePath('0000000000000004/ExtraData0'), SLOT_A);
    assert.equal(slotIdFromRelativePath('0000000000000004/.oldsave/x_GameData.bin'), null);
    assert.equal(slotIdFromRelativePath('.romstore-backups/0000000000000004/x'), null);
    assert.equal(slotIdFromRelativePath('notaslot/save.bin'), null);
    assert.equal(slotIdFromRelativePath(''), null);
});

test('invalid slot identifiers are never queued', () => {
    const h = harness();
    assert.equal(h.sync.markDirty('nope'), false);
    assert.equal(h.sync.markDirty(''), false);
    assert.deepEqual(h.sync.pendingSlots(), []);
});

test('a queue built while the server was unreachable survives a restart', async () => {
    let disk = [];
    const persist = { persistPending: ids => { disk = ids; }, restorePending: () => disk };

    // Session one: the emulator writes, but every upload fails (server down).
    const first = createSwitchAutoSync({
        isEmulatorRunning: () => false,
        uploadBundle: async () => ({ success: false, error: 'ECONNREFUSED' }),
        now: () => 1000, setTimer: () => null, clearTimer: () => { }, settleMs: 0,
        maxAttempts: 99, ...persist
    });
    first.markDirty(SLOT_A);
    await first.tick();
    assert.deepEqual(disk, [SLOT_A], 'the pending slot is written to disk');

    // The process goes away entirely.
    first.stop();

    // Session two: the server is back.
    const uploaded = [];
    const second = createSwitchAutoSync({
        isEmulatorRunning: () => false,
        uploadBundle: async id => { uploaded.push(id); return { success: true, fileCount: 4 }; },
        now: () => 2000, setTimer: () => null, clearTimer: () => { }, settleMs: 0,
        ...persist
    });
    assert.deepEqual(second.pendingSlots(), [SLOT_A], 'queue is restored from disk');

    await second.tick();
    assert.deepEqual(uploaded, [SLOT_A], 'the offline save is uploaded once the server returns');
    assert.deepEqual(disk, [], 'disk queue is cleared after a successful flush');
});

test('restored queues ignore corrupt or non-slot entries', () => {
    const sync = createSwitchAutoSync({
        isEmulatorRunning: () => false,
        uploadBundle: async () => ({ success: true }),
        restorePending: () => ['not-a-slot', '', null, SLOT_B],
        setTimer: () => null, clearTimer: () => { }
    });
    assert.deepEqual(sync.pendingSlots(), [SLOT_B]);
});

test('resumePending reports what is still queued when connectivity returns', () => {
    const sync = createSwitchAutoSync({
        isEmulatorRunning: () => true,
        uploadBundle: async () => ({ success: true }),
        restorePending: () => [SLOT_A, SLOT_B],
        setTimer: () => null, clearTimer: () => { }
    });
    assert.deepEqual(sync.resumePending().sort(), [SLOT_A, SLOT_B]);
});
