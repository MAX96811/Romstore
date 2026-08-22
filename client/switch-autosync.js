// Ryujinx writes a save as several files that are only mutually consistent once
// the emulator has committed them. The legacy per-file watcher must therefore
// never touch a Switch slot (see shouldSyncSavePath). This scheduler is the
// supported alternative: it records which slots changed during a session and
// uploads each one as a single verified bundle *after* Ryujinx exits.

const DEFAULT_POLL_INTERVAL_MS = 5000;
// Ryujinx flushes its final write as it tears down, so a slot is left to settle
// before it is read; snapshotting the instant the process vanishes can race it.
const DEFAULT_SETTLE_MS = 4000;
const DEFAULT_MAX_ATTEMPTS = 3;

function createSwitchAutoSync(options = {}) {
    const {
        isEmulatorRunning,
        uploadBundle,
        pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
        settleMs = DEFAULT_SETTLE_MS,
        maxAttempts = DEFAULT_MAX_ATTEMPTS,
        onResult = () => { },
        // Offline play and crashes both end a session without a flush, so the
        // queue has to outlive the process rather than living only in memory.
        persistPending = () => { },
        restorePending = () => [],
        now = () => Date.now(),
        setTimer = setInterval,
        clearTimer = clearInterval
    } = options;

    if (typeof isEmulatorRunning !== 'function') throw new Error('isEmulatorRunning is required.');
    if (typeof uploadBundle !== 'function') throw new Error('uploadBundle is required.');

    const pending = new Map();
    let timer = null;
    let flushing = false;
    let lastRunningAt = 0;

    function snapshotPending() {
        try { persistPending([...pending.keys()]); } catch (error) { }
    }

    // A queue restored from disk is resumed on the next tick, so saves made
    // while the server was unreachable are uploaded once it comes back.
    for (const slotId of (restorePending() || [])) {
        const key = String(slotId || '').toUpperCase();
        if (/^[0-9A-F]{16}$/.test(key)) pending.set(key, { attempts: 0 });
    }

    function ensureTimer() {
        if (timer || !pending.size) return;
        timer = setTimer(() => { tick(); }, pollIntervalMs);
        if (timer && typeof timer.unref === 'function') timer.unref();
    }

    function stopTimer() {
        if (!timer) return;
        clearTimer(timer);
        timer = null;
    }

    function markDirty(slotId) {
        const key = String(slotId || '').toUpperCase();
        if (!/^[0-9A-F]{16}$/.test(key)) return false;
        if (!pending.has(key)) {
            pending.set(key, { attempts: 0 });
            snapshotPending();
        }
        ensureTimer();
        return true;
    }

    // isRyujinxRunning already fails closed; mirror that here so an inspection
    // error can never be read as "safe to snapshot". The callback may be sync
    // or async, so it is always awaited through this one path.
    async function emulatorRunning() {
        try {
            return await isEmulatorRunning();
        } catch (error) {
            return true;
        }
    }

    // Exposed so the caller can drive the state machine from a test or from a
    // deterministic event (emulator exit) instead of waiting on the poll timer.
    async function tick() {
        if (flushing) return { flushed: [], reason: 'busy' };
        if (!pending.size) {
            stopTimer();
            return { flushed: [], reason: 'idle' };
        }

        const running = await emulatorRunning();
        if (running) {
            lastRunningAt = now();
            return { flushed: [], reason: 'emulator-running' };
        }
        if (lastRunningAt && now() - lastRunningAt < settleMs) {
            return { flushed: [], reason: 'settling' };
        }

        flushing = true;
        const flushed = [];
        try {
            for (const slotId of [...pending.keys()]) {
                const state = pending.get(slotId);
                if (!state) continue;

                let result;
                try {
                    result = await uploadBundle(slotId);
                } catch (error) {
                    result = { success: false, error: error && error.message };
                }

                if (result && result.success) {
                    pending.delete(slotId);
                    flushed.push({ slotId, success: true, fileCount: result.fileCount });
                    onResult({ slotId, success: true, fileCount: result.fileCount });
                } else {
                    state.attempts += 1;
                    const giveUp = state.attempts >= maxAttempts;
                    if (giveUp) pending.delete(slotId);
                    flushed.push({ slotId, success: false, error: result && result.error, giveUp });
                    onResult({ slotId, success: false, error: result && result.error, giveUp });
                }

                // Uploading a bundle takes time, and Ryujinx may have been
                // relaunched during it. This check must run after every slot,
                // successful or not: anything still queued has to wait rather
                // than be snapshotted out from under a live emulator.
                if (pending.size && await emulatorRunning()) {
                    lastRunningAt = now();
                    break;
                }
            }
        } finally {
            flushing = false;
            snapshotPending();
            if (!pending.size) stopTimer();
        }

        return { flushed, reason: 'flushed' };
    }

    // Called when connectivity returns: a restored queue has no timer until
    // something asks for one, and nothing new may be written for hours.
    function resumePending() {
        ensureTimer();
        return [...pending.keys()];
    }

    function stop() {
        stopTimer();
        pending.clear();
        flushing = false;
        lastRunningAt = 0;
    }

    return {
        markDirty,
        tick,
        stop,
        resumePending,
        pendingSlots: () => [...pending.keys()],
        isFlushing: () => flushing
    };
}

// The watcher fires on individual files deep inside a slot; only the slot
// directory name identifies the bundle that has to be uploaded.
function slotIdFromRelativePath(relativePath) {
    const parts = String(relativePath || '').replace(/\\/g, '/').split('/').filter(Boolean);
    if (!parts.length) return null;
    // Ryujinx's own rotation folders are not part of a committed save.
    if (parts.some(part => part.startsWith('.'))) return null;
    const slotId = parts[0].toUpperCase();
    return /^[0-9A-F]{16}$/.test(slotId) ? slotId : null;
}

module.exports = {
    createSwitchAutoSync,
    slotIdFromRelativePath,
    DEFAULT_POLL_INTERVAL_MS,
    DEFAULT_SETTLE_MS
};
