const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
    findCanonicalFile,
    materializeLegacyBackslashFiles,
    normalizeSaveRelativePath,
    resolveContainedSavePath,
    scanCanonicalFiles
} = require('./save-paths');

function fixture(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'romstore-save-paths-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return root;
}

test('save paths canonicalize Windows separators and reject traversal', () => {
    assert.equal(normalizeSaveRelativePath('ryujinx\\saves\\0000000000000002\\0\\save.bin'), 'ryujinx/saves/0000000000000002/0/save.bin');
    assert.equal(normalizeSaveRelativePath('../outside.bin'), null);
    assert.equal(normalizeSaveRelativePath('ryujinx\\..\\outside.bin'), null);
    assert.equal(normalizeSaveRelativePath('/absolute.bin'), null);
    assert.equal(normalizeSaveRelativePath('C:\\absolute.bin'), null);
    assert.equal(normalizeSaveRelativePath('bad\0name'), null);
    assert.equal(resolveContainedSavePath('/tmp/saves', '../saves-evil/file'), null);
});

test('canonical scans deduplicate legacy flat paths and prefer nested files', t => {
    const root = fixture(t);
    const relPath = 'ryujinx/saves/0000000000000002/0/save.bin';
    const nested = path.join(root, ...relPath.split('/'));
    fs.mkdirSync(path.dirname(nested), { recursive: true });
    fs.writeFileSync(nested, 'nested-current');
    fs.writeFileSync(path.join(root, relPath.replace(/\//g, '\\')), 'legacy-old');

    const results = scanCanonicalFiles(root);
    assert.equal(results.length, 1);
    assert.equal(results[0].relPath, relPath);
    assert.equal(results[0].physicalPath, nested);
    assert.equal(fs.readFileSync(findCanonicalFile(root, relPath), 'utf8'), 'nested-current');
});

test('legacy-only saves are copied to canonical paths without deleting the source', t => {
    const root = fixture(t);
    const relPath = 'ryujinx/saves/0000000000000002/0/save.bin';
    const legacy = path.join(root, relPath.replace(/\//g, '\\'));
    fs.writeFileSync(legacy, 'recover-me');

    const report = materializeLegacyBackslashFiles(root);
    const canonical = path.join(root, ...relPath.split('/'));
    assert.equal(report.copied.length, 1);
    assert.equal(fs.readFileSync(canonical, 'utf8'), 'recover-me');
    assert.equal(fs.readFileSync(legacy, 'utf8'), 'recover-me');
});

test('save resolution and scanning reject symlinks that escape the storage root', t => {
    const root = fixture(t);
    const outside = fixture(t);
    fs.writeFileSync(path.join(outside, 'secret.bin'), 'outside');
    fs.symlinkSync(outside, path.join(root, 'link'));

    assert.equal(resolveContainedSavePath(root, 'link/secret.bin'), null);
    assert.equal(findCanonicalFile(root, 'link/secret.bin'), null);
    assert.deepEqual(scanCanonicalFiles(root), []);
});
