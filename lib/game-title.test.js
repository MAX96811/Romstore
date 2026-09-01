const test = require('node:test');
const assert = require('node:assert');

const {
    cleanSearchQuery,
    matchesPlatform,
    normalizeTitle,
    pickConfidentMatch
} = require('./game-title');

test('the extension and dump tags are stripped from the query', () => {
    assert.strictEqual(cleanSearchQuery('Metroid Dread.xci'), 'Metroid Dread');
    assert.strictEqual(
        cleanSearchQuery('Bayonetta 3 (World) (En,Ja,Fr,De,Es,It,Zh-Hant,Zh-Hans,Ko,Ru).xci'),
        'Bayonetta 3'
    );
    assert.strictEqual(
        cleanSearchQuery('The Legend of Zelda Tears of the Kingdom [0100F2C0115B6000][v0].nsp'),
        'The Legend of Zelda Tears of the Kingdom'
    );
    assert.strictEqual(
        cleanSearchQuery('Mario vs. Donkey Kong v1.0.0 [0100B99019412000][v0][APP].nsp'),
        'Mario vs. Donkey Kong'
    );
});

test('a No-Intro set index no longer defeats the search', () => {
    // The leading number is why every .nds in the library came back empty.
    assert.strictEqual(
        cleanSearchQuery('0573 - Mario Vs Donkey Kong 2 - March of the Minis (U)(WRG).nds'),
        'Mario Vs Donkey Kong 2 - March of the Minis'
    );
    assert.strictEqual(cleanSearchQuery('3538 - Grand Theft Auto - Chinatown Wars (EU)(M5)(XenoPhobia).nds'), 'Grand Theft Auto - Chinatown Wars');
});

test('a trailing article is moved back to the front', () => {
    assert.strictEqual(
        cleanSearchQuery('Legend of Zelda, The - Spirit Tracks (USA) (En,Fr,Es) (Rev 1).nds'),
        'The Legend of Zelda - Spirit Tracks'
    );
});

test('normalization ignores punctuation, case and accents', () => {
    assert.strictEqual(normalizeTitle('Mario vs. Donkey Kong'), normalizeTitle('Mario vs Donkey Kong'));
    assert.strictEqual(normalizeTitle('The Legend of Zelda: Spirit Tracks'), normalizeTitle('The Legend of Zelda - Spirit Tracks'));
    assert.strictEqual(normalizeTitle('Pokémon Snap'), 'pokemon snap');
    assert.strictEqual(normalizeTitle('Ratchet & Clank'), 'ratchet and clank');
});

test('an exact title match is applied unattended', () => {
    const results = [
        { id: 1, name: 'Metroid Dread', platforms: [{ name: 'Nintendo Switch' }] },
        { id: 2, name: 'Metroid Dread Randomizer', platforms: [{ name: 'Nintendo Switch' }] }
    ];
    assert.strictEqual(pickConfidentMatch('Metroid Dread', results, 'switch').id, 1);
});

test('a near miss is left for review rather than guessed at', () => {
    // IGDB puts mods and fan projects alongside the real game; none of these is
    // the requested title, so applying any of them would be wrong.
    const results = [
        { id: 1, name: 'Super Mario Odyssey F.L.U.D.D.', platforms: [{ name: 'Nintendo Switch' }] },
        { id: 2, name: 'Super Mario Odyssey 64', platforms: [{ name: 'Nintendo 64' }] }
    ];
    assert.strictEqual(pickConfidentMatch('Super Mario Odyssey', results, 'switch'), null);
});

test('DLC never inherits the base game artwork', () => {
    // Stripping `[DLC Creeper]` with the other bracketed tags would collapse the
    // query onto the base game, which IGDB returns verbatim and the exact-match
    // rule would then happily apply to the pack. Keeping the label prevents it.
    const query = cleanSearchQuery('Super Smash Bros Ultimate [DLC Creeper] [01006A800016F03D][v0].nsp');
    const results = [{ id: 1, name: 'Super Smash Bros. Ultimate', platforms: [{ name: 'Nintendo Switch' }] }];
    assert.strictEqual(query, 'Super Smash Bros Ultimate Creeper');
    assert.strictEqual(pickConfidentMatch(query, results, 'switch'), null);
});

test('ties are broken by platform, then by original release', () => {
    const results = [
        { id: 1, name: 'Donkey Kong Country Returns', first_release_date: 400, coverUrl: 'a.jpg', platforms: [{ name: 'Nintendo 3DS' }] },
        { id: 2, name: 'Donkey Kong Country Returns', first_release_date: 200, coverUrl: 'b.jpg', platforms: [{ name: 'Wii' }] },
        { id: 3, name: 'Donkey Kong Country Returns', first_release_date: 100, coverUrl: 'c.jpg', platforms: [{ name: 'Wii' }] }
    ];
    assert.strictEqual(pickConfidentMatch('Donkey Kong Country Returns', results, 'wii').id, 3);
});

test('an empty or unmatched result set yields no match', () => {
    assert.strictEqual(pickConfidentMatch('Anything', [], 'switch'), null);
    assert.strictEqual(pickConfidentMatch('', [{ name: 'Anything' }], 'switch'), null);
});

test('platform matching maps folder names to IGDB names', () => {
    assert.strictEqual(matchesPlatform({ platforms: [{ name: 'Nintendo Switch' }] }, 'switch'), true);
    assert.strictEqual(matchesPlatform({ platforms: [{ name: 'Nintendo DS' }] }, 'nds'), true);
    assert.strictEqual(matchesPlatform({ platforms: [{ name: 'Wii' }] }, 'switch'), false);
    assert.strictEqual(matchesPlatform({ platforms: [{ name: 'Wii' }] }, 'unknown-system'), false);
});
