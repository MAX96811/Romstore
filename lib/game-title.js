// Turning a ROM filename into something IGDB can actually find, and deciding
// when a search result is trustworthy enough to apply without asking.
//
// Dump filenames carry a lot of freight the search index has never seen --
// No-Intro index numbers, region and language tags, Switch Title IDs, version
// and content markers. Sending the raw name means either no results at all
// (`0573 - Mario Vs Donkey Kong 2 ... (U)(WRG)`) or the wrong ones.

// IGDB platform names, keyed by the EmuDeck folder they live in. Used only to
// break ties between results that are otherwise equally good matches.
const PLATFORM_NAMES = {
    switch: ['Nintendo Switch'],
    nds: ['Nintendo DS'],
    '3ds': ['Nintendo 3DS'],
    wii: ['Wii'],
    wiiu: ['Wii U'],
    gc: ['Nintendo GameCube'],
    gamecube: ['Nintendo GameCube'],
    n64: ['Nintendo 64'],
    snes: ['Super Nintendo Entertainment System', 'Super Famicom'],
    nes: ['Nintendo Entertainment System', 'Family Computer'],
    gba: ['Game Boy Advance'],
    gbc: ['Game Boy Color'],
    gb: ['Game Boy'],
    genesis: ['Sega Mega Drive/Genesis'],
    megadrive: ['Sega Mega Drive/Genesis'],
    dreamcast: ['Dreamcast'],
    saturn: ['Sega Saturn'],
    psx: ['PlayStation'],
    ps1: ['PlayStation'],
    ps2: ['PlayStation 2'],
    ps3: ['PlayStation 3'],
    psp: ['PlayStation Portable'],
    psvita: ['PlayStation Vita'],
    xbox: ['Xbox']
};

function stripExtension(name) {
    return String(name || '').replace(/\.[A-Za-z0-9]{1,5}$/, '');
}

// `Legend of Zelda, The - Spirit Tracks` -> `The Legend of Zelda - Spirit Tracks`.
// No-Intro moves the leading article to the end of the first title segment;
// IGDB keeps it up front, so an otherwise exact match would never line up.
function restoreLeadingArticle(title) {
    return title.replace(/^([^,]+?), (The|A|An|Les|La|Le|Der|Die|Das)\b/i, (match, rest, article) => `${article} ${rest}`);
}

function cleanSearchQuery(fileName) {
    let query = stripExtension(fileName);

    // The DLC label is the one bracketed tag worth keeping. Stripping it with
    // the rest collapses `Smash Ultimate [DLC Creeper]` onto the base game,
    // which then matches exactly and hands the pack the base game's box art.
    const dlcLabel = (query.match(/[\[\(]\s*dlc\b[\s:_-]*([^\]\)]*)[\]\)]/i) || [])[1] || '';

    query = query.replace(/_/g, ' ');
    // Region, language, revision, Title ID, version and content tags all live
    // in brackets or parentheses.
    query = query.replace(/\s*[\(\[\{][^\)\]\}]*[\)\]\}]/g, ' ');
    // No-Intro/GoodTools set index: `0573 - Title`, `1234. Title`.
    query = query.replace(/^\s*\d{1,5}\s*[-.–]\s+/, '');
    // Trailing dump version, e.g. `Mario vs. Donkey Kong v1.0.0`.
    query = query.replace(/\s+v\d+(?:\.\d+)*\s*$/i, '');
    query = query.replace(/\s+/g, ' ').trim();
    // A stripped tag can leave a dangling separator behind.
    query = query.replace(/[\s\-–:]+$/, '').trim();

    query = restoreLeadingArticle(query);
    if (dlcLabel.trim()) query = `${query} ${dlcLabel.trim()}`.replace(/\s+/g, ' ').trim();

    return query;
}

// Comparison form: case, accents, punctuation and separator noise removed, so
// `Mario vs. Donkey Kong` and `Mario vs Donkey Kong` compare equal.
function normalizeTitle(title) {
    return String(title || '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase()
        .replace(/&/g, ' and ')
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
}

function resultPlatformNames(result) {
    if (!result || !Array.isArray(result.platforms)) return [];
    return result.platforms.map(platform => (platform && platform.name) || '').filter(Boolean);
}

function matchesPlatform(result, system) {
    const expected = PLATFORM_NAMES[String(system || '').toLowerCase()];
    if (!expected) return false;
    const names = resultPlatformNames(result);
    return names.some(name => expected.includes(name));
}

// A match is only applied unattended when the cleaned filename and the result
// title are the same string once normalized. Anything looser (prefixes,
// substrings, fuzzy distance) is how a DLC pack ends up wearing the base
// game's box art, so those cases go to the review queue instead.
function pickConfidentMatch(query, results, system) {
    if (!Array.isArray(results) || results.length === 0) return null;

    const target = normalizeTitle(query);
    if (!target) return null;

    const exact = results.filter(result => normalizeTitle(result && result.name) === target);
    if (exact.length === 0) return null;
    if (exact.length === 1) return exact[0];

    const onPlatform = exact.filter(result => matchesPlatform(result, system));
    const pool = onPlatform.length ? onPlatform : exact;

    // Same title on the same platform more than once means re-releases or
    // regional entries: the earliest one with art is the original.
    const withCover = pool.filter(result => result && result.coverUrl);
    const ranked = (withCover.length ? withCover : pool)
        .slice()
        .sort((a, b) => (a.first_release_date || Infinity) - (b.first_release_date || Infinity));

    return ranked[0] || null;
}

module.exports = {
    PLATFORM_NAMES,
    cleanSearchQuery,
    matchesPlatform,
    normalizeTitle,
    pickConfidentMatch,
    restoreLeadingArticle
};
