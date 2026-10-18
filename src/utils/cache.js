const { LRUCache } = require('lru-cache');

const stats = {
  megaplayHits: 0,
  megaplayMisses: 0,
  zokoHits: 0,
  zokoMisses: 0,
  animeSaltHits: 0,
  animeSaltMisses: 0,
  segmentHits: 0,
  segmentUpstream: 0,
  segmentPrefetch: 0,
  prefetchInflight: 0,
  clientInflight: 0
};

// 1. M3U8 Master & Variant Playlist Cache (6 Hours TTL, 25K entries)
const m3u8PlaylistCache = new LRUCache({
  max: 25000,
  ttl: 6 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 6. Segment Cache (45 min TTL, 384MB total) — content-agnostic: works for
// disguised .jpg/.html TS chunks from kira as well as plain .ts from zoko.
// Entries are { body: Buffer, contentType: string }.
// Kept deliberately small: multi-GB buffer piles put Node under constant GC
// and OS memory pressure, which shows up as stream stutter on the client.
// 384MB ≈ 10+ min of a 5.3 Mbps 1080p stream or a couple of full episodes.
const tsSegmentCache = new LRUCache({
  maxSize: 384 * 1024 * 1024, // 384 MB
  ttl: 45 * 60 * 1000,
  sizeCalculation: (entry) => entry.body.length,
  updateAgeOnGet: true
});

// 6b. Abyss (haiku) 5MB chunk cache — 256MB, 45min TTL
const abyssChunkCache = new LRUCache({
  maxSize: 256 * 1024 * 1024, // 256 MB
  ttl: 45 * 60 * 1000,
  sizeCalculation: (buf) => buf.length,
  updateAgeOnGet: true
});

// 6c. Segment → Playlist Index (upstream segment URL → { playlistKey, idx })
// Used to look ahead in the playlist and prefetch upcoming segments.
const segmentIndex = new LRUCache({
  max: 100000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 2. Zoko Stream Cache (4 Hours TTL, 40K entries)
const zokoStreamCache = new LRUCache({
  max: 40000,
  ttl: 4 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 3. AnimeSalt Stream & Audio Links Cache (4 Hours TTL, 40K entries)
const animeSaltStreamCache = new LRUCache({
  max: 40000,
  ttl: 4 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const animeSaltAudioLinksCache = new LRUCache({
  max: 20000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const animeSaltSlugCache = new LRUCache({
  max: 10000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 4. MegaPlay Stream Cache (4 Hours TTL, 40K entries)
const megaplayStreamCache = new LRUCache({
  max: 40000,
  ttl: 4 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 4b. MegaPlay AniList-shelf Gap Memo (2 Hours TTL)
// When ani/{id}/{ep}/{lang} misses upstream, remembers the working mal/{idMal}
// route so repeat requests skip the dead probe + resolver round-trip entirely.
const megaplayGapCache = new LRUCache({
  max: 5000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 4c. MegaPlay language-gap memo (1 Hour TTL)
// Some /:lang shelves (e.g. hin) have no player page and cost a dead probe on
// every request. Remember the working fallback language for that path.
const megaplayLangGapCache = new LRUCache({
  max: 20000,
  ttl: 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 5. Anime Title & MAL/AniList Mapping Cache (24 Hours TTL)
const animeTitleCache = new LRUCache({
  max: 50000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const malIdCache = new LRUCache({
  max: 50000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 7. Resolve failure memo: a dead source (or a 4 s timeout) is remembered
// briefly so repeated viewers do not each re-run the full upstream probe.
const resolveErrorTtlMs = parseInt(process.env.EMBED_RESOLVE_ERROR_TTL_MS || '30000', 10) || 30000;
const resolveErrorCache = new LRUCache({
  max: 20000,
  ttl: resolveErrorTtlMs
});

module.exports = {
  stats,
  m3u8PlaylistCache,
  tsSegmentCache,
  abyssChunkCache,
  segmentIndex,
  zokoStreamCache,
  animeSaltStreamCache,
  animeSaltAudioLinksCache,
  animeSaltSlugCache,
  megaplayStreamCache,
  animeTitleCache,
  malIdCache,
  megaplayGapCache,
  megaplayLangGapCache,
  resolveErrorCache
};
