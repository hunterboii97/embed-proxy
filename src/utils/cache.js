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

// 6. Segment Cache (20 min TTL, 128MB total) — content-agnostic: works for
// disguised .jpg/.html TS chunks from kira as well as plain .ts from zoko.
// Entries are { body: Buffer, contentType: string }.
// Reduced from 384MB to 128MB to prevent GC pressure and memory buildup over time.
// 128MB ≈ 4-5 min of a 5.3 Mbps 1080p stream - sufficient for smooth playback.
const tsSegmentCache = new LRUCache({
  maxSize: 128 * 1024 * 1024, // 128 MB (reduced from 384MB)
  ttl: 20 * 60 * 1000, // 20 min (reduced from 45 min)
  sizeCalculation: (entry) => entry.body.length,
  updateAgeOnGet: true
});

// 6b. Abyss (haiku) 5MB chunk cache — 96MB, 20min TTL
// Reduced from 256MB to 96MB to prevent memory buildup and GC pressure.
const abyssChunkCache = new LRUCache({
  maxSize: 96 * 1024 * 1024, // 96 MB (reduced from 256MB)
  ttl: 20 * 60 * 1000, // 20 min (reduced from 45 min)
  sizeCalculation: (buf) => buf.length,
  updateAgeOnGet: true
});

// 6c. Segment → Playlist Index (upstream segment URL → { playlistKey, idx })
// Used to look ahead in the playlist and prefetch upcoming segments.
const segmentIndex = new LRUCache({
  max: 50000, // Reduced from 100000 to prevent memory buildup
  ttl: 1 * 60 * 60 * 1000, // Reduced from 2 hours to 1 hour
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

// Periodic cleanup function to prevent memory buildup
// Clears stale entries and runs every 5 minutes
let cleanupInterval = null;

function startPeriodicCleanup() {
  if (cleanupInterval) return; // Already running

  cleanupInterval = setInterval(() => {
    // LRU caches auto-evict based on TTL, but we can force cleanup
    // This helps GC by releasing references to old entries
    const now = Date.now();

    // Force purge expired entries in all caches
    tsSegmentCache.purgeStale();
    abyssChunkCache.purgeStale();
    segmentIndex.purgeStale();
    m3u8PlaylistCache.purgeStale();
    zokoStreamCache.purgeStale();
    animeSaltStreamCache.purgeStale();
    animeSaltAudioLinksCache.purgeStale();
    animeSaltSlugCache.purgeStale();
    megaplayStreamCache.purgeStale();
    megaplayGapCache.purgeStale();
    animeTitleCache.purgeStale();
    malIdCache.purgeStale();
  }, 5 * 60 * 1000); // Every 5 minutes
}

function stopPeriodicCleanup() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
}

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
  startPeriodicCleanup,
  stopPeriodicCleanup
};
