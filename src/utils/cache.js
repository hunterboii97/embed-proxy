const { LRUCache } = require('lru-cache');

const stats = {
  megaplayHits: 0,
  megaplayMisses: 0,
  zokoHits: 0,
  zokoMisses: 0,
  animeSaltHits: 0,
  animeSaltMisses: 0
};

// 1. M3U8 Master & Variant Playlist Cache (2 Hours TTL)
const m3u8PlaylistCache = new LRUCache({
  max: 10000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 2. Zoko Stream Cache (3 Hours TTL)
const zokoStreamCache = new LRUCache({
  max: 5000,
  ttl: 3 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 3. AnimeSalt Stream & Audio Links Cache (2 Hours TTL)
const animeSaltStreamCache = new LRUCache({
  max: 5000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const animeSaltAudioLinksCache = new LRUCache({
  max: 5000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const animeSaltSlugCache = new LRUCache({
  max: 5000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 4. MegaPlay Stream Cache (2 Hours TTL)
const megaplayStreamCache = new LRUCache({
  max: 5000,
  ttl: 2 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

// 5. Anime Title & MAL/AniList Mapping Cache (24 Hours TTL)
const animeTitleCache = new LRUCache({
  max: 5000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

const malIdCache = new LRUCache({
  max: 5000,
  ttl: 24 * 60 * 60 * 1000,
  updateAgeOnGet: true
});

module.exports = {
  stats,
  m3u8PlaylistCache,
  zokoStreamCache,
  animeSaltStreamCache,
  animeSaltAudioLinksCache,
  animeSaltSlugCache,
  megaplayStreamCache,
  animeTitleCache,
  malIdCache
};
