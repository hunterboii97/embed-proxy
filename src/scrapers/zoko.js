const { fetchText } = require('../utils/http');
const { deobfuscateZokoPayload } = require('../utils/crypto');
const { zokoStreamCache, stats } = require('../utils/cache');

const zokoPRegex = /window\.__P\s*=\s*"([^"]+)"/;

async function extractZokoHLS(malID, ep = 1, track = 'sub') {
  if (track !== 'dub' && track !== 'sub') track = 'sub';
  if (ep <= 0) ep = 1;
  if (!malID || malID <= 0) {
    throw new Error(`Invalid mal_id: ${malID}`);
  }

  const cacheKey = `${malID}:${ep}:${track}`;
  if (zokoStreamCache.has(cacheKey)) {
    stats.zokoHits++;
    return zokoStreamCache.get(cacheKey);
  }
  stats.zokoMisses++;

  const targetURL = `https://zokoanime.video/stream/mal/${malID}/${ep}/${track}`;
  const res = await fetchText(targetURL, {
    headers: {
      referer: 'https://zokoanime.video/',
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
  });

  if (res.statusCode !== 200 || !res.body) {
    throw new Error(`Zoko upstream returned status: ${res.statusCode}`);
  }

  const m = res.body.match(zokoPRegex);
  if (!m || !m[1]) {
    throw new Error('Zoko __P payload not found in upstream HTML');
  }

  const data = deobfuscateZokoPayload(m[1]);
  if (!data || !data.src) {
    throw new Error('Zoko returned empty stream src');
  }

  const tracks = [];
  if (Array.isArray(data.subtitles)) {
    for (const sub of data.subtitles) {
      if (sub.src) {
        let label = sub.label;
        if (!label) {
          label = (sub.lang || 'SUB').toUpperCase();
        }
        tracks.push({
          file: sub.src,
          label,
          kind: 'captions',
          default: Boolean(sub.default)
        });
      }
    }
  }

  const result = {
    streamFile: data.src,
    tracks,
    skip: data.skip || null
  };

  zokoStreamCache.set(cacheKey, result);
  return result;
}

module.exports = {
  extractZokoHLS
};
