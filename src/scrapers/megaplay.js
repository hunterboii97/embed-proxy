const { fetchText, fetchJSON } = require('../utils/http');
const { decryptMegaplayEnc } = require('../utils/crypto');
const { megaplayStreamCache, megaplayGapCache, stats } = require('../utils/cache');
const { resolveMalId } = require('./resolver');
const { singleflight } = require('../utils/singleflight');

const cidRegex = /cid\s*:\s*['"]([^'"]+)['"]/;
const ciduRegex = /cidu\s*:\s*['"]([^'"]+)['"]/;
const dataIdRegex = /data-id\s*=\s*["']([^"']+)["']/;
const aniPathRegex = /^ani\/(\d+)\/(\d+)\/(.+)$/;

function normalizeMegaplayPath(rawPath) {
  let clean = rawPath.replace(/^\/+/, '');
  clean = clean.replace(/^(embed\/kira\/|embed\/megaplay\/|embed\/|stream\/)/, '');
  return clean;
}

function parseMegaplaySourcesResponse(data) {
  let streamFile = '';
  const tracks = (data.tracks || []).map(t => ({
    file: t.file,
    label: t.label || t.name || 'Subtitles',
    kind: t.kind || 'captions',
    default: Boolean(t.default)
  }));

  // 1. Try decrypting enc first if present
  if (data.enc) {
    try {
      const decrypted = decryptMegaplayEnc(data.enc);
      if (decrypted) streamFile = decrypted;
    } catch {}
  }

  // 2. Fallback to plain sources
  if (!streamFile && data.sources) {
    if (typeof data.sources === 'object') {
      if (data.sources.file) {
        streamFile = data.sources.file;
      } else if (Array.isArray(data.sources) && data.sources.length > 0 && data.sources[0].file) {
        streamFile = data.sources[0].file;
      }
    }
  }

  if (!streamFile) {
    throw new Error('No stream file found in MegaPlay response');
  }

  return { streamFile, tracks };
}

async function extractMegaplayHLS(targetPath) {
  const start = Date.now();
  const normPath = normalizeMegaplayPath(targetPath);
  if (megaplayStreamCache.has(normPath)) {
    stats.megaplayHits++;
    console.log(`[TIMING] MegaPlay cache HIT took ${Date.now() - start}ms`);
    return megaplayStreamCache.get(normPath);
  }
  stats.megaplayMisses++;
  console.log(`[TIMING] MegaPlay cache MISS, starting extraction...`);

  const upstreamURL = `https://megaplay.buzz/stream/${normPath}`;
  const htmlStart = Date.now();
  const htmlRes = await fetchText(upstreamURL, {
    headers: {
      referer: 'https://anikoto.cz/',
      'sec-fetch-dest': 'iframe',
      'sec-fetch-mode': 'navigate'
    }
  });
  console.log(`[TIMING] MegaPlay HTML fetch took ${Date.now() - htmlStart}ms`);

  if (htmlRes.statusCode !== 200 || !htmlRes.body) {
    throw new Error(`MegaPlay returned status ${htmlRes.statusCode}`);
  }

  const html = htmlRes.body;
  const cidMatch = html.match(cidRegex);
  const ciduMatch = html.match(ciduRegex);
  const dataIdMatch = html.match(dataIdRegex);

  if (!cidMatch || !ciduMatch || !dataIdMatch) {
    throw new Error('Could not extract player IDs from MegaPlay HTML');
  }

  const cid = cidMatch[1];
  const cidu = ciduMatch[1];
  const dataId = dataIdMatch[1];

  // ONLY use getSourcesNew (legacy API is too slow: 800ms avg)
  const newApiURL = `https://megaplay.buzz/stream/getSourcesNew?id=${encodeURIComponent(dataId)}&cid=${encodeURIComponent(cid)}&cidu=${encodeURIComponent(cidu)}`;

  const headers = {
    referer: 'https://megaplay.buzz/',
    'x-requested-with': 'XMLHttpRequest'
  };

  const apiStart = Date.now();
  const res = await fetchJSON(newApiURL, { headers });
  console.log(`[TIMING] MegaPlay API New took ${Date.now() - apiStart}ms`);

  if (res.statusCode !== 200 || !res.data) {
    throw new Error(`MegaPlay API returned status ${res.statusCode}`);
  }

  const result = parseMegaplaySourcesResponse(res.data);
  if (!result || !result.streamFile) {
    throw new Error('MegaPlay API returned no stream file');
  }

  megaplayStreamCache.set(normPath, result);
  console.log(`[TIMING] MegaPlay total extraction took ${Date.now() - start}ms`);
  return result;
}

async function extractMegaplayHLSAniFirst(path) {
  const normPath = normalizeMegaplayPath(path);
  const match = normPath.match(aniPathRegex);
  if (!match) {
    return extractMegaplayHLS(path);
  }

  const [, aniId, ep, lang] = match;

  // Known AniList-shelf gap: go straight to the mapped MAL path, skipping
  // the dead upstream probe and the resolver round-trip entirely.
  const knownMalId = megaplayGapCache.get(normPath);
  if (knownMalId) {
    try {
      return await extractMegaplayHLS(`mal/${knownMalId}/${ep}/${lang}`);
    } catch {
      megaplayGapCache.delete(normPath);
    }
  }

  // AniList shelf stays primary; the MAL resolve + fetch only happens when
  // AniList actually misses, so healthy paths waste zero upstream work.
  try {
    return await extractMegaplayHLS(path);
  } catch (aniErr) {
    const malId = await resolveMalId(parseInt(aniId, 10));
    if (malId > 0) {
      try {
        const result = await extractMegaplayHLS(`mal/${malId}/${ep}/${lang}`);
        megaplayGapCache.set(normPath, malId);
        return result;
      } catch {}
    }
    throw aniErr;
  }
}

async function extractMegaplayHLSWithFallback(originalPath) {
  const normPath = normalizeMegaplayPath(originalPath);
  return singleflight(`kira|${normPath}`, async () => {
    try {
      return await extractMegaplayHLSAniFirst(normPath);
    } catch (err) {
      // If language was dub or sub, try fallback language
      const parts = normPath.split('/');
      if (parts.length >= 3) {
        const currentLang = parts[parts.length - 1];
        const fallbackLang = currentLang === 'dub' ? 'sub' : 'dub';
        const fallbackPath = [...parts.slice(0, -1), fallbackLang].join('/');
        return await extractMegaplayHLSAniFirst(fallbackPath);
      }
      throw err;
    }
  });
}

module.exports = {
  normalizeMegaplayPath,
  extractMegaplayHLS,
  extractMegaplayHLSWithFallback
};
