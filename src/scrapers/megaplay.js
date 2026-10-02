const { fetchText, fetchJSON } = require('../utils/http');
const { decryptMegaplayEnc } = require('../utils/crypto');
const { megaplayStreamCache, stats } = require('../utils/cache');

const cidRegex = /cid\s*:\s*['"]([^'"]+)['"]/;
const ciduRegex = /cidu\s*:\s*['"]([^'"]+)['"]/;
const dataIdRegex = /data-id\s*=\s*["']([^"']+)["']/;

function normalizeMegaplayPath(rawPath) {
  let clean = rawPath.replace(/^\/+/, '');
  clean = clean.replace(/^(embed\/megaplay\/|embed\/|stream\/)/, '');
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
  const normPath = normalizeMegaplayPath(targetPath);
  if (megaplayStreamCache.has(normPath)) {
    stats.megaplayHits++;
    return megaplayStreamCache.get(normPath);
  }
  stats.megaplayMisses++;

  const upstreamURL = `https://megaplay.buzz/stream/${normPath}`;
  const htmlRes = await fetchText(upstreamURL, {
    headers: {
      referer: 'https://anikoto.cz/',
      'sec-fetch-dest': 'iframe',
      'sec-fetch-mode': 'navigate'
    }
  });

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

  // PARALLEL: Race getSourcesNew and getSources simultaneously
  const newApiURL = `https://megaplay.buzz/stream/getSourcesNew?id=${encodeURIComponent(dataId)}&cid=${encodeURIComponent(cid)}&cidu=${encodeURIComponent(cidu)}`;
  const legacyApiURL = `https://megaplay.buzz/stream/getSources?id=${encodeURIComponent(dataId)}&cid=${encodeURIComponent(cid)}&cidu=${encodeURIComponent(cidu)}`;

  const headers = {
    referer: 'https://megaplay.buzz/',
    'x-requested-with': 'XMLHttpRequest'
  };

  const fetchSources = async (url) => {
    try {
      const res = await fetchJSON(url, { headers });
      if (res.statusCode === 200 && res.data) {
        return parseMegaplaySourcesResponse(res.data);
      }
    } catch {}
    return null;
  };

  const [resNew, resLegacy] = await Promise.all([
    fetchSources(newApiURL),
    fetchSources(legacyApiURL)
  ]);

  const result = resNew || resLegacy;
  if (!result || !result.streamFile) {
    throw new Error('Both MegaPlay getSourcesNew and getSources failed');
  }

  megaplayStreamCache.set(normPath, result);
  return result;
}

async function extractMegaplayHLSWithFallback(originalPath) {
  try {
    return await extractMegaplayHLS(originalPath);
  } catch (err) {
    // If language was dub or sub, try fallback language
    const parts = originalPath.split('/');
    if (parts.length >= 3) {
      const currentLang = parts[parts.length - 1];
      const fallbackLang = currentLang === 'dub' ? 'sub' : 'dub';
      const fallbackPath = [...parts.slice(0, -1), fallbackLang].join('/');
      return await extractMegaplayHLS(fallbackPath);
    }
    throw err;
  }
}

module.exports = {
  normalizeMegaplayPath,
  extractMegaplayHLS,
  extractMegaplayHLSWithFallback
};
