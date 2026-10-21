const { request } = require('undici');
const { LRUCache } = require('lru-cache');
const {
  isPrivateHost,
  anipmLinkGateDir,
  anipmLinkMinGapMs,
  anipmLinkCooldownMs
} = require('../../config');
const { globalAgent, DEFAULT_UA } = require('../utils/http');
const { singleflight } = require('../utils/singleflight');
const { createAnipmLinkGate } = require('../utils/anipm-link-gate');

const ANIPM_ORIGIN = 'https://ani.pm';
const SERIES_PATH = '/api/partner/v1/series';
const DOWNLOAD_PATH = '/api/anime/src/download';
const SERIES_TTL_MS = 6 * 60 * 60 * 1000;
const LINK_MARGIN_MS = 60 * 1000;

const seriesCache = new LRUCache({ max: 2000, ttl: SERIES_TTL_MS, updateAgeOnGet: true });
const linkCache = new LRUCache({ max: 500, ttl: 60 * 60 * 1000 });

const linkGate = createAnipmLinkGate({
  dir: anipmLinkGateDir,
  minGapMs: anipmLinkMinGapMs,
  cooldownMs: anipmLinkCooldownMs
});

class AnipmError extends Error {
  constructor(message, { statusCode = 0, code = '', retryAfter = 0 } = {}) {
    super(message);
    this.name = 'AnipmError';
    this.statusCode = statusCode;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

class AnipmAuthError extends AnipmError {}
class AnipmNotFoundError extends AnipmError {}

function baseHeaders(cookie) {
  return {
    'user-agent': DEFAULT_UA,
    accept: '*/*',
    'accept-language': 'en-US,en;q=0.9',
    origin: ANIPM_ORIGIN,
    referer: `${ANIPM_ORIGIN}/`,
    ...(cookie ? { cookie } : {})
  };
}

async function readJson(res) {
  let text;
  try {
    text = await res.body.text();
  } catch {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function getSeries(anilistId) {
  const key = String(anilistId);
  const cached = seriesCache.get(key);
  if (cached) return cached;

  return singleflight(`anipm-series:${key}`, async () => {
    const hit = seriesCache.get(key);
    if (hit) return hit;

    const res = await request(`${ANIPM_ORIGIN}${SERIES_PATH}/${encodeURIComponent(key)}`, {
      method: 'GET',
      headers: { 'user-agent': DEFAULT_UA, accept: 'application/json' },
      dispatcher: globalAgent,
      signal: AbortSignal.timeout(10000)
    });
    const json = await readJson(res);

    if (res.statusCode === 404) throw new AnipmNotFoundError('Anime not found on ani.pm', { statusCode: 404 });
    if (res.statusCode !== 200 || !json?.data) {
      throw new AnipmError(`series lookup HTTP ${res.statusCode}`, { statusCode: res.statusCode });
    }

    seriesCache.set(key, json.data);
    return json.data;
  });
}

function assertEpisode(series, ep, lang) {
  const list = Array.isArray(series.episodeList) ? series.episodeList : null;
  if (!list || list.length === 0) return;

  const info = list.find((entry) => Number(entry && entry.number) === ep);
  if (!info) throw new AnipmNotFoundError(`Episode ${ep} not found on ani.pm`, { statusCode: 404 });

  const available = info.available;
  if (available && typeof available === 'object' && available[lang] === false) {
    throw new AnipmNotFoundError(`Episode ${ep} has no ${lang} download`, { statusCode: 404 });
  }
}

function pickCandidate(json) {
  const list = Array.isArray(json.candidates) && json.candidates.length ? json.candidates : [json];
  const files = list.filter((c) => c && typeof c.url === 'string' && c.url && (!c.kind || c.kind === 'file'));
  if (files.length === 0) throw new AnipmError('download lookup returned no file candidate');

  return files.reduce((best, current) =>
    (Number(current.bytes) || 0) > (Number(best.bytes) || 0) ? current : best
  );
}

function assertCdnLocation(raw, base, cdnHosts) {
  let url;
  try {
    url = new URL(raw, base);
  } catch {
    throw new AnipmError('invalid CDN redirect');
  }
  if (url.protocol !== 'https:') throw new AnipmError(`refusing non-https CDN: ${url.protocol}`);
  if (isPrivateHost(url.hostname)) throw new AnipmError(`refusing private CDN host: ${url.hostname}`);

  const host = url.hostname.toLowerCase();
  const allowed = (cdnHosts || []).some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
  if (!allowed) throw new AnipmError(`refusing unexpected CDN host: ${host}`);
  return url.toString();
}

async function fetchLink({ series, anilistId, ep, lang, cookie, cdnHosts }) {
  const body = JSON.stringify({
    title: series.title,
    ep,
    year: series.year,
    anilistId: String(anilistId),
    malId: series.malId,
    lang
  });

  try {
    await linkGate.acquire();
  } catch (err) {
    if (err.code === 'ANIPM_GATE_BUSY') {
      throw new AnipmError(err.message, { statusCode: 429, retryAfter: err.retryAfter });
    }
    throw err;
  }

  const res = await request(`${ANIPM_ORIGIN}${DOWNLOAD_PATH}`, {
    method: 'POST',
    headers: { ...baseHeaders(cookie), 'content-type': 'application/json' },
    body,
    dispatcher: globalAgent,
    signal: AbortSignal.timeout(15000)
  });
  const json = await readJson(res);

  if (res.statusCode === 401) {
    throw new AnipmAuthError('ani.pm session expired', { statusCode: 401, code: 'auth-required' });
  }
  if (res.statusCode === 403) {
    if (json && json.code === 'auth-required') {
      throw new AnipmAuthError('ani.pm session expired', { statusCode: 403, code: 'auth-required' });
    }
    throw new AnipmError('ani.pm blocked the request', { statusCode: 403 });
  }
  if (res.statusCode === 429) {
    const retryAfter = parseInt(res.headers['retry-after'] || '0', 10) || 0;
    await linkGate.coolDown(retryAfter > 0 ? retryAfter * 1000 : 0);
    throw new AnipmError('ani.pm rate limit', { statusCode: 429, retryAfter });
  }
  if (res.statusCode === 404) {
    throw new AnipmNotFoundError(json?.error || 'Episode is not available for download', { statusCode: 404, code: json?.code || '' });
  }
  if (res.statusCode !== 200 || !json || !json.url) {
    throw new AnipmError(`download lookup HTTP ${res.statusCode}`);
  }

  const candidate = pickCandidate(json);
  const dlUrl = new URL(candidate.url, ANIPM_ORIGIN).toString();

  const redirect = await request(dlUrl, {
    method: 'GET',
    headers: baseHeaders(cookie),
    dispatcher: globalAgent,
    signal: AbortSignal.timeout(15000)
  });
  const location = redirect.headers.location;
  try { await redirect.body.dump(); } catch {}

  let cdnUrl = dlUrl;
  let needsCookie = true;
  if (redirect.statusCode >= 300 && redirect.statusCode < 400) {
    if (!location) throw new AnipmError(`download redirect HTTP ${redirect.statusCode} without Location`);
    cdnUrl = assertCdnLocation(location, dlUrl, cdnHosts);
    needsCookie = false;
  } else if (redirect.statusCode === 401 || redirect.statusCode === 403) {
    throw new AnipmAuthError('ani.pm download token rejected', { statusCode: redirect.statusCode });
  } else if (redirect.statusCode === 429) {
    await linkGate.coolDown(0);
    throw new AnipmError('ani.pm rate limit', { statusCode: 429 });
  } else if (redirect.statusCode === 404) {
    throw new AnipmNotFoundError('Download link no longer exists', { statusCode: 404 });
  } else if (redirect.statusCode !== 200) {
    throw new AnipmError(`download redirect HTTP ${redirect.statusCode}`, { statusCode: redirect.statusCode });
  }

  const expSeconds = parseInt(new URL(cdnUrl).searchParams.get('exp') || '0', 10);
  let graceUntil = Number(json.graceUntil) || 0;
  if (graceUntil > 0 && graceUntil < 1e12) graceUntil *= 1000;
  const expiresAt = expSeconds > 0 ? expSeconds * 1000 : (graceUntil || Date.now() + 10 * 60 * 1000);

  return {
    title: String(series.title || 'Anime'),
    url: cdnUrl,
    filename: String(candidate.filename || json.filename || ''),
    bytes: Number(candidate.bytes ?? json.bytes) || 0,
    quality: candidate.quality ?? json.quality ?? null,
    needsCookie,
    expiresAt
  };
}

async function resolveAnipmDownload({ anilistId, ep, lang, cookie, cdnHosts }) {
  const key = `${anilistId}:${ep}:${lang}`;
  const cached = linkCache.get(key);
  if (cached && cached.expiresAt - Date.now() > LINK_MARGIN_MS) return cached;

  const series = await getSeries(anilistId);
  assertEpisode(series, ep, lang);

  const resolved = await singleflight(`anipm-link:${key}`, async () => {
    const hit = linkCache.get(key);
    if (hit && hit.expiresAt - Date.now() > LINK_MARGIN_MS) return hit;
    return fetchLink({ series, anilistId, ep, lang, cookie, cdnHosts });
  });

  const ttl = resolved.expiresAt - Date.now() - LINK_MARGIN_MS;
  if (ttl > 0) linkCache.set(key, resolved, { ttl });
  return resolved;
}

module.exports = {
  AnipmError,
  AnipmAuthError,
  AnipmNotFoundError,
  getSeries,
  resolveAnipmDownload
};
