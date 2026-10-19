const {
  isEmbedAllowed, buildFrameAncestorsCSP, getClientIP, embedRateLimitPerMin,
  freeEmbedMode, adDirectUrls, adInterstitialUrl, adminTelemetryEnabled,
  isBlockedEmbedSource, getEmbedTier,
  embedResolveTimeoutMs, embedHedgeStaggerMs, cdnRules
} = require('../../config');
const { request } = require('undici');
const { rateLimited } = require('../utils/ratelimit');
const { encryptToken, signTierToken, verifyTierToken } = require('../utils/crypto');
const { renderPlayerShell, renderCustomProxy404 } = require('../views/player');
const { extractZokoHLS } = require('../scrapers/zoko');
const { resolveAnimeSaltSlug, extractAnimeSaltStream } = require('../scrapers/animesalt');
const { extractMegaplayHLSWithFallback, normalizeMegaplayPath } = require('../scrapers/megaplay');
const { resolveMalId } = require('../scrapers/resolver');
const { resolveErrorCache, zokoStreamCache, megaplayStreamCache } = require('../utils/cache');
const { globalAgent, DEFAULT_UA } = require('../utils/http');

// Providers can resolve to a CDN host that is currently blackholing. The
// resolve itself "succeeds", so without a probe the player would sit through
// its manifest retries (tens of seconds) before the backup source is tried.
const PLAYLIST_PROBE_MS = 2200;
const deadPayloads = new WeakSet();

function markSourceDead(payload) {
  deadPayloads.add(payload);
  return payload;
}

function playlistProbeHeaders(targetURL, ref) {
  const parsed = new URL(targetURL);
  const host = parsed.hostname.toLowerCase();
  let referer = ref || '';
  let origin = '';
  let secSite = 'cross-site';
  for (const rule of cdnRules) {
    if (rule.matches(host)) {
      if (!referer) referer = rule.referer;
      origin = rule.origin;
      secSite = rule.secSite;
      break;
    }
  }
  if (!referer) referer = `${parsed.protocol}//${parsed.host}/`;
  if (!origin) origin = `${parsed.protocol}//${parsed.host}`;
  return {
    'user-agent': DEFAULT_UA,
    referer,
    origin,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': secSite
  };
}

// Only playlists are probed: a segment fetch would download media. A healthy
// CDN answers the master playlist in ~100 ms; the budget stays well inside the
// resolve deadline so a dead host cannot delay the hedge.
async function playlistReachable(targetURL, ref, signal) {
  if (!/\.m3u8(?:$|\?)/i.test(targetURL.split('#')[0])) return true;
  const timeout = AbortSignal.timeout(PLAYLIST_PROBE_MS);
  const probeSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  try {
    const res = await request(targetURL, {
      method: 'GET',
      headers: playlistProbeHeaders(targetURL, ref),
      dispatcher: globalAgent,
      signal: probeSignal
    });
    try { await res.body.dump(); } catch { /* aborted mid-body */ }
    return res.statusCode < 400;
  } catch {
    return false;
  }
}

function isResolveRequest(req) {
  const flag = req.query && req.query.resolve;
  return flag === '1' || flag === 'true';
}

function embedCSP(req) {
  return buildFrameAncestorsCSP(req.headers['host'] || '');
}

// Shell-first: the HTML carries no stream, token, tier or ad data, so it is
// identical for every embedding site and safe to cache. Everything viewer-
// specific is decided by the resolve call below.
//
// Partner tier is minted here from the embedding site's actual Referer/Origin
// (or reused from a signed ?tier token on failover navigations) and travels to
// resolve as a signed token — the client can no longer claim partner with a
// forged `ref`. Partner shells are viewer-specific and never shared-cached.
function sendShell(req, reply) {
  const qIndex = req.url.indexOf('?');
  const path = qIndex < 0 ? req.url : req.url.slice(0, qIndex);
  const params = new URLSearchParams(qIndex < 0 ? '' : req.url.slice(qIndex + 1));
  params.delete('resolve');
  params.set('resolve', '1');

  let tierToken = '';
  if (freeEmbedMode) {
    const tier = verifyTierToken(req.query && req.query.tier) || getEmbedTier(req);
    if (tier === 'partner') {
      tierToken = signTierToken('partner');
      params.set('tier', tierToken);
    }
  }
  if (!tierToken) params.delete('tier');

  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Content-Security-Policy', embedCSP(req));
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header(
    'Cache-Control',
    tierToken ? 'private, no-store' : 'public, max-age=60, stale-while-revalidate=300'
  );
  return reply.send(renderPlayerShell(`${path}?${params.toString()}`));
}

function sendHtmlError(req, reply, status, message) {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Content-Security-Policy', embedCSP(req));
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Cache-Control', 'no-store');
  return reply.code(status).send(renderCustomProxy404(req.url, message));
}

// The resolve fetch is same-origin, so its Referer is our own origin and its
// `ref` is client-supplied. Partner status therefore comes only from the
// signed token minted at the shell request, never from `ref`.
function resolveTier(req) {
  if (!freeEmbedMode) return 'partner';
  return verifyTierToken(req.query && req.query.tier) === 'partner' ? 'partner' : 'free';
}

function embedAds(tier) {
  if (!freeEmbedMode || tier === 'partner') return null;
  const ads = {};
  if (adDirectUrls.length) ads.redirects = adDirectUrls;
  if (adInterstitialUrl) ads.interstitial = adInterstitialUrl;
  return Object.keys(ads).length ? ads : null;
}

// Self-reported viewer data is opt-in. Content/episode come from the route,
// never from upstream HTML, so nothing extra is fetched on the embed path.
function telemetryMeta(provider, content, episode, tier) {
  if (!adminTelemetryEnabled) return null;
  return {
    enabled: true,
    provider,
    tier: tier === 'partner' ? 'partner' : 'free',
    content: String(content || '').slice(0, 64),
    episode: String(episode || '').slice(0, 64)
  };
}

function proxyStreamToken(url, ref, clientIP) {
  return encryptToken({
    url,
    ref,
    exp: Math.floor(Date.now() / 1000) + 86400,
    ip: clientIP
  });
}

function proxiedPlaylist(url, ref, clientIP) {
  return `/p/${proxyStreamToken(url, ref, clientIP)}/master.m3u8`;
}

function proxyTracks(tracks, referer = '', clientIP = '') {
  return (tracks || []).map(t => {
    if (!t.file) return t;
    if (t.file.startsWith('/p/')) return t;
    const token = proxyStreamToken(t.file, referer, clientIP);
    return {
      ...t,
      file: `/p/${token}/subtitles.vtt`
    };
  });
}

function payload({ tier, src, tracks, fallbacks = [], telemetry = null, intro = null, outro = null }) {
  return {
    src,
    tracks: tracks || [],
    ads: embedAds(tier),
    fallbacks,
    tier,
    telemetry,
    intro: intro || null,
    outro: outro || null
  };
}

/* ------------------------------------------------------------------------- *
 * Resolve: one hard budget for the whole call, fallbacks hedged in after a
 * stagger. The first provider that produces a stream wins and every loser is
 * aborted, so a hung upstream can never keep a request (or a socket) open.
 * ------------------------------------------------------------------------- */

function resolveFailure(message, statusCode) {
  const err = new Error(message);
  err.statusCode = statusCode || 404;
  return err;
}

function raceProviders(candidates, signal) {
  return new Promise((resolve, reject) => {
    const controllers = [];
    const timers = [];
    let next = 0;
    let active = 0;
    let settled = false;
    let firstResult = null;
    const errors = [];

    const cleanup = () => {
      for (const t of timers) clearTimeout(t);
      for (const c of controllers) {
        try { c.abort(); } catch { /* already settled */ }
      }
      if (signal) signal.removeEventListener('abort', onAbort);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const fail = (err) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };
    // A dead source still beats no source: the player's own failover chain can
    // use it as a last resort, exactly as it did before resolve-time probing.
    const finish = () => (firstResult ? succeed(firstResult) : fail(resolveFailure(errors.join(' | '), 404)));
    const onAbort = () => (firstResult ? succeed(firstResult) : fail(resolveFailure('Stream resolve aborted', 504)));

    if (signal) {
      if (signal.aborted) return onAbort();
      signal.addEventListener('abort', onAbort, { once: true });
    }

    const launch = () => {
      if (settled || next >= candidates.length) return;
      const candidate = candidates[next++];
      const controller = new AbortController();
      controllers.push(controller);
      active++;

      Promise.resolve()
        .then(() => candidate.run(controller.signal))
        .then((value) => {
          if (settled) return;
          if (!value || !deadPayloads.has(value)) return succeed(value);
          if (!firstResult) firstResult = value;
          errors.push(`${candidate.name}: source unreachable`);
          active--;
          if (next < candidates.length) launch();
          else if (active === 0) finish();
        }, (err) => {
          errors.push(`${candidate.name}: ${err?.message || err}`);
          active--;
          if (settled) return;
          if (next < candidates.length) launch();
          else if (active === 0) finish();
        });

      if (next < candidates.length) {
        timers.push(setTimeout(launch, Math.max(0, embedHedgeStaggerMs)));
      }
    };

    launch();
  });
}

async function resolveRoute(req, reply, key, run) {
  reply.header('Content-Type', 'application/json; charset=utf-8');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Cache-Control', 'no-store');

  if (isBlockedEmbedSource(String(req.query.ref || ''))) {
    return reply.code(403).send({ error: 'Embedding domain is blocked' });
  }

  const remembered = resolveErrorCache.get(key);
  if (remembered) {
    return reply.code(remembered.statusCode || 404).send({ error: remembered.message });
  }

  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), embedResolveTimeoutMs);
  try {
    const body = await run(controller.signal);
    resolveErrorCache.delete(key);
    // Hand the player a fresh token so a failover navigation keeps partner
    // status without trusting document.referrer.
    if (freeEmbedMode && body && body.tier === 'partner') {
      body.tierToken = signTierToken('partner');
    }
    return reply.send(body);
  } catch (err) {
    let message = err?.message || 'Stream resolve failed';
    let statusCode = err?.statusCode || 404;
    if (statusCode === 504 || (controller.signal.aborted && !err?.statusCode)) {
      statusCode = 504;
      message = `Stream resolve timed out after ${embedResolveTimeoutMs} ms`;
    }
    // A timeout is often transient, so it is remembered only briefly; a hard
    // provider error keeps the full negative TTL.
    resolveErrorCache.set(key, { message, statusCode }, statusCode === 504 ? { ttl: 10000 } : undefined);
    return reply.code(statusCode).send({ error: message });
  } finally {
    clearTimeout(deadline);
  }
}

/* ------------------------------------------------------------------------- *
 * Provider payloads
 * ------------------------------------------------------------------------- */

async function runZoko(req, { malId, ep, lang }, tier, signal) {
  const clientIP = getClientIP(req);
  const ref = 'https://zokoanime.video/';
  const data = await extractZokoHLS(malId, ep, lang, signal);
  if (!data.streamFile) throw resolveFailure('Zoko returned empty stream src');
  const reachable = await playlistReachable(data.streamFile, ref, signal);

  const result = payload({
    tier,
    src: proxiedPlaylist(data.streamFile, ref, clientIP),
    tracks: proxyTracks(data.tracks, ref, clientIP),
    // The player only ever navigates to the first entry.
    fallbacks: [
      `/embed/kira/mal/${malId}/${ep}/${lang}`,
      `/embed/haiku/mal/${malId}/${ep}/${lang}`
    ],
    telemetry: telemetryMeta('zoko', `mal:${malId}`, ep, tier)
  });
  if (!reachable) {
    zokoStreamCache.delete(`${malId}:${ep <= 0 ? 1 : ep}:${lang === 'dub' ? 'dub' : 'sub'}`);
    markSourceDead(result);
  }
  return result;
}

async function runKira(req, { targetPath, tier, fallbacks }, signal) {
  const clientIP = getClientIP(req);
  const ref = 'https://megaplay.buzz/';
  const data = await extractMegaplayHLSWithFallback(targetPath, signal);
  const reachable = await playlistReachable(data.streamFile, ref, signal);

  const malMatch = targetPath.match(/^mal\/(\d+)/);
  const aniMatch = targetPath.match(/^ani\/(\d+)/);
  const s2Match = targetPath.match(/^s-2\/([^/]+)/);
  const contentLabel = malMatch ? `mal:${malMatch[1]}`
    : aniMatch ? `ani:${aniMatch[1]}`
      : s2Match ? `s2:${s2Match[1]}` : '';
  const episodeLabel = (malMatch || aniMatch) ? (targetPath.split('/')[2] || '') : '';

  const result = payload({
    tier,
    src: proxiedPlaylist(data.streamFile, ref, clientIP),
    tracks: proxyTracks(data.tracks, ref, clientIP),
    fallbacks,
    telemetry: telemetryMeta('kira', contentLabel, episodeLabel, tier),
    intro: data.intro,
    outro: data.outro
  });
  if (!reachable) {
    megaplayStreamCache.delete(normalizeMegaplayPath(targetPath));
    markSourceDead(result);
  }
  return result;
}

async function runSalt(req, { slug, aniId, malId, season, ep, hash, lang }, tier, signal) {
  const clientIP = getClientIP(req);
  // Slug/MAL/AniList resolution stays inside the resolve budget.
  const resolvedSlug = slug || await resolveAnimeSaltSlug(aniId, malId, '', signal);
  const data = await extractAnimeSaltStream(resolvedSlug, season, ep, hash, lang, clientIP, signal);

  // Abyss plays through a plain <video> element, which cannot send the
  // priority header, so partner status rides in the initial URL instead.
  const streamURL = tier === 'partner' ? `${data.proxiedURL}?prior=1` : data.proxiedURL;

  return payload({
    tier,
    src: streamURL,
    tracks: proxyTracks(data.tracks, 'https://abyssplayer.com/', clientIP),
    fallbacks: [],
    telemetry: telemetryMeta('haiku', resolvedSlug || (hash ? `hash:${hash.slice(0, 12)}` : ''), `${season}x${ep}`, tier)
  });
}

/* ------------------------------------------------------------------------- *
 * Routes
 * ------------------------------------------------------------------------- */

async function registerEmbedRoutes(fastify) {
  // Hook to enforce ALLOWED_EMBED_DOMAINS on all /embed/* and /player/* routes.
  // Blocked requests get a bare 403 (no page, no branding) so the iframe shows
  // a plain error and nothing loads. Resolve requests are same-origin JSON:
  // browsers do not forward the embedder's Referer there, so the page-level
  // check ran on the shell and the blocklist is enforced inside the handler.
  fastify.addHook('preHandler', async (req, reply) => {
    if (req.url.startsWith('/embed') || req.url.startsWith('/player')) {
      if (rateLimited(req, 'embed', embedRateLimitPerMin)) {
        reply.header('Cache-Control', 'no-store');
        return reply.code(429).send();
      }
      if (!isResolveRequest(req) && !isEmbedAllowed(req)) {
        reply.header('Cache-Control', 'no-store');
        return reply.code(403).send();
      }
    }
  });

  // --- ZOKO / NAOKA ---
  async function handleZoko(req, reply, { malId = 0, aniId = 0, ep, lang, key }) {
    if (!isResolveRequest(req)) return sendShell(req, reply);

    return resolveRoute(req, reply, key, async (signal) => {
      const tier = resolveTier(req);
      let mal = malId;
      if (!mal && aniId > 0) {
        mal = await resolveMalId(aniId, signal);
      }
      if (!mal) {
        throw resolveFailure(`Could not resolve MAL ID for AniList ID: ${aniId}`, 404);
      }

      return raceProviders([
        {
          name: 'zoko',
          run: (signal) => runZoko(req, { malId: mal, ep, lang }, tier, signal)
        },
        {
          name: 'kira',
          run: (signal) => runKira(req, {
            targetPath: `mal/${mal}/${ep}/${lang}`,
            tier,
            fallbacks: [`/embed/haiku/mal/${mal}/${ep}/${lang}`]
          }, signal)
        }
      ], signal);
    });
  }

  const handleZokoMal = async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleZoko(req, reply, { malId, ep, lang, key: `zoko_mal_${malId}_${ep}_${lang}` });
  };
  fastify.get('/embed/naoka/mal/:mal_id/:ep/:lang', handleZokoMal);
  fastify.get('/embed/zoko/mal/:mal_id/:ep/:lang', handleZokoMal);

  const handleZokoAni = async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleZoko(req, reply, { aniId, ep, lang, key: `zoko_ani_${aniId}_${ep}_${lang}` });
  };
  fastify.get('/embed/naoka/ani/:anilist_id/:ep/:lang', handleZokoAni);
  fastify.get('/embed/zoko/ani/:anilist_id/:ep/:lang', handleZokoAni);

  fastify.get('/embed/naoka/:mal_id/:ep/:lang', handleZokoMal);
  fastify.get('/embed/zoko/:mal_id/:ep/:lang', handleZokoMal);

  const handleZokoPlayer = async (req, reply) => {
    const malId = parseInt(req.query.mal, 10) || 0;
    const aniId = parseInt(req.query.ani, 10) || 0;
    const ep = parseInt(req.query.ep, 10) || 1;
    const lang = req.query.lang || 'sub';

    if (!malId && !aniId) {
      return sendHtmlError(req, reply, 400, 'Missing or invalid mal ID');
    }
    return handleZoko(req, reply, { malId, aniId, ep, lang, key: `zoko_player_${malId || `ani${aniId}`}_${ep}_${lang}` });
  };
  fastify.get('/player/naoka', handleZokoPlayer);
  fastify.get('/player/zoko', handleZokoPlayer);

  // --- ANIMESALT / HAIKU ---
  async function handleSalt(req, reply, ctx) {
    if (!isResolveRequest(req)) return sendShell(req, reply);

    return resolveRoute(req, reply, ctx.key, async (signal) => {
      const tier = resolveTier(req);
      return raceProviders([
        {
          name: 'haiku',
          run: (signal) => runSalt(req, ctx, tier, signal)
        }
      ], signal);
    });
  }

  // /embed/haiku/:spec (e.g. dan-da-dan-1x1?lang=hin)
  const handleSaltSpec = async (req, reply) => {
    const spec = req.params.spec;
    const lang = req.query.lang || 'hin';

    const match = spec.match(/^(.+?)-(\d+)x(\d+)$/);
    if (!match) {
      return sendHtmlError(req, reply, 400, 'Invalid episode spec format (expected slug-1x1)');
    }

    const slug = match[1];
    const season = parseInt(match[2], 10);
    const ep = parseInt(match[3], 10);

    return handleSalt(req, reply, {
      slug, season, ep, hash: '', lang,
      key: `salt_${slug}_${season}x${ep}_${lang}`
    });
  };
  fastify.get('/embed/haiku/:spec', handleSaltSpec);
  fastify.get('/embed/animesalt/:spec', handleSaltSpec);

  const handleSaltAni = async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'hin';
    return handleSalt(req, reply, {
      aniId, season: 1, ep, hash: '', lang,
      key: `salt_ani_${aniId}_${ep}_${lang}`
    });
  };
  fastify.get('/embed/haiku/ani/:anilist_id/:ep/:lang', handleSaltAni);
  fastify.get('/embed/animesalt/ani/:anilist_id/:ep/:lang', handleSaltAni);

  const handleSaltMal = async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'hin';
    return handleSalt(req, reply, {
      malId, season: 1, ep, hash: '', lang,
      key: `salt_mal_${malId}_${ep}_${lang}`
    });
  };
  fastify.get('/embed/haiku/mal/:mal_id/:ep/:lang', handleSaltMal);
  fastify.get('/embed/animesalt/mal/:mal_id/:ep/:lang', handleSaltMal);

  const handleAsCdnHash = async (req, reply) => {
    const hash = req.params.hash;
    const lang = req.query.lang || 'hin';
    return handleSalt(req, reply, {
      hash, season: 1, ep: 1, lang,
      key: `salt_hash_${hash}_${lang}`
    });
  };
  fastify.get('/embed/haiku-cdn/:hash', handleAsCdnHash);
  fastify.get('/player/haiku-cdn/:hash', handleAsCdnHash);
  fastify.get('/embed/as-cdn/:hash', handleAsCdnHash);
  fastify.get('/player/as-cdn/:hash', handleAsCdnHash);

  const handleSaltPlayer = async (req, reply) => {
    const slug = req.query.slug || '';
    const season = parseInt(req.query.season || req.query.s, 10) || 1;
    const ep = parseInt(req.query.ep, 10) || 1;
    const hash = req.query.hash || '';
    const lang = req.query.lang || 'hin';

    if (!slug && !hash) {
      return sendHtmlError(req, reply, 400, 'Missing slug or hash parameter');
    }

    return handleSalt(req, reply, {
      slug, season, ep, hash, lang,
      key: `salt_player_${slug || hash}_${ep}_${lang}`
    });
  };
  fastify.get('/player/haiku', handleSaltPlayer);
  fastify.get('/player/salt', handleSaltPlayer);

  // --- KIRA / MEGAPLAY ---
  async function handleMegaplay(req, reply, { targetPath, lang, key, kiraFallbacks = [], saltHedge = null }) {
    if (!isResolveRequest(req)) return sendShell(req, reply);

    return resolveRoute(req, reply, key, async (signal) => {
      const tier = resolveTier(req);
      const candidates = [
        {
          name: 'kira',
          run: (signal) => runKira(req, { targetPath, tier, fallbacks: kiraFallbacks }, signal)
        }
      ];
      if (saltHedge) {
        candidates.push({
          name: 'haiku',
          run: (signal) => runSalt(req, { ...saltHedge, season: 1, hash: '', lang }, tier, signal)
        });
      }
      return raceProviders(candidates, signal);
    });
  }

  const handleMegaMal = async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, {
      targetPath: `mal/${malId}/${ep}/${lang}`,
      lang,
      key: `mega_mal_${malId}_${ep}_${lang}`,
      kiraFallbacks: [`/embed/haiku/mal/${malId}/${ep}/${lang}`],
      saltHedge: { malId }
    });
  };
  fastify.get('/embed/kira/mal/:mal_id/:ep/:lang', handleMegaMal);
  fastify.get('/embed/megaplay/mal/:mal_id/:ep/:lang', handleMegaMal);

  const handleMegaAni = async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, {
      targetPath: `ani/${aniId}/${ep}/${lang}`,
      lang,
      key: `mega_ani_${aniId}_${ep}_${lang}`,
      kiraFallbacks: [`/embed/haiku/ani/${aniId}/${ep}/${lang}`],
      saltHedge: { aniId }
    });
  };
  fastify.get('/embed/kira/ani/:anilist_id/:ep/:lang', handleMegaAni);
  fastify.get('/embed/megaplay/ani/:anilist_id/:ep/:lang', handleMegaAni);

  const handleMegaS2 = async (req, reply) => {
    const id = req.params.id;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, {
      targetPath: `s-2/${id}/${lang}`,
      lang,
      key: `mega_s2_${id}_${lang}`
    });
  };
  fastify.get('/embed/kira/s-2/:id/:lang', handleMegaS2);
  fastify.get('/embed/megaplay/s-2/:id/:lang', handleMegaS2);

  fastify.get('/player/kira', async (req, reply) => {
    const malId = parseInt(req.query.mal, 10) || 0;
    const aniId = parseInt(req.query.ani, 10) || 0;
    const ep = parseInt(req.query.ep, 10) || 1;
    const lang = req.query.lang || 'sub';
    if (malId > 0) {
      return handleMegaplay(req, reply, {
        targetPath: `mal/${malId}/${ep}/${lang}`,
        lang,
        key: `mega_player_mal_${malId}_${ep}_${lang}`,
        kiraFallbacks: [`/embed/haiku/mal/${malId}/${ep}/${lang}`],
        saltHedge: { malId }
      });
    }
    if (aniId > 0) {
      return handleMegaplay(req, reply, {
        targetPath: `ani/${aniId}/${ep}/${lang}`,
        lang,
        key: `mega_player_ani_${aniId}_${ep}_${lang}`,
        kiraFallbacks: [`/embed/haiku/ani/${aniId}/${ep}/${lang}`],
        saltHedge: { aniId }
      });
    }
    return sendHtmlError(req, reply, 400, 'Missing mal or ani query parameter');
  });
}

module.exports = {
  registerEmbedRoutes,
  raceProviders,
  markSourceDead
};
