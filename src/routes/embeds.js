const { isEmbedAllowed, buildFrameAncestorsCSP } = require('../../config');
const { encryptToken } = require('../utils/crypto');
const { renderCleanArtplayer, renderCustomProxy404 } = require('../views/player');
const { extractZokoHLS } = require('../scrapers/zoko');
const { resolveAnimeSaltSlug, extractAnimeSaltStream } = require('../scrapers/animesalt');
const { extractMegaplayHLSWithFallback } = require('../scrapers/megaplay');
const { resolveMalId } = require('../scrapers/resolver');

function applyEmbedHeaders(req, reply) {
  const host = req.headers['host'] || '';
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Content-Security-Policy', buildFrameAncestorsCSP(host));
  reply.header('X-Content-Type-Options', 'nosniff');
}

function proxyTracks(tracks) {
  return (tracks || []).map(t => {
    if (!t.file) return t;
    if (t.file.startsWith('/p/')) return t;
    const token = encryptToken({
      url: t.file,
      ref: '',
      exp: Math.floor(Date.now() / 1000) + 86400
    });
    return {
      ...t,
      file: `/p/${token}/subtitles.vtt`
    };
  });
}

async function registerEmbedRoutes(fastify) {
  // Hook to enforce ALLOWED_EMBED_DOMAINS iframe security on all /embed/* and /player/* routes
  fastify.addHook('preHandler', async (req, reply) => {
    if (req.url.startsWith('/embed') || req.url.startsWith('/player')) {
      if (!isEmbedAllowed(req)) {
        applyEmbedHeaders(req, reply);
        return reply.code(403).send(renderCustomProxy404(req.url, 'Embedding is not permitted from this domain'));
      }
    }
  });

  // --- ZOKO EMBEDS ---
  async function handleZoko(req, reply, malId, ep, lang, episodeKey) {
    applyEmbedHeaders(req, reply);
    try {
      const data = await extractZokoHLS(malId, ep, lang);
      const streamToken = encryptToken({
        url: data.streamFile,
        ref: 'https://zokoanime.video/',
        exp: Math.floor(Date.now() / 1000) + 86400
      });
      const proxiedM3U8 = `/p/${streamToken}/master.m3u8`;
      const proxiedTracks = proxyTracks(data.tracks);

      const html = renderCleanArtplayer(proxiedM3U8, proxiedTracks, lang, episodeKey);
      return reply.send(html);
    } catch (err) {
      return reply.code(404).send(renderCustomProxy404(req.url, `Zoko stream error: ${err.message}`));
    }
  }

  // /embed/zoko/mal/:mal_id/:ep/:lang
  fastify.get('/embed/zoko/mal/:mal_id/:ep/:lang', async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleZoko(req, reply, malId, ep, lang, `zoko_mal_${malId}_${ep}_${lang}`);
  });

  // /embed/zoko/ani/:anilist_id/:ep/:lang
  fastify.get('/embed/zoko/ani/:anilist_id/:ep/:lang', async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    const malId = await resolveMalId(aniId);
    if (!malId) {
      applyEmbedHeaders(req, reply);
      return reply.code(404).send(renderCustomProxy404(req.url, `Could not resolve MAL ID for AniList ID: ${aniId}`));
    }
    return handleZoko(req, reply, malId, ep, lang, `zoko_ani_${aniId}_${ep}_${lang}`);
  });

  // /embed/zoko/:mal_id/:ep/:lang
  fastify.get('/embed/zoko/:mal_id/:ep/:lang', async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleZoko(req, reply, malId, ep, lang, `zoko_mal_${malId}_${ep}_${lang}`);
  });

  // /player/zoko?mal=&ani=&ep=&lang=
  fastify.get('/player/zoko', async (req, reply) => {
    let malId = parseInt(req.query.mal, 10) || 0;
    const aniId = parseInt(req.query.ani, 10) || 0;
    const ep = parseInt(req.query.ep, 10) || 1;
    const lang = req.query.lang || 'sub';

    if (!malId && aniId > 0) {
      malId = await resolveMalId(aniId);
    }
    if (!malId) {
      applyEmbedHeaders(req, reply);
      return reply.code(400).send(renderCustomProxy404(req.url, 'Missing or invalid mal ID'));
    }
    return handleZoko(req, reply, malId, ep, lang, `zoko_player_${malId}_${ep}_${lang}`);
  });

  // --- ANIMESALT EMBEDS ---
  async function handleSalt(req, reply, slug, season, ep, hash, lang, episodeKey) {
    applyEmbedHeaders(req, reply);
    try {
      const data = await extractAnimeSaltStream(slug, season, ep, hash, lang);
      const proxiedTracks = proxyTracks(data.tracks);

      const html = renderCleanArtplayer(
        data.proxiedURL,
        proxiedTracks,
        lang,
        episodeKey,
        data.audioOptions
      );
      return reply.send(html);
    } catch (err) {
      return reply.code(404).send(renderCustomProxy404(req.url, `AnimeSalt stream error: ${err.message}`));
    }
  }

  // /embed/animesalt/:spec (e.g. dan-da-dan-1x1?lang=hin)
  fastify.get('/embed/animesalt/:spec', async (req, reply) => {
    const spec = req.params.spec;
    const lang = req.query.lang || 'hin';

    // Parse slug-1x1
    const match = spec.match(/^(.+?)-(\d+)x(\d+)$/);
    if (!match) {
      applyEmbedHeaders(req, reply);
      return reply.code(400).send(renderCustomProxy404(req.url, 'Invalid episode spec format (expected slug-1x1)'));
    }

    const slug = match[1];
    const season = parseInt(match[2], 10);
    const ep = parseInt(match[3], 10);

    return handleSalt(req, reply, slug, season, ep, '', lang, `salt_${slug}_${season}x${ep}_${lang}`);
  });

  // /embed/animesalt/ani/:anilist_id/:ep/:lang
  fastify.get('/embed/animesalt/ani/:anilist_id/:ep/:lang', async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'hin';

    try {
      const slug = await resolveAnimeSaltSlug(aniId, 0, '');
      return handleSalt(req, reply, slug, 1, ep, '', lang, `salt_ani_${aniId}_${ep}_${lang}`);
    } catch (err) {
      applyEmbedHeaders(req, reply);
      return reply.code(404).send(renderCustomProxy404(req.url, err.message));
    }
  });

  // /embed/animesalt/mal/:mal_id/:ep/:lang
  fastify.get('/embed/animesalt/mal/:mal_id/:ep/:lang', async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'hin';

    try {
      const slug = await resolveAnimeSaltSlug(0, malId, '');
      return handleSalt(req, reply, slug, 1, ep, '', lang, `salt_mal_${malId}_${ep}_${lang}`);
    } catch (err) {
      applyEmbedHeaders(req, reply);
      return reply.code(404).send(renderCustomProxy404(req.url, err.message));
    }
  });

  // /embed/as-cdn/:hash and /player/as-cdn/:hash
  const handleAsCdnHash = async (req, reply) => {
    const hash = req.params.hash;
    const lang = req.query.lang || 'hin';
    return handleSalt(req, reply, '', 1, 1, hash, lang, `salt_hash_${hash}_${lang}`);
  };
  fastify.get('/embed/as-cdn/:hash', handleAsCdnHash);
  fastify.get('/player/as-cdn/:hash', handleAsCdnHash);

  // /player/salt?slug=&ep=&lang=
  fastify.get('/player/salt', async (req, reply) => {
    const slug = req.query.slug || '';
    const season = parseInt(req.query.season || req.query.s, 10) || 1;
    const ep = parseInt(req.query.ep, 10) || 1;
    const hash = req.query.hash || '';
    const lang = req.query.lang || 'hin';

    if (!slug && !hash) {
      applyEmbedHeaders(req, reply);
      return reply.code(400).send(renderCustomProxy404(req.url, 'Missing slug or hash parameter'));
    }

    return handleSalt(req, reply, slug, season, ep, hash, lang, `salt_player_${slug || hash}_${ep}_${lang}`);
  });

  // --- MEGAPLAY EMBEDS ---
  async function handleMegaplay(req, reply, targetPath, lang, episodeKey) {
    applyEmbedHeaders(req, reply);
    try {
      const data = await extractMegaplayHLSWithFallback(targetPath);
      const streamToken = encryptToken({
        url: data.streamFile,
        ref: 'https://megaplay.buzz/',
        exp: Math.floor(Date.now() / 1000) + 86400
      });
      const proxiedM3U8 = `/p/${streamToken}/master.m3u8`;
      const proxiedTracks = proxyTracks(data.tracks);

      const html = renderCleanArtplayer(proxiedM3U8, proxiedTracks, lang, episodeKey);
      return reply.send(html);
    } catch (err) {
      return reply.code(404).send(renderCustomProxy404(req.url, `MegaPlay stream error: ${err.message}`));
    }
  }

  // /embed/megaplay/mal/:mal_id/:ep/:lang
  fastify.get('/embed/megaplay/mal/:mal_id/:ep/:lang', async (req, reply) => {
    const malId = parseInt(req.params.mal_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, `mal/${malId}/${ep}/${lang}`, lang, `mega_mal_${malId}_${ep}_${lang}`);
  });

  // /embed/megaplay/ani/:anilist_id/:ep/:lang
  fastify.get('/embed/megaplay/ani/:anilist_id/:ep/:lang', async (req, reply) => {
    const aniId = parseInt(req.params.anilist_id, 10);
    const ep = parseInt(req.params.ep, 10) || 1;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, `ani/${aniId}/${ep}/${lang}`, lang, `mega_ani_${aniId}_${ep}_${lang}`);
  });

  // /embed/megaplay/s-2/:id/:lang
  fastify.get('/embed/megaplay/s-2/:id/:lang', async (req, reply) => {
    const id = req.params.id;
    const lang = req.params.lang || 'sub';
    return handleMegaplay(req, reply, `s-2/${id}/${lang}`, lang, `mega_s2_${id}_${lang}`);
  });
}

module.exports = {
  registerEmbedRoutes
};
