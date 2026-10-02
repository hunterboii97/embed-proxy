const { extractZokoHLS } = require('../scrapers/zoko');
const { extractAnimeSaltStream, resolveAnimeSaltSlug } = require('../scrapers/animesalt');
const { extractMegaplayHLSWithFallback } = require('../scrapers/megaplay');
const { resolveMalId } = require('../scrapers/resolver');
const { stats, m3u8PlaylistCache, zokoStreamCache, animeSaltStreamCache, megaplayStreamCache } = require('../utils/cache');

const startTime = Date.now();

async function registerApiRoutes(fastify) {
  // /health
  fastify.get('/health', async (req, reply) => {
    const mem = process.memoryUsage();
    return {
      status: 'ok',
      service: 'yume-proxy-node',
      uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
      timestamp: new Date().toISOString(),
      memory: {
        rssMB: Math.round(mem.rss / 1024 / 1024),
        heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024)
      },
      cacheStats: stats,
      cacheSizes: {
        m3u8: m3u8PlaylistCache.size,
        zoko: zokoStreamCache.size,
        animeSalt: animeSaltStreamCache.size,
        megaplay: megaplayStreamCache.size
      }
    };
  });

  // /api/zoko/source?mal=&ani=&ep=&lang=
  fastify.get('/api/zoko/source', async (req, reply) => {
    let malId = parseInt(req.query.mal, 10) || 0;
    const aniId = parseInt(req.query.ani, 10) || 0;
    const ep = parseInt(req.query.ep, 10) || 1;
    const lang = req.query.lang || 'sub';

    if (!malId && aniId > 0) {
      malId = await resolveMalId(aniId);
    }
    if (!malId) {
      return reply.code(400).send({ error: 'Missing or invalid mal ID' });
    }

    try {
      const data = await extractZokoHLS(malId, ep, lang);
      return {
        server: 'zoko',
        malId,
        episode: ep,
        language: lang,
        streamUrl: data.streamFile,
        subtitles: data.tracks,
        skip: data.skip
      };
    } catch (err) {
      return reply.code(404).send({ error: err.message });
    }
  });

  // /api/animesalt/source?slug=&season=&ep=&hash=&ani=&mal=
  const handleSaltSource = async (req, reply) => {
    let slug = req.query.slug || '';
    const season = parseInt(req.query.season || req.query.s, 10) || 1;
    const ep = parseInt(req.query.ep, 10) || 1;
    const hash = req.query.hash || req.params.hash || '';
    const aniId = parseInt(req.query.ani, 10) || 0;
    const malId = parseInt(req.query.mal, 10) || 0;
    const lang = req.query.lang || 'hin';

    if (!slug && !hash && (aniId > 0 || malId > 0)) {
      try {
        slug = await resolveAnimeSaltSlug(aniId, malId, '');
      } catch (err) {
        return reply.code(404).send({ error: err.message });
      }
    }

    if (!slug && !hash) {
      return reply.code(400).send({ error: 'Missing slug, hash, or ani/mal ID' });
    }

    try {
      const data = await extractAnimeSaltStream(slug, season, ep, hash, lang);
      return {
        server: 'animesalt',
        slug: data.resolvedSlug || slug,
        season,
        episode: ep,
        language: lang,
        streamUrl: data.proxiedURL,
        audioOptions: data.audioOptions
      };
    } catch (err) {
      return reply.code(404).send({ error: err.message });
    }
  };

  fastify.get('/api/animesalt/source', handleSaltSource);
  fastify.get('/api/as-cdn/:hash', handleSaltSource);

  // /stream/getSources and /stream/getSourcesNew
  const handleMegaplaySources = async (req, reply) => {
    const id = req.query.id || '';
    const malId = parseInt(req.query.mal, 10) || 0;
    const aniId = parseInt(req.query.ani, 10) || 0;
    const ep = parseInt(req.query.ep, 10) || 1;
    const lang = req.query.lang || 'sub';

    let targetPath = '';
    if (id) {
      targetPath = `s-2/${id}/${lang}`;
    } else if (malId > 0) {
      targetPath = `mal/${malId}/${ep}/${lang}`;
    } else if (aniId > 0) {
      targetPath = `ani/${aniId}/${ep}/${lang}`;
    } else {
      return reply.code(400).send({ error: 'Missing id, mal, or ani query param' });
    }

    try {
      const data = await extractMegaplayHLSWithFallback(targetPath);
      return {
        server: 'megaplay',
        path: targetPath,
        streamUrl: data.streamFile,
        subtitles: data.tracks
      };
    } catch (err) {
      return reply.code(404).send({ error: err.message });
    }
  };

  fastify.get('/stream/getSources', handleMegaplaySources);
  fastify.get('/stream/getSourcesNew', handleMegaplaySources);
}

module.exports = {
  registerApiRoutes
};
