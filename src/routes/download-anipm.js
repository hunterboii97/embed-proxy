const { request } = require('undici');
const {
  getClientIP,
  anipmCookie,
  anipmCdnHosts,
  anipmDownloadRateLimitPerMin,
  anipmDownloadDailyLimit,
  anipmDownloadQuotaDir,
  anipmDownloadConcurrency,
  rateLimitEnabled
} = require('../../config');
const { consumeDownloadQuota } = require('../utils/download-quota');
const {
  resolveAnipmDownload,
  AnipmError,
  AnipmAuthError,
  AnipmNotFoundError
} = require('../scrapers/anipm');
const { globalAgent, DEFAULT_UA } = require('../utils/http');

const EXT_WHITELIST = new Set(['mkv', 'mp4', 'webm', 'avi', 'm4v', 'mov', 'ts', 'm2ts']);

let activeDownloads = 0;

function downloadEnabled() {
  return String(process.env.DOWNLOAD_ENABLED || '').toLowerCase() === 'true';
}

function extensionOf(filename) {
  const match = /\.([A-Za-z0-9]{2,5})$/.exec(String(filename || ''));
  const ext = match ? match[1].toLowerCase() : '';
  return EXT_WHITELIST.has(ext) ? ext : 'mp4';
}

function qualityTag(quality) {
  if (quality === null || quality === undefined) return '';
  const value = String(quality).trim();
  if (!value) return '';
  return `(${/p$/i.test(value) ? value : `${value}p`})`;
}

function buildFilename(title, ep, lang, quality, upstreamFilename) {
  const cleanTitle = String(title || 'Anime')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/"]/g, '')
    .replace(/\s+/g, ' ')
    .trim() || 'Anime';
  const epPad = String(ep).padStart(2, '0');
  const tags = [qualityTag(quality), `(${lang === 'dub' ? 'Dub' : 'Sub'})`].filter(Boolean).join(' ');
  return `[Mikaza-API] - ${cleanTitle} (Ep ${epPad}) ${tags}.${extensionOf(upstreamFilename)}`;
}

function rfc5987Encode(value) {
  return encodeURIComponent(value).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function contentDisposition(filename) {
  const ascii = filename.replace(/[\\"]/g, '_').replace(/[^\x20-\x7e]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${rfc5987Encode(filename)}`;
}

function commonHeaders(filename) {
  return {
    'Content-Disposition': contentDisposition(filename),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Accel-Buffering': 'no',
    'Access-Control-Allow-Origin': '*'
  };
}

function waitDrain(res) {
  return new Promise((resolve) => {
    const done = () => {
      res.off('drain', done);
      res.off('close', done);
      resolve();
    };
    res.once('drain', done);
    res.once('close', done);
  });
}

async function registerAnipmDownloadRoutes(fastify) {
  fastify.get('/download/nut/ani/:ani/:ep/:lang', async (req, reply) => {
    if (!downloadEnabled()) {
      return reply.code(403).send({ error: 'Downloads are disabled on this deployment.' });
    }
    if (!anipmCookie) {
      return reply.code(503).send({ error: 'Download source is not configured (ANIPM_COOKIE).' });
    }

    const aniId = /^\d{1,10}$/.test(req.params.ani || '') ? parseInt(req.params.ani, 10) : 0;
    const episode = /^\d{1,4}$/.test(req.params.ep || '') ? parseInt(req.params.ep, 10) : 0;
    const lang = String(req.params.lang || '').toLowerCase();
    const method = req.method === 'HEAD' ? 'HEAD' : 'GET';

    if (!aniId || !episode) {
      return reply.code(400).send({ error: 'anilistId and episode must be positive integers' });
    }
    if (lang !== 'sub' && lang !== 'dub') {
      return reply.code(400).send({ error: 'lang must be sub or dub' });
    }

    // HEAD probes are free: download managers send one before the real GET.
    if (method !== 'HEAD') {
      let quota;
      try {
        quota = await consumeDownloadQuota(getClientIP(req), {
          dir: anipmDownloadQuotaDir,
          perMinute: rateLimitEnabled ? anipmDownloadRateLimitPerMin : 0,
          perDay: rateLimitEnabled ? anipmDownloadDailyLimit : 0
        });
      } catch (err) {
        console.error('[anipm-download-quota]', err.message);
        return reply.code(503).send({ error: 'Download quota store unavailable' });
      }
      if (!quota.allowed) {
        reply.header('Retry-After', String(quota.retryAfter));
        const error = quota.reason === 'day'
          ? `Daily download limit reached (${anipmDownloadDailyLimit} per IP per 24 hours)`
          : quota.reason === 'minute'
            ? `Download rate limit reached (${anipmDownloadRateLimitPerMin} per minute per IP)`
            : 'Download quota is busy, try again shortly';
        return reply.code(429).send({ error, retryAfter: quota.retryAfter });
      }
    }

    // HEAD transfers no body and finishes in about a second; only real GET
    // streams should consume the per-worker concurrency budget.
    const countsTowardConcurrency = method !== 'HEAD';
    if (countsTowardConcurrency && activeDownloads >= anipmDownloadConcurrency) {
      reply.header('Retry-After', '2');
      return reply.code(503).send({ error: 'Download server is busy, try again shortly' });
    }
    if (countsTowardConcurrency) activeDownloads++;

    const abort = new AbortController();
    const raw = reply.raw;
    const onClientClose = () => {
      if (!raw.writableFinished) abort.abort();
    };
    raw.once('close', onClientClose);

    try {
      let resolved;
      try {
        resolved = await resolveAnipmDownload({
          anilistId: aniId,
          ep: episode,
          lang,
          cookie: anipmCookie,
          cdnHosts: anipmCdnHosts
        });
      } catch (err) {
        if (abort.signal.aborted) {
          reply.hijack();
          raw.destroy();
          return;
        }
        if (err instanceof AnipmAuthError) {
          console.error('[anipm-download] session:', err.message);
          return reply.code(503).send({ error: 'Download source session expired. Update ANIPM_COOKIE.' });
        }
        if (err instanceof AnipmNotFoundError) {
          return reply.code(404).send({ error: err.message });
        }
        if (err instanceof AnipmError && err.statusCode === 429) {
          if (err.retryAfter) reply.header('Retry-After', String(err.retryAfter));
          return reply.code(429).send({ error: 'Download source rate limit reached' });
        }
        if (err instanceof AnipmError && err.statusCode === 403) {
          console.error('[anipm-download] blocked:', err.message);
          return reply.code(503).send({ error: 'Download source blocked the request' });
        }
        console.error('[anipm-download] resolve failed:', err.message);
        return reply.code(502).send({ error: 'Download source failed' });
      }

      const filename = buildFilename(resolved.title, episode, lang, resolved.quality, resolved.filename);
      const upstreamHeaders = {
        'user-agent': DEFAULT_UA,
        accept: '*/*',
        'accept-encoding': 'identity'
      };
      if (resolved.needsCookie) upstreamHeaders.cookie = anipmCookie;
      if (method !== 'HEAD' && req.headers.range) upstreamHeaders.range = String(req.headers.range);

      let upstream;
      try {
        upstream = await request(resolved.url, {
          method,
          headers: upstreamHeaders,
          dispatcher: globalAgent,
          signal: abort.signal
        });
      } catch (err) {
        if (abort.signal.aborted) {
          reply.hijack();
          raw.destroy();
          return;
        }
        console.error('[anipm-download] cdn failed:', err.message);
        return reply.code(502).send({ error: 'Download CDN failed' });
      }

      if (upstream.statusCode >= 400 && upstream.statusCode !== 416) {
        try { await upstream.body.dump(); } catch {}
        console.error('[anipm-download] cdn HTTP', upstream.statusCode);
        return reply.code(502).send({ error: `Download CDN HTTP ${upstream.statusCode}` });
      }

      const headers = {
        ...commonHeaders(filename),
        'Content-Type': upstream.headers['content-type'] || 'application/octet-stream',
        'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges, Content-Disposition'
      };
      for (const key of ['content-length', 'content-range', 'accept-ranges', 'last-modified', 'etag']) {
        const value = upstream.headers[key];
        if (value) headers[key.replace(/(^|-)\w/g, (c) => c.toUpperCase())] = value;
      }

      reply.hijack();
      raw.writeHead(upstream.statusCode, headers);

      if (method === 'HEAD') {
        try { await upstream.body.dump(); } catch {}
        raw.end();
        return;
      }

      try {
        for await (const chunk of upstream.body) {
          if (raw.destroyed || raw.writableEnded) break;
          if (!raw.write(chunk)) await waitDrain(raw);
        }
      } catch {}
      if (!raw.writableEnded) raw.end();
    } finally {
      if (countsTowardConcurrency) activeDownloads--;
      raw.off('close', onClientClose);
    }
  });
}

module.exports = {
  registerAnipmDownloadRoutes
};
