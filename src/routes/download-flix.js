const { spawn } = require('node:child_process');
const {
  getClientIP,
  flixDownloadRateLimitPerMin,
  flixDownloadDailyLimit,
  flixDownloadQuotaDir
} = require('../../config');
const { consumeDownloadQuota } = require('../utils/download-quota');
const { resolveAnimeTitle } = require('../scrapers/resolver');
const { listFlixServers, pickFlixServer } = require('../scrapers/reanime');
const { openFlixDownload, resolveFlixDownloadUrl } = require('../scrapers/flixcloud');
const { DEFAULT_UA } = require('../utils/http');

const SERVER_SLOTS = { kaiju: 1 };
const EXT_WHITELIST = new Set(['mkv', 'mp4', 'webm', 'avi', 'm4v', 'mov', 'ts', 'm2ts']);

function downloadEnabled() {
  return String(process.env.DOWNLOAD_ENABLED || '').toLowerCase() === 'true';
}

function extensionOf(filename) {
  const m = /\.([A-Za-z0-9]{2,5})$/.exec(String(filename || ''));
  const ext = m ? m[1].toLowerCase() : '';
  return EXT_WHITELIST.has(ext) ? ext : 'mkv';
}

function buildFilename(title, ep, lang, upstreamFilename) {
  const cleanTitle = String(title || 'Anime')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/"]/g, '')
    .replace(/\s+/g, ' ')
    .trim() || 'Anime';
  const epPad = String(ep).padStart(2, '0');
  const langTag = lang === 'dub' ? 'Dub' : 'Sub';
  return `[Mikaza-API] - ${cleanTitle} (Ep ${epPad})(${langTag}).${extensionOf(upstreamFilename)}`;
}

function rfc5987Encode(value) {
  return encodeURIComponent(value).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
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

// Reanime lists one dual-audio file under both languages, so a direct proxy
// would always play the first (Japanese) track. Sub can stay on the fast raw
// path; dub is remuxed here to keep only the English audio.
async function streamSub(reply, { fileId, episode, titlePromise, method, range, signal }) {
  const raw = reply.raw;
  let upstream;
  let title;
  try {
    [upstream, title] = await Promise.all([
      openFlixDownload(fileId, {
        method,
        range: method === 'GET' ? String(range || '') : '',
        signal
      }),
      titlePromise
    ]);
  } catch (err) {
    if (signal.aborted) {
      reply.hijack();
      raw.destroy();
      return;
    }
    console.error('[kaiju-download] sub source failed:', err.message);
    const status = err.upstreamStatus === 404 ? 404 : 502;
    return reply.code(status).send({
      error: status === 404 ? 'Source file was removed upstream' : 'Download extraction failed'
    });
  }

  const filename = buildFilename(title, episode, 'sub', upstream.video.filename);
  const headers = {
    ...commonHeaders(filename),
    'Content-Type': upstream.res.headers['content-type'] || 'application/octet-stream',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges, Content-Disposition'
  };
  for (const key of ['content-length', 'content-range', 'accept-ranges', 'last-modified']) {
    const value = upstream.res.headers[key];
    if (value) headers[key.replace(/(^|-)\w/g, c => c.toUpperCase())] = value;
  }

  reply.hijack();
  raw.writeHead(upstream.res.statusCode, headers);

  if (method === 'HEAD') {
    try { await upstream.res.body.dump(); } catch {}
    raw.end();
    return;
  }

  try {
    for await (const chunk of upstream.res.body) {
      if (raw.destroyed || raw.writableEnded) break;
      if (!raw.write(chunk)) await waitDrain(raw);
    }
  } catch {}
  if (!raw.writableEnded) raw.end();
}

function streamDubRemux(reply, { url, filename, signal }) {
  return new Promise((resolve) => {
    const raw = reply.raw;
    let child;
    try {
      child = spawn('ffmpeg', [
        '-loglevel', 'error',
        '-nostdin',
        '-probesize', '1000000',
        '-analyzeduration', '0',
        '-rw_timeout', '15000000',
        '-user_agent', DEFAULT_UA,
        '-i', url,
        '-map', '0:v:0',
        '-map', '0:a:m:language:eng',
        '-map', '0:s?',
        '-map', '0:t?',
        '-c', 'copy',
        '-f', 'matroska',
        'pipe:1'
      ], { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      reply.code(502).send({ error: 'Remux process failed to start' });
      resolve();
      return;
    }

    let started = false;
    let finished = false;
    let stderr = '';

    const kill = () => {
      try { child.kill('SIGKILL'); } catch {}
    };
    signal.addEventListener('abort', kill, { once: true });
    if (signal.aborted) kill();

    const finish = (fn) => {
      if (finished) return;
      finished = true;
      signal.removeEventListener('abort', kill);
      fn();
      resolve();
    };

    raw.once('close', () => {
      if (!raw.writableFinished) kill();
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (d) => {
      stderr = (stderr + d).slice(-4000);
    });

    child.stdout.once('data', (chunk) => {
      started = true;
      reply.hijack();
      raw.writeHead(200, {
        ...commonHeaders(filename),
        'Content-Type': 'video/x-matroska',
        'Accept-Ranges': 'none',
        'Access-Control-Expose-Headers': 'Content-Disposition'
      });
      raw.write(chunk);
      child.stdout.pipe(raw);
    });

    child.on('error', () => {
      finish(() => {
        if (started) {
          if (!raw.writableEnded) raw.destroy();
        } else if (!raw.destroyed) {
          reply.code(502).send({ error: 'Remux process is unavailable' });
        }
      });
    });

    child.on('close', (code) => {
      if (!started) {
        console.error('[kaiju-download] ffmpeg produced no output', code, stderr.slice(0, 500));
      }
      finish(() => {
        if (!started) {
          if (!raw.destroyed) {
            const noEnglish = /matches no streams|does not match any streams/i.test(stderr);
            reply.code(noEnglish ? 404 : 502).send({
              error: noEnglish ? 'Source has no English audio track' : 'Failed to remux the source audio'
            });
          }
        } else if (!raw.writableEnded) {
          raw.end();
        }
      });
    });
  });
}

async function streamDub(reply, { fileId, episode, titlePromise, method, signal }) {
  const raw = reply.raw;
  let resolved;
  let title;
  try {
    [resolved, title] = await Promise.all([
      resolveFlixDownloadUrl(fileId, { signal }),
      titlePromise
    ]);
  } catch (err) {
    if (signal.aborted) {
      reply.hijack();
      raw.destroy();
      return;
    }
    console.error('[kaiju-download] dub source failed:', err.message);
    const status = err.upstreamStatus === 404 ? 404 : 502;
    return reply.code(status).send({
      error: status === 404 ? 'Source file was removed upstream' : 'Download extraction failed'
    });
  }

  const filename = buildFilename(title, episode, 'dub', 'output.mkv');

  if (method === 'HEAD') {
    reply.hijack();
    raw.writeHead(200, {
      ...commonHeaders(filename),
      'Content-Type': 'video/x-matroska',
      'Accept-Ranges': 'none',
      'Access-Control-Expose-Headers': 'Content-Disposition'
    });
    raw.end();
    return;
  }

  await streamDubRemux(reply, { url: resolved.url, filename, signal });
}

async function registerFlixDownloadRoutes(fastify) {
  fastify.get('/download/:server/ani/:ani/:ep/:lang', async (req, reply) => {
    if (!downloadEnabled()) {
      return reply.code(403).send({ error: 'Downloads are disabled on this deployment.' });
    }

    const serverName = String(req.params.server || '').toLowerCase();
    const serverSlot = SERVER_SLOTS[serverName];
    const aniId = /^\d{1,10}$/.test(req.params.ani || '') ? parseInt(req.params.ani, 10) : 0;
    const episode = /^\d{1,4}$/.test(req.params.ep || '') ? parseInt(req.params.ep, 10) : 0;
    const lang = String(req.params.lang || '').toLowerCase();
    const method = req.method === 'HEAD' ? 'HEAD' : 'GET';

    if (!serverSlot) {
      return reply.code(400).send({ error: 'Unknown download server. Use /download/kaiju/ani/{anilistId}/{ep}/{sub|dub}' });
    }
    if (!aniId || !episode) {
      return reply.code(400).send({ error: 'anilistId and episode must be positive integers' });
    }
    if (lang !== 'sub' && lang !== 'dub') {
      return reply.code(400).send({ error: 'Language must be sub or dub' });
    }

    let picked;
    try {
      const servers = await listFlixServers(aniId, episode);
      picked = pickFlixServer(servers, serverSlot, lang);
    } catch (err) {
      return reply.code(502).send({ error: `Source lookup failed: ${err.message}` });
    }
    if (!picked) {
      return reply.code(404).send({
        error: `No ${lang} source on ${serverName} for AniList ${aniId} episode ${episode}`
      });
    }

    // HEAD probes are free: download managers send one before the real GET.
    if (method !== 'HEAD') {
      let quota;
      try {
        quota = consumeDownloadQuota(getClientIP(req), {
          dir: flixDownloadQuotaDir,
          perMinute: flixDownloadRateLimitPerMin,
          perDay: flixDownloadDailyLimit
        });
      } catch (err) {
        console.error('[download-quota]', err.message);
        return reply.code(503).send({ error: 'Download quota store unavailable' });
      }
      if (!quota.allowed) {
        reply.header('Retry-After', String(quota.retryAfter));
        const error = quota.reason === 'day'
          ? `Daily download limit reached (${flixDownloadDailyLimit} per IP per 24 hours)`
          : quota.reason === 'minute'
            ? `Download rate limit reached (${flixDownloadRateLimitPerMin} per minute per IP)`
            : 'Download quota is busy, try again shortly';
        return reply.code(429).send({ error, retryAfter: quota.retryAfter });
      }
    }

    const abort = new AbortController();
    const raw = reply.raw;
    const onClientClose = () => {
      if (!raw.writableFinished) abort.abort();
    };
    raw.once('close', onClientClose);

    const titlePromise = resolveAnimeTitle(aniId, 0).catch(() => '');
    const shared = {
      fileId: picked.fileId,
      episode,
      titlePromise,
      method,
      signal: abort.signal
    };

    if (lang === 'sub') {
      await streamSub(reply, { ...shared, range: req.headers.range });
    } else {
      await streamDub(reply, shared);
    }
  });
}

module.exports = {
  registerFlixDownloadRoutes
};
