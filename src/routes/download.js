const { spawn } = require('node:child_process');
const { Readable } = require('node:stream');
const { extractZokoHLS } = require('../scrapers/zoko');
const { extractAnimeSaltStream, resolveAnimeSaltSlug } = require('../scrapers/animesalt');
const { extractMegaplayHLSWithFallback } = require('../scrapers/megaplay');
const { resolveAnimeTitle, resolveMalId } = require('../scrapers/resolver');
const { resolveM3U8Quality, resolveAbsoluteURL } = require('../utils/m3u8');
const { fetchText, request, globalAgent, DEFAULT_UA } = require('../utils/http');

function buildDownloadFilename(title, ep, quality, lang, ext = 'mp4') {
  let cleanTitle = (title || 'Anime')
    .replace(/[^a-zA-Z0-9_\-\.\s]/g, '')
    .trim()
    .replace(/\s+/g, '_');
  if (!cleanTitle) cleanTitle = 'Anime';

  let q = (quality || 'HD').toLowerCase();
  if (!q.endsWith('p') && q !== 'hd' && q !== 'best') {
    q = q + 'p';
  }
  const langUpper = (lang || 'SUB').toUpperCase();
  const epPad = String(ep).padStart(2, '0');

  return `[KaidoAPI]_${cleanTitle}_EP${epPad}_${langUpper}_${q}.${ext}`;
}

async function streamM3U8AsMP4(reply, variantM3U8URL, referer, filename) {
  reply.hijack();
  const rawRes = reply.raw;
  reply.header('Content-Type', 'video/mp4');
  reply.header('Content-Disposition', `attachment; filename="${filename}"`);
  reply.header('Accept-Ranges', 'none');
  reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');

  const headers = {
    'user-agent': DEFAULT_UA
  };
  if (referer) {
    headers['referer'] = referer;
    try {
      const u = new URL(referer);
      headers['origin'] = `${u.protocol}//${u.host}`;
    } catch {}
  }

  // 1. Fetch variant playlist to get segment URLs
  const { body: m3u8Text } = await fetchText(variantM3U8URL, { headers });
  if (!m3u8Text) {
    return reply.code(502).send({ error: 'Failed fetching variant M3U8 playlist' });
  }

  const chunkURLs = [];
  const lines = m3u8Text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      chunkURLs.push(resolveAbsoluteURL(trimmed, variantM3U8URL));
    }
  }

  if (chunkURLs.length === 0) {
    return reply.code(404).send({ error: 'No video segments found in playlist' });
  }

  // 2. Spawn FFmpeg for real-time zero-transcode remuxing
  const ffmpegArgs = [
    '-loglevel', 'error',
    '-probesize', '1000000',
    '-analyzeduration', '1500000',
    '-f', 'mpegts',
    '-i', 'pipe:0',
    '-map', '0:v:0',
    '-map', '0:a:0?',
    '-sn',
    '-dn',
    '-avoid_negative_ts', 'make_zero',
    '-c', 'copy',
    '-bsf:a', 'aac_adtstoasc',
    '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
    '-f', 'mp4',
    'pipe:1'
  ];

  let ffmpeg;
  try {
    ffmpeg = spawn('ffmpeg', ffmpegArgs);
  } catch (err) {
    // If FFmpeg is not installed, fallback to streaming raw TS
    return streamM3U8AsTS(reply, chunkURLs, referer, filename.replace('.mp4', '.ts'));
  }

  ffmpeg.on('error', () => {
    // FFmpeg spawn failure -> fallback
    if (!rawRes.headersSent) {
      streamM3U8AsTS(reply, chunkURLs, referer, filename.replace('.mp4', '.ts'));
    }
  });

  ffmpeg.stdout.pipe(rawRes);

  rawRes.on('close', () => {
    try { ffmpeg.kill('SIGKILL'); } catch {}
  });

  // 3. Concurrently prefetch and feed TS chunks into FFmpeg stdin
  (async () => {
    for (const cURL of chunkURLs) {
      if (rawRes.destroyed || ffmpeg.killed) break;
      try {
        const cRes = await request(cURL, {
          method: 'GET',
          headers,
          dispatcher: globalAgent
        });

        const buf = Buffer.from(await cRes.body.arrayBuffer());
        let data = buf;

        // Strip PNG header if disguised TS chunk
        if (data.length >= 253 && data[0] === 0x89 && data[1] === 0x50 && data[252] === 0x47) {
          data = data.subarray(252);
        }

        if (data.length > 0) {
          if (!ffmpeg.stdin.write(data)) {
            await new Promise(r => ffmpeg.stdin.once('drain', r));
          }
        }
      } catch (err) {
        break;
      }
    }
    ffmpeg.stdin.end();
  })();
}

async function streamM3U8AsTS(reply, chunkURLs, referer, filename) {
  reply.hijack();
  const rawRes = reply.raw;
  if (!rawRes.headersSent) {
    reply.header('Content-Type', 'video/mp2t');
    reply.header('Content-Disposition', `attachment; filename="${filename}"`);
    reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  }

  const headers = { 'user-agent': DEFAULT_UA };
  if (referer) headers['referer'] = referer;

  for (const cURL of chunkURLs) {
    if (rawRes.destroyed) break;
    try {
      const cRes = await request(cURL, {
        method: 'GET',
        headers,
        dispatcher: globalAgent
      });
      const buf = Buffer.from(await cRes.body.arrayBuffer());
      let data = buf;
      if (data.length >= 253 && data[0] === 0x89 && data[1] === 0x50 && data[252] === 0x47) {
        data = data.subarray(252);
      }
      if (data.length > 0) {
        if (!rawRes.write(data)) {
          await new Promise(r => rawRes.once('drain', r));
        }
      }
    } catch {}
  }
  rawRes.end();
}

async function registerDownloadRoutes(fastify) {
  const handleDownload = async (req, reply) => {
    const q = req.query;
    let server = (q.server || '').toLowerCase().trim();
    const malId = parseInt(q.mal, 10) || 0;
    const aniId = parseInt(q.ani || q.anilist, 10) || 0;
    const slug = q.slug || '';
    const hash = q.hash || '';
    const ep = parseInt(q.ep || q.episode, 10) || 1;
    const season = parseInt(q.season || q.s, 10) || 1;
    const quality = (q.q || q.quality || 'best').toLowerCase().trim();
    const lang = (q.lang || 'sub').toLowerCase().trim();
    const format = (q.format || 'mp4').toLowerCase().trim();
    let customTitle = q.title || '';

    if (!customTitle && (malId > 0 || aniId > 0)) {
      customTitle = await resolveAnimeTitle(aniId, malId);
    }

    if (!server) {
      server = (slug || hash) ? 'haiku' : 'naoka';
    }

    let streamURL = '';
    let referer = '';

    if (server === 'naoka' || server === 'zoko') {
      let resolvedMal = malId;
      if (!resolvedMal && aniId > 0) {
        resolvedMal = await resolveMalId(aniId);
      }
      if (!resolvedMal) {
        return reply.code(400).send({ error: 'Missing or invalid mal or ani parameter for Naoka' });
      }
      try {
        const data = await extractZokoHLS(resolvedMal, ep, lang);
        streamURL = data.streamFile;
        referer = 'https://zokoanime.video/';
      } catch (err) {
        return reply.code(404).send({ error: `Naoka extraction error: ${err.message}` });
      }
    } else if (server === 'kira' || server === 'megaplay') {
      let targetPath = '';
      if (q.s2) {
        targetPath = `s-2/${q.s2}/${lang}`;
      } else if (malId > 0) {
        targetPath = `mal/${malId}/${ep}/${lang}`;
      } else if (aniId > 0) {
        targetPath = `ani/${aniId}/${ep}/${lang}`;
      } else {
        return reply.code(400).send({ error: 'Missing s2, mal, or ani parameter for Kira' });
      }
      try {
        const data = await extractMegaplayHLSWithFallback(targetPath);
        streamURL = data.streamFile;
        referer = 'https://anikoto.cz/';
      } catch (err) {
        return reply.code(404).send({ error: `Kira extraction error: ${err.message}` });
      }
    } else if (server === 'haiku' || server === 'animesalt' || server === 'salt') {
      let resolvedSlug = slug;
      if (!resolvedSlug && !hash && (aniId > 0 || malId > 0)) {
        try {
          resolvedSlug = await resolveAnimeSaltSlug(aniId, malId, '');
        } catch (err) {
          return reply.code(404).send({ error: err.message });
        }
      }
      try {
        const data = await extractAnimeSaltStream(resolvedSlug, season, ep, hash, lang);
        const filename = buildDownloadFilename(customTitle || data.resolvedSlug || 'Anime', ep, quality, lang, 'mp4');

        // Haiku returns a proxied URL like /p/:token/video.mp4
        reply.header('Location', `${data.proxiedURL}?dl=1&filename=${encodeURIComponent(filename)}`);
        return reply.code(302).send();
      } catch (err) {
        return reply.code(404).send({ error: `Haiku extraction error: ${err.message}` });
      }
    } else {
      return reply.code(400).send({ error: `Unknown server: ${server}` });
    }

    if (!streamURL) {
      return reply.code(404).send({ error: 'Failed extracting stream URL' });
    }

    // Resolve M3U8 Quality variant
    try {
      const { selectedURL, effectiveReferer } = await resolveM3U8Quality(streamURL, referer, quality);
      const filename = buildDownloadFilename(customTitle || 'Anime', ep, quality, lang, format);

      return streamM3U8AsMP4(reply, selectedURL, effectiveReferer, filename);
    } catch (err) {
      return reply.code(500).send({ error: `Stream download failed: ${err.message}` });
    }
  };

  fastify.get('/api/download', handleDownload);
  fastify.get('/download', handleDownload);
}

module.exports = {
  registerDownloadRoutes
};
