const { spawn, execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { extractZokoHLS } = require('../scrapers/zoko');
const { extractAnimeSaltStream, resolveAnimeSaltSlug } = require('../scrapers/animesalt');
const { extractMegaplayHLSWithFallback } = require('../scrapers/megaplay');
const { resolveAnimeTitle, resolveMalId } = require('../scrapers/resolver');
const { resolveM3U8Quality, resolveAbsoluteURL, buildCdnHeaders } = require('../utils/m3u8');
const { fetchText, request, globalAgent } = require('../utils/http');

// High concurrency keeps CDN pipes saturated for max download throughput
const PREFETCH_CONCURRENCY = 12;
// Override via MAX_CONCURRENT_DOWNLOADS env for bigger instances
const MAX_CONCURRENT_DOWNLOADS = Math.max(1, parseInt(process.env.MAX_CONCURRENT_DOWNLOADS, 10) || 5);

let ffmpegAvailable = null;
let activeDownloads = 0;

function detectFFmpeg() {
  if (ffmpegAvailable !== null) return ffmpegAvailable;
  try {
    execFileSync('ffmpeg', ['-version'], { stdio: 'ignore', timeout: 5000 });
    ffmpegAvailable = true;
  } catch {
    ffmpegAvailable = false;
  }
  return ffmpegAvailable;
}

function makeTempPath() {
  return path.join(os.tmpdir(), `kaido-dl-${crypto.randomBytes(8).toString('hex')}.mp4`);
}

function removeTempFile(tempPath) {
  if (!tempPath) return;
  fs.unlink(tempPath, () => {});
}

function cleanupOrphanedTempFiles() {
  const dir = os.tmpdir();
  fs.readdir(dir, (err, names) => {
    if (err || !names) return;
    const cutoff = Date.now() - 60 * 60 * 1000;
    for (const name of names) {
      if (!name.startsWith('kaido-dl-') || !name.endsWith('.mp4')) continue;
      const full = path.join(dir, name);
      fs.stat(full, (statErr, st) => {
        if (statErr || st.mtimeMs >= cutoff) return;
        fs.unlink(full, () => {});
      });
    }
  });
}

/**
 * MegaPlay CDNs disguise TS as .jpg/.html/.js/etc. Strip fake headers
 * and align to MPEG-TS sync byte (0x47, 188-byte packets).
 */
function stripToMpegTs(data) {
  if (!data || data.length === 0) return data;

  // Known PNG disguise prefix (252 bytes) used by several anime CDNs
  if (
    data.length >= 253 &&
    data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47 &&
    data[252] === 0x47
  ) {
    return data.subarray(252);
  }

  if (data[0] === 0x47) return data;

  const limit = Math.min(data.length - 1, 2048);
  for (let i = 1; i < limit; i++) {
    if (data[i] !== 0x47) continue;
    const next = i + 188;
    if (next < data.length) {
      if (data[next] === 0x47) return data.subarray(i);
    } else {
      return data.subarray(i);
    }
  }
  return data;
}

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

function parseMediaPlaylist(m3u8Text, baseURL) {
  const chunkURLs = [];
  let hasKey = false;
  let hasMap = false;
  const lines = m3u8Text.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('#EXT-X-KEY')) hasKey = true;
    if (trimmed.startsWith('#EXT-X-MAP')) hasMap = true;
    if (!trimmed.startsWith('#')) {
      chunkURLs.push(resolveAbsoluteURL(trimmed, baseURL));
    }
  }

  return { chunkURLs, hasKey, hasMap, needsHlsDemuxer: hasKey || hasMap };
}

function writeAttachmentHead(rawRes, contentType, filename) {
  rawRes.writeHead(200, {
    'Content-Type': contentType,
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Accept-Ranges': 'none',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Access-Control-Allow-Origin': '*',
    'X-Content-Type-Options': 'nosniff'
  });
}

/**
 * Ordered prefetch pool: keeps up to `concurrency` segment fetches in flight,
 * but delivers buffers to the consumer in playlist order.
 */
async function prefetchOrdered(urls, fetchOne, concurrency, shouldAbort) {
  const n = urls.length;
  const results = new Array(n);
  let nextToStart = 0;
  let nextToYield = 0;
  const waiters = [];

  function notify() {
    while (waiters.length > 0 && (results[nextToYield] !== undefined || shouldAbort())) {
      const { resolve } = waiters.shift();
      resolve();
    }
  }

  async function worker() {
    while (true) {
      if (shouldAbort()) return;
      const idx = nextToStart++;
      if (idx >= n) return;
      try {
        results[idx] = await fetchOne(urls[idx], idx);
      } catch {
        results[idx] = null;
      }
      notify();
    }
  }

  const workers = [];
  const workerCount = Math.min(concurrency, n);
  for (let i = 0; i < workerCount; i++) {
    workers.push(worker());
  }

  async function* iterate() {
    while (nextToYield < n) {
      if (shouldAbort()) return;
      while (results[nextToYield] === undefined) {
        if (shouldAbort()) return;
        await Promise.race([
          new Promise((resolve) => waiters.push({ resolve })),
          new Promise((resolve) => setTimeout(resolve, 200))
        ]);
        if (shouldAbort()) return;
      }
      const buf = results[nextToYield];
      results[nextToYield] = undefined;
      nextToYield++;
      if (buf && buf.length > 0) yield buf;
    }
  }

  return { iterate, done: Promise.all(workers) };
}

async function fetchSegmentBuffer(url, fallbackReferer) {
  const headers = buildCdnHeaders(url, fallbackReferer);
  const cRes = await request(url, {
    method: 'GET',
    headers,
    dispatcher: globalAgent,
    headersTimeout: 20000,
    bodyTimeout: 45000
  });
  if (cRes.statusCode >= 400) {
    try { await cRes.body.dump(); } catch {}
    throw new Error(`Segment HTTP ${cRes.statusCode}`);
  }
  const buf = Buffer.from(await cRes.body.arrayBuffer());
  return stripToMpegTs(buf);
}

async function writeWithBackpressure(writable, data) {
  if (!data || data.length === 0) return;
  if (!writable || writable.destroyed || writable.writableEnded) return;
  try {
    if (!writable.write(data)) {
      await new Promise((resolve, reject) => {
        const onDrain = () => {
          cleanup();
          resolve();
        };
        const onError = () => {
          cleanup();
          resolve(); // treat as stop, not crash
        };
        const cleanup = () => {
          writable.off('drain', onDrain);
          writable.off('error', onError);
        };
        writable.once('drain', onDrain);
        writable.once('error', onError);
      });
    }
  } catch {
    // EPIPE / EOF when client or ffmpeg closes early
  }
}

function acquireDownloadSlot() {
  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) return false;
  activeDownloads++;
  return true;
}

function releaseDownloadSlot() {
  if (activeDownloads > 0) activeDownloads--;
}

async function fetchPlaylistText(url, fallbackReferer) {
  const headers = buildCdnHeaders(url, fallbackReferer);
  const { body, statusCode } = await fetchText(url, { headers });
  const ok = statusCode === 200 && body && body.includes('#EXTM3U');
  return {
    ok,
    body: body || '',
    statusCode,
    headers,
    referer: headers['referer'] || fallbackReferer || ''
  };
}

/**
 * Concatenate TS segments (explicit format=ts only).
 */
async function streamM3U8AsTS(reply, chunkURLs, fallbackReferer, filename) {
  reply.hijack();
  const rawRes = reply.raw;
  writeAttachmentHead(rawRes, 'video/mp2t', filename);

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseDownloadSlot();
    }
  };
  rawRes.on('close', release);

  const t0 = Date.now();
  let bytes = 0;
  try {
    const { iterate, done } = await prefetchOrdered(
      chunkURLs,
      (url) => fetchSegmentBuffer(url, fallbackReferer),
      PREFETCH_CONCURRENCY,
      () => rawRes.destroyed
    );

    for await (const data of iterate()) {
      if (rawRes.destroyed) break;
      bytes += data.length;
      await writeWithBackpressure(rawRes, data);
    }
    await done;
    console.log(`[download] ts done segments=${chunkURLs.length} bytes=${bytes} ms=${Date.now() - t0}`);
  } catch (err) {
    console.error('[download] TS stream error:', err.message);
  } finally {
    if (!rawRes.writableEnded && !rawRes.destroyed) rawRes.end();
    release();
  }
}

/**
 * Remux plain MPEG-TS via FFmpeg stdin (-c copy → fMP4). Ultra-fast path.
 */
async function streamTSViaFFmpeg(reply, chunkURLs, fallbackReferer, filename) {
  reply.hijack();
  const rawRes = reply.raw;
  writeAttachmentHead(rawRes, 'video/mp4', filename);

  const ffmpegArgs = [
    '-hide_banner',
    '-loglevel', 'error',
    '-fflags', '+genpts+discardcorrupt',
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
    '-flush_packets', '1',
    '-f', 'mp4',
    'pipe:1'
  ];

  let ffmpeg;
  try {
    ffmpeg = spawn('ffmpeg', ffmpegArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err) {
    console.error('[download] FFmpeg spawn failed:', err.message);
    releaseDownloadSlot();
    if (!rawRes.destroyed) {
      try {
        rawRes.writeHead(503, { 'Content-Type': 'application/json' });
      } catch {}
      rawRes.end(JSON.stringify({ error: 'FFmpeg spawn failed' }));
    }
    return;
  }

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseDownloadSlot();
    }
  };

  let aborted = false;
  let clientGone = false;
  let bytesOut = 0;
  const abort = () => {
    aborted = true;
    try { ffmpeg.kill('SIGKILL'); } catch {}
  };

  rawRes.on('close', () => {
    clientGone = true;
    abort();
    release();
  });

  ffmpeg.on('error', (err) => {
    console.error('[download] FFmpeg error:', err.message);
    abort();
    release();
    if (!rawRes.writableEnded && !rawRes.destroyed) {
      try {
        if (bytesOut === 0 && !clientGone) rawRes.destroy();
        else rawRes.end();
      } catch {}
    }
  });

  let stderrBuf = '';
  ffmpeg.stderr.on('data', (chunk) => {
    if (stderrBuf.length < 2000) stderrBuf += chunk.toString();
  });

  ffmpeg.stdin.on('error', () => {
    aborted = true;
  });

  ffmpeg.stdout.on('data', (chunk) => {
    bytesOut += chunk.length;
  });
  ffmpeg.stdout.pipe(rawRes, { end: false });

  const t0 = Date.now();
  ffmpeg.on('close', (code) => {
    const failed = Boolean(code) && code !== 0;
    if (failed && !clientGone) {
      console.error(`[download] FFmpeg exited ${code} bytesOut=${bytesOut}: ${stderrBuf.slice(0, 300)}`);
    }
    console.log(`[download] mp4 remux done segments=${chunkURLs.length} code=${code} bytes=${bytesOut} ms=${Date.now() - t0}`);
    if (!rawRes.writableEnded && !rawRes.destroyed) {
      try {
        if (failed && !clientGone) rawRes.destroy();
        else rawRes.end();
      } catch {}
    }
    release();
  });

  try {
    const { iterate, done } = await prefetchOrdered(
      chunkURLs,
      (url) => fetchSegmentBuffer(url, fallbackReferer),
      PREFETCH_CONCURRENCY,
      () => aborted || rawRes.destroyed || ffmpeg.killed
    );

    for await (const data of iterate()) {
      if (aborted || rawRes.destroyed || ffmpeg.killed) break;
      await writeWithBackpressure(ffmpeg.stdin, data);
    }
    await done;
  } catch (err) {
    console.error('[download] Feed error:', err.message);
  } finally {
    try {
      if (!ffmpeg.stdin.destroyed) ffmpeg.stdin.end();
    } catch {}
  }
}

/**
 * FFmpeg HLS demuxer for EXT-X-KEY / EXT-X-MAP playlists.
 */
async function streamViaFFmpegHLS(reply, variantM3U8URL, headers, filename) {
  reply.hijack();
  const rawRes = reply.raw;
  writeAttachmentHead(rawRes, 'video/mp4', filename);

  const ffmpegArgs = [
    '-hide_banner',
    '-loglevel', 'error',
    ...buildFFmpegHeaderArgs(headers),
    '-protocol_whitelist', 'file,http,https,tcp,tls,crypto',
    '-i', variantM3U8URL,
    '-map', '0:v:0',
    '-map', '0:a:0?',
    '-sn',
    '-dn',
    '-avoid_negative_ts', 'make_zero',
    '-c', 'copy',
    '-bsf:a', 'aac_adtstoasc',
    '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
    '-flush_packets', '1',
    '-f', 'mp4',
    'pipe:1'
  ];

  let ffmpeg;
  try {
    ffmpeg = spawn('ffmpeg', ffmpegArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    releaseDownloadSlot();
    if (!rawRes.headersSent) {
      rawRes.writeHead(502, { 'Content-Type': 'application/json' });
      rawRes.end(JSON.stringify({ error: 'FFmpeg unavailable for HLS remux' }));
    } else {
      rawRes.end();
    }
    return;
  }

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseDownloadSlot();
    }
  };

  let clientGone = false;
  let bytesOut = 0;

  rawRes.on('close', () => {
    clientGone = true;
    try { ffmpeg.kill('SIGKILL'); } catch {}
    release();
  });

  ffmpeg.on('error', (err) => {
    console.error('[download] FFmpeg HLS error:', err.message);
    try { ffmpeg.kill('SIGKILL'); } catch {}
  });

  let stderrBuf = '';
  ffmpeg.stderr.on('data', (chunk) => {
    if (stderrBuf.length < 2000) stderrBuf += chunk.toString();
  });
  ffmpeg.stdout.on('data', (chunk) => {
    bytesOut += chunk.length;
  });
  ffmpeg.stdout.pipe(rawRes, { end: false });

  ffmpeg.on('close', (code) => {
    const failed = Boolean(code) && code !== 0;
    if (failed && !clientGone) {
      console.error(`[download] FFmpeg HLS exited ${code} bytesOut=${bytesOut}: ${stderrBuf.slice(0, 300)}`);
    }
    if (!rawRes.writableEnded && !rawRes.destroyed) {
      try {
        if (failed && !clientGone) rawRes.destroy();
        else rawRes.end();
      } catch {}
    }
    release();
  });
}

function buildFFmpegHeaderArgs(headers) {
  const headerLines = [`User-Agent: ${headers['user-agent'] || ''}`];
  if (headers['referer']) headerLines.push(`Referer: ${headers['referer']}`);
  if (headers['origin']) headerLines.push(`Origin: ${headers['origin']}`);
  return ['-headers', headerLines.join('\r\n') + '\r\n'];
}

/**
 * Remux into a seekable temp file → regular (non-fragmented) MP4 with moov
 * up front (faststart). Resolves with the final file size.
 */
function remuxToTempFile(ctx, { inputArgs, tempPath, feedSegments }) {
  return new Promise((resolve, reject) => {
    const args = [
      '-hide_banner',
      '-loglevel', 'error',
      '-y',
      ...inputArgs,
      '-map', '0:v:0',
      '-map', '0:a:0?',
      '-sn',
      '-dn',
      '-avoid_negative_ts', 'make_zero',
      '-c', 'copy',
      '-bsf:a', 'aac_adtstoasc',
      '-movflags', '+faststart',
      '-f', 'mp4',
      tempPath
    ];

    let ffmpeg;
    try {
      ffmpeg = spawn('ffmpeg', args, { stdio: ['pipe', 'ignore', 'pipe'] });
    } catch (err) {
      reject(err);
      return;
    }

    let settled = false;
    let stderrBuf = '';

    ctx.kill = () => {
      try { ffmpeg.kill('SIGKILL'); } catch {}
    };

    ffmpeg.stderr.on('data', (chunk) => {
      if (stderrBuf.length < 2000) stderrBuf += chunk.toString();
    });
    ffmpeg.stdin.on('error', () => {});

    ffmpeg.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

    ffmpeg.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (ctx.stopped) return reject(new Error('aborted by client'));
      if (code !== 0) return reject(new Error(`FFmpeg exited ${code}: ${stderrBuf.slice(0, 300)}`));
      fs.stat(tempPath, (err, st) => {
        if (err || !st || st.size === 0) return reject(new Error('FFmpeg produced empty output'));
        resolve(st.size);
      });
    });

    if (feedSegments) {
      feedSegments(ffmpeg.stdin)
        .catch(() => {})
        .finally(() => {
          try {
            if (!ffmpeg.stdin.destroyed) ffmpeg.stdin.end();
          } catch {}
        });
    } else {
      try { ffmpeg.stdin.end(); } catch {}
    }
  });
}

/**
 * Default mode: remux the whole episode into a temp file, then serve it as a
 * completed regular MP4 (faststart, real Content-Length). The client waits
 * until remux finishes — use stream=1 for instant fragmented-MP4 streaming.
 */
async function downloadToRegularMP4(reply, { label, filename, inputArgs, chunkURLs, fallbackReferer }) {
  const rawRes = reply.raw;
  const tempPath = makeTempPath();
  const ctx = { stopped: false, kill: null };
  const onClose = () => {
    ctx.stopped = true;
    if (ctx.kill) ctx.kill();
  };
  rawRes.on('close', onClose);

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseDownloadSlot();
    }
  };

  const t0 = Date.now();
  let bytesIn = 0;
  try {
    const feedSegments = chunkURLs && chunkURLs.length > 0
      ? async (stdin) => {
          const { iterate, done } = await prefetchOrdered(
            chunkURLs,
            (url) => fetchSegmentBuffer(url, fallbackReferer),
            PREFETCH_CONCURRENCY,
            () => ctx.stopped || stdin.destroyed
          );
          for await (const data of iterate()) {
            if (ctx.stopped || stdin.destroyed) break;
            bytesIn += data.length;
            await writeWithBackpressure(stdin, data);
          }
          await done;
        }
      : null;

    const size = await remuxToTempFile(ctx, { inputArgs, tempPath, feedSegments });

    console.log(
      `[download] mp4 ready src=${label} segments=${chunkURLs ? chunkURLs.length : '-'} in=${bytesIn} size=${size} ms=${Date.now() - t0}`
    );
    serveCompletedFile(reply, tempPath, filename, size, release);
  } catch (err) {
    removeTempFile(tempPath);
    release();
    if (ctx.stopped || rawRes.destroyed) {
      reply.hijack(); // client already gone — keep Fastify out of the dead connection
      if (!rawRes.destroyed) rawRes.destroy();
      return;
    }
    console.error(`[download] file remux failed (${label}): ${err.message}`);
    return reply.code(502).send({ error: 'Remux to MP4 failed', detail: err.message });
  }
}

function serveCompletedFile(reply, tempPath, filename, size, onDone) {
  reply.hijack();
  const rawRes = reply.raw;

  let finalized = false;
  const finalize = () => {
    if (finalized) return;
    finalized = true;
    removeTempFile(tempPath);
    onDone();
  };

  rawRes.writeHead(200, {
    'Content-Type': 'video/mp4',
    'Content-Length': String(size),
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Accept-Ranges': 'none',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Access-Control-Allow-Origin': '*',
    'X-Content-Type-Options': 'nosniff'
  });

  const fileStream = fs.createReadStream(tempPath, { highWaterMark: 1 << 20 });
  rawRes.on('close', () => {
    fileStream.destroy();
    finalize();
  });
  fileStream.on('error', (err) => {
    console.error('[download] file serve error:', err.message);
    if (!rawRes.destroyed) rawRes.destroy();
    finalize();
  });
  fileStream.pipe(rawRes);
}

/**
 * Entry: validate playlist with CDN headers, then remux to MP4.
 * Default: complete regular MP4 file (broad player support).
 * streamMode (stream=1): instant fragmented-MP4 streaming.
 */
async function streamM3U8AsMP4(reply, variantM3U8URL, fallbackReferer, filename, streamMode = false) {
  const playlist = await fetchPlaylistText(variantM3U8URL, fallbackReferer);
  if (!playlist.ok) {
    releaseDownloadSlot();
    return reply.code(502).send({
      error: 'Failed fetching variant M3U8 playlist',
      status: playlist.statusCode,
      url: variantM3U8URL.split('?')[0]
    });
  }

  const { chunkURLs, needsHlsDemuxer } = parseMediaPlaylist(playlist.body, variantM3U8URL);
  if (chunkURLs.length === 0 && !needsHlsDemuxer) {
    releaseDownloadSlot();
    return reply.code(404).send({ error: 'No video segments found in playlist' });
  }

  console.log(
    `[download] playlist ok segments=${chunkURLs.length} key=${needsHlsDemuxer} mode=${streamMode ? 'stream' : 'file'} ref=${playlist.referer}`
  );

  if (!detectFFmpeg()) {
    releaseDownloadSlot();
    return reply.code(503).send({
      error: 'FFmpeg is required for MP4 downloads. Install ffmpeg or use Docker/Railway image.'
    });
  }

  if (needsHlsDemuxer) {
    // Encrypted / CMAF playlists: let the FFmpeg HLS demuxer handle keys & init segments
    if (streamMode) {
      return streamViaFFmpegHLS(reply, variantM3U8URL, playlist.headers, filename);
    }
    return downloadToRegularMP4(reply, {
      label: 'hls',
      filename,
      inputArgs: [
        ...buildFFmpegHeaderArgs(playlist.headers),
        '-protocol_whitelist', 'file,http,https,tcp,tls,crypto',
        '-i', variantM3U8URL
      ]
    });
  }

  if (streamMode) {
    return streamTSViaFFmpeg(reply, chunkURLs, playlist.referer, filename);
  }

  return downloadToRegularMP4(reply, {
    label: 'ts',
    filename,
    inputArgs: ['-fflags', '+genpts+discardcorrupt', '-f', 'mpegts', '-i', 'pipe:0'],
    chunkURLs,
    fallbackReferer: playlist.referer
  });
}

async function registerDownloadRoutes(fastify) {
  detectFFmpeg();
  if (detectFFmpeg()) {
    console.log('[download] FFmpeg detected — MP4 remux enabled');
  } else {
    console.warn('[download] FFmpeg not found — MP4 downloads will return 503');
  }
  cleanupOrphanedTempFiles();

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
    let format = (q.format || 'mp4').toLowerCase().trim();
    if (format !== 'mp4' && format !== 'ts') format = 'mp4';
    const streamMode = q.stream === '1' || q.stream === 'true' || (q.mode || '').toLowerCase().trim() === 'stream';
    let customTitle = q.title || '';

    if (!acquireDownloadSlot()) {
      return reply.code(429).send({
        error: 'Too many concurrent downloads. Try again shortly.',
        limit: MAX_CONCURRENT_DOWNLOADS
      });
    }

    let slotHeld = true;
    const releaseIfHeld = () => {
      if (slotHeld) {
        slotHeld = false;
        releaseDownloadSlot();
      }
    };

    try {
      if (!customTitle && (malId > 0 || aniId > 0)) {
        customTitle = await resolveAnimeTitle(aniId, malId);
      }

      if (!server) {
        server = (slug || hash) ? 'haiku' : 'naoka';
      }

      let streamURL = '';
      let fallbackReferer = '';

      if (server === 'naoka' || server === 'zoko') {
        let resolvedMal = malId;
        if (!resolvedMal && aniId > 0) {
          resolvedMal = await resolveMalId(aniId);
        }
        if (!resolvedMal) {
          releaseIfHeld();
          return reply.code(400).send({ error: 'Missing or invalid mal or ani parameter for Naoka' });
        }
        try {
          const data = await extractZokoHLS(resolvedMal, ep, lang);
          streamURL = data.streamFile;
          fallbackReferer = 'https://zokoanime.video/';
        } catch (err) {
          releaseIfHeld();
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
          releaseIfHeld();
          return reply.code(400).send({ error: 'Missing s2, mal, or ani parameter for Kira' });
        }
        try {
          const data = await extractMegaplayHLSWithFallback(targetPath);
          streamURL = data.streamFile;
          // CDN hosts (nexabloom/shiora/…) require megaplay.buzz, NOT anikoto.cz
          fallbackReferer = 'https://megaplay.buzz/';
        } catch (err) {
          releaseIfHeld();
          return reply.code(404).send({ error: `Kira extraction error: ${err.message}` });
        }
      } else if (server === 'haiku' || server === 'animesalt' || server === 'salt') {
        let resolvedSlug = slug;
        if (!resolvedSlug && !hash && (aniId > 0 || malId > 0)) {
          try {
            resolvedSlug = await resolveAnimeSaltSlug(aniId, malId, '');
          } catch (err) {
            releaseIfHeld();
            return reply.code(404).send({ error: err.message });
          }
        }
        try {
          const data = await extractAnimeSaltStream(resolvedSlug, season, ep, hash, lang);
          const filename = buildDownloadFilename(
            customTitle || data.resolvedSlug || 'Anime',
            ep,
            quality,
            lang,
            'mp4'
          );
          releaseIfHeld();
          reply.header('Location', `${data.proxiedURL}?dl=1&filename=${encodeURIComponent(filename)}`);
          return reply.code(302).send();
        } catch (err) {
          releaseIfHeld();
          return reply.code(404).send({ error: `Haiku extraction error: ${err.message}` });
        }
      } else {
        releaseIfHeld();
        return reply.code(400).send({ error: `Unknown server: ${server}` });
      }

      if (!streamURL) {
        releaseIfHeld();
        return reply.code(404).send({ error: 'Failed extracting stream URL' });
      }

      const resolved = await resolveM3U8Quality(streamURL, fallbackReferer, quality);
      const selectedURL = resolved.selectedURL;
      const effectiveReferer = resolved.referer || fallbackReferer;
      const filename = buildDownloadFilename(customTitle || 'Anime', ep, quality, lang, 'mp4');

      // Explicit TS only when requested — default is always MP4
      if (format === 'ts') {
        const playlist = await fetchPlaylistText(selectedURL, effectiveReferer);
        if (!playlist.ok) {
          releaseIfHeld();
          return reply.code(502).send({
            error: 'Failed fetching variant M3U8 playlist',
            status: playlist.statusCode
          });
        }
        const { chunkURLs, needsHlsDemuxer } = parseMediaPlaylist(playlist.body, selectedURL);
        if (needsHlsDemuxer) {
          slotHeld = false;
          return streamM3U8AsMP4(reply, selectedURL, effectiveReferer, filename, streamMode);
        }
        if (chunkURLs.length === 0) {
          releaseIfHeld();
          return reply.code(404).send({ error: 'No video segments found in playlist' });
        }
        slotHeld = false;
        return streamM3U8AsTS(
          reply,
          chunkURLs,
          playlist.referer,
          filename.replace(/\.mp4$/i, '.ts')
        );
      }

      slotHeld = false;
      return streamM3U8AsMP4(reply, selectedURL, effectiveReferer, filename, streamMode);
    } catch (err) {
      releaseIfHeld();
      return reply.code(500).send({ error: `Stream download failed: ${err.message}` });
    }
  };

  fastify.get('/api/download', handleDownload);
  fastify.get('/download', handleDownload);
}

module.exports = {
  registerDownloadRoutes,
  detectFFmpeg,
  MAX_CONCURRENT_DOWNLOADS
};
