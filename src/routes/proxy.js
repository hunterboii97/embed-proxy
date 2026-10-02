const { request } = require('undici');
const crypto = require('node:crypto');
const { Readable, Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const { cdnRules, isPrivateHost } = require('../../config');
const { decryptToken, encryptPlaylistResponse, genSoraToken } = require('../utils/crypto');
const { rewriteM3U8 } = require('../utils/m3u8');
const { m3u8PlaylistCache, tsSegmentCache, stats } = require('../utils/cache');
const { globalAgent, DEFAULT_UA } = require('../utils/http');

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || '127.0.0.1';
}

function setCORS(reply) {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  reply.header('Access-Control-Allow-Headers', 'Range, Content-Type, Authorization, X-Requested-With');
  reply.header('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges');
  reply.header('Accept-Ranges', 'bytes');
}

/**
 * Handles Abyss Chunked (Type B) video proxying with Sora tokens and range clamping
 */
async function handleAbyssChunked(req, reply, payload) {
  const totalSize = payload.ts || 0;
  let chunkSize = payload.cs || 5242880;
  if (chunkSize <= 0) chunkSize = 5242880;

  const rangeHeader = req.headers['range'];
  let start = 0;
  let end = totalSize - 1;

  if (rangeHeader && rangeHeader.startsWith('bytes=')) {
    const parts = rangeHeader.replace('bytes=', '').split('-');
    if (parts[0]) {
      const pStart = parseInt(parts[0], 10);
      if (!isNaN(pStart)) start = pStart;
    }
    if (parts[1]) {
      const pEnd = parseInt(parts[1], 10);
      if (!isNaN(pEnd) && pEnd < totalSize) end = pEnd;
    }
  }

  // Cap range response to at most 1 chunk (5MB) per HTTP request.
  // This prevents the proxy from getting stuck in an infinite 300MB download loop
  // when browsers request open-ended ranges like 'bytes=0-'.
  let chunkEnd = (Math.floor(start / chunkSize) + 1) * chunkSize - 1;
  if (chunkEnd >= totalSize) chunkEnd = totalSize - 1;
  if (end > chunkEnd) end = chunkEnd;

  reply.hijack();
  const rawRes = reply.raw;

  if (start > end || start >= totalSize) {
    rawRes.writeHead(416, {
      'Content-Range': `bytes */${totalSize}`,
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization, X-Requested-With',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges'
    });
    rawRes.end('Requested range not satisfiable');
    return;
  }

  const contentLength = end - start + 1;
  rawRes.writeHead(206, {
    'Content-Type': 'video/mp4',
    'Accept-Ranges': 'bytes',
    'Content-Length': String(contentLength),
    'Content-Range': `bytes ${start}-${end}/${totalSize}`,
    'Cache-Control': 'public, max-age=86400, immutable',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization, X-Requested-With',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges'
  });

  const startChunkIdx = Math.floor(start / chunkSize);
  const endChunkIdx = Math.floor(end / chunkSize);

  for (let idx = startChunkIdx; idx <= endChunkIdx; idx++) {
    if (rawRes.destroyed) return;

    const cStartByte = idx * chunkSize;
    let cEndByte = cStartByte + chunkSize - 1;
    if (cEndByte >= totalSize) cEndByte = totalSize - 1;

    let reqStartInChunk = 0;
    if (start > cStartByte) {
      reqStartInChunk = start - cStartByte;
    }

    let reqEndInChunk = cEndByte - cStartByte;
    if (end < cEndByte) {
      reqEndInChunk = end - cStartByte;
    }

    const soraPath = `/mp4/${payload.mid}/${payload.rid}/${totalSize}/${chunkSize}/${idx}`;
    const soraToken = genSoraToken(soraPath, totalSize);
    const chunkURL = `https://${payload.dom}/sora/${totalSize}/${soraToken}`;

    const cReqRange = `bytes=${reqStartInChunk}-${reqEndInChunk}`;
    try {
      const upstreamRes = await request(chunkURL, {
        method: 'GET',
        headers: {
          'user-agent': DEFAULT_UA,
          referer: 'https://abyssplayer.com/',
          origin: 'https://abyssplayer.com',
          connection: 'keep-alive',
          'sec-fetch-dest': 'video',
          'sec-fetch-mode': 'cors',
          'sec-fetch-site': 'cross-site',
          range: cReqRange
        },
        dispatcher: globalAgent
      });

      for await (const chunk of upstreamRes.body) {
        if (rawRes.destroyed) return;
        if (!rawRes.write(chunk)) {
          await new Promise(r => rawRes.once('drain', r));
        }
      }
    } catch (err) {
      break;
    }
  }

  rawRes.end();
}

/**
 * Handles Abyss CTR Decryption (first 64KB decrypted with AES-256-CTR)
 */
async function handleAbyssCTR(req, reply, upstreamRes, payload) {
  reply.hijack();
  const rawRes = reply.raw;

  const headers = {
    'Content-Type': 'video/mp4',
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'public, max-age=86400, immutable',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization, X-Requested-With',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges'
  };
  if (upstreamRes.headers['content-length']) {
    headers['Content-Length'] = upstreamRes.headers['content-length'];
  }
  if (upstreamRes.headers['content-range']) {
    headers['Content-Range'] = upstreamRes.headers['content-range'];
  }
  rawRes.writeHead(upstreamRes.statusCode, headers);

  let rangeStart = 0;
  const cr = upstreamRes.headers['content-range'];
  const reqRange = req.headers['range'];

  if (cr) {
    const parts = cr.split(' ');
    if (parts.length === 2) {
      const startStr = parts[1].split('/')[0].split('-')[0];
      const parsed = parseInt(startStr, 10);
      if (!isNaN(parsed)) rangeStart = parsed;
    }
  } else if (reqRange) {
    const startStr = reqRange.replace('bytes=', '').split('-')[0];
    const parsed = parseInt(startStr, 10);
    if (!isNaN(parsed)) rangeStart = parsed;
  }

  // If beyond 64KB, stream directly as plaintext
  if (rangeStart >= 65536) {
    upstreamRes.body.pipe(rawRes);
    return;
  }

  let filename = payload.key;
  if (!filename) {
    const uParts = payload.url.split('?')[0].split('/');
    filename = uParts[uParts.length - 1];
  }
  const hexKey = crypto.createHash('md5').update(filename).digest('hex');
  const keyBytes = Buffer.from(hexKey, 'utf8');
  const ivBytes = keyBytes.subarray(0, 16);

  const decipher = crypto.createDecipheriv('aes-256-ctr', keyBytes, ivBytes);

  // If seeking within the first 64KB, advance decipher keystream to rangeStart
  if (rangeStart > 0) {
    decipher.update(Buffer.alloc(rangeStart));
  }

  let encBytesRemaining = 65536 - rangeStart;

  const transform = new Transform({
    transform(chunk, encoding, callback) {
      if (encBytesRemaining > 0) {
        if (chunk.length <= encBytesRemaining) {
          const dec = decipher.update(chunk);
          encBytesRemaining -= chunk.length;
          callback(null, dec);
        } else {
          const toDec = chunk.subarray(0, encBytesRemaining);
          const plain = chunk.subarray(encBytesRemaining);
          const dec = decipher.update(toDec);
          encBytesRemaining = 0;
          callback(null, Buffer.concat([dec, plain]));
        }
      } else {
        callback(null, chunk);
      }
    }
  });

  upstreamRes.body.pipe(transform).pipe(rawRes);
}

async function registerProxyRoutes(fastify) {
  fastify.get('/p/*', async (req, reply) => {
    req.raw.socket?.setNoDelay(true);
    setCORS(reply);

    const path = req.params['*'] || '';
    if (!path) {
      return reply.code(400).send({ error: 'Missing proxy token' });
    }

    const tokenStr = path.split('/')[0];
    let payload;
    try {
      payload = decryptToken(tokenStr);
    } catch (err) {
      return reply.code(403).send({ error: `Decryption failed: ${err.message}` });
    }

    // Check token expiration
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return reply.code(410).send({ error: 'Token expired' });
    }

    if (req.query.dl === '1' || req.query.download === '1') {
      const dlName = req.query.filename || 'video.mp4';
      reply.header('Content-Disposition', `attachment; filename="${dlName}"`);
    }

    // 1. Abyss Chunked Proxy
    if (payload.cipher === 'abyss-chunked') {
      return handleAbyssChunked(req, reply, payload);
    }

    const targetURL = payload.url;
    let parsedTarget;
    try {
      parsedTarget = new URL(targetURL);
    } catch {
      return reply.code(400).send({ error: 'Invalid target URL' });
    }

    const targetHost = parsedTarget.hostname.toLowerCase();
    if (isPrivateHost(targetHost)) {
      return reply.code(403).send({ error: 'Access denied: target host is private or restricted' });
    }

    const cleanPath = targetURL.split('?')[0].toLowerCase();
    const isM3U8Target = cleanPath.includes('.m3u8');
    const pkParam = req.query.pk || '';
    const isEncrypted = req.query.enc === '1';
    const m3u8CacheKey = `${targetURL}|pk:${pkParam}|enc:${isEncrypted}`;

    // FAST PATH: In-memory M3U8 Cache (< 1ms latency)
    if (isM3U8Target) {
      if (m3u8PlaylistCache.has(m3u8CacheKey)) {
        const entry = m3u8PlaylistCache.get(m3u8CacheKey);
        reply.header('Content-Type', entry.contentType);
        reply.header('Cache-Control', 'no-cache');
        return reply.code(entry.statusCode).send(entry.body);
      }
    }

    // Match CDN rules for header spoofing
    let effectiveReferer = payload.ref || '';
    let effectiveOrigin = '';
    let effectiveSecSite = 'cross-site';

    for (const rule of cdnRules) {
      if (rule.matches(targetHost)) {
        if (!effectiveReferer) effectiveReferer = rule.referer;
        effectiveOrigin = rule.origin;
        effectiveSecSite = rule.secSite;
        break;
      }
    }

    if (!effectiveReferer) {
      effectiveReferer = `${parsedTarget.protocol}//${parsedTarget.host}/`;
    }
    if (!effectiveOrigin) {
      effectiveOrigin = `${parsedTarget.protocol}//${parsedTarget.host}`;
    }

    const upstreamHeaders = {
      'user-agent': DEFAULT_UA,
      referer: effectiveReferer,
      origin: effectiveOrigin,
      'sec-fetch-dest': isM3U8Target ? 'empty' : 'video',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': effectiveSecSite
    };

    if (req.headers['range']) {
      upstreamHeaders['range'] = req.headers['range'];
    }

    const clientIP = getClientIP(req);
    let upstreamRes;
    try {
      upstreamRes = await request(targetURL, {
        method: 'GET',
        headers: upstreamHeaders,
        dispatcher: globalAgent
      });
    } catch (err) {
      return reply.code(502).send({ error: `Upstream gateway error: ${err.message}` });
    }

    const contentType = (upstreamRes.headers['content-type'] || '').toLowerCase();
    const isM3U8 = contentType.includes('mpegurl') || isM3U8Target;

    // 2. M3U8 Playlist Processing & Rewriting
    if (isM3U8) {
      let bodyText = await upstreamRes.body.text();

      // De-XOR if pkParam is present
      if (pkParam && !bodyText.trim().startsWith('#EXTM3U')) {
        try {
          const keyBytes = Buffer.from(pkParam, 'base64');
          if (keyBytes.length > 0) {
            const buf = Buffer.from(bodyText, 'utf8');
            for (let i = 0; i < buf.length; i++) {
              buf[i] ^= keyBytes[i % keyBytes.length];
            }
            bodyText = buf.toString('utf8');
          }
        } catch {}
      }

      const rewritten = rewriteM3U8(
        bodyText,
        targetURL,
        effectiveReferer,
        clientIP,
        payload.exp,
        payload.key,
        pkParam,
        isEncrypted
      );

      if (payload.key && isEncrypted) {
        try {
          const encrypted = encryptPlaylistResponse(rewritten, payload.key);
          m3u8PlaylistCache.set(m3u8CacheKey, {
            body: encrypted,
            contentType: 'text/plain; charset=utf-8',
            statusCode: upstreamRes.statusCode
          });
          reply.header('Content-Type', 'text/plain; charset=utf-8');
          reply.header('Cache-Control', 'no-cache');
          return reply.code(upstreamRes.statusCode).send(encrypted);
        } catch {}
      }

      m3u8PlaylistCache.set(m3u8CacheKey, {
        body: rewritten,
        contentType: 'application/vnd.apple.mpegurl',
        statusCode: upstreamRes.statusCode
      });

      reply.header('Content-Type', 'application/vnd.apple.mpegurl');
      reply.header('Cache-Control', 'no-cache');
      return reply.code(upstreamRes.statusCode).send(rewritten);
    }

    // 3. Abyss CTR Stream Cipher
    if (payload.cipher === 'abyss-ctr') {
      return handleAbyssCTR(req, reply, upstreamRes, payload);
    }

    // 4. Binary Streaming (TS segments, MP4, VTT, WebVTT)
    reply.hijack();
    const rawRes = reply.raw;

    const isVTT = cleanPath.endsWith('.vtt') || cleanPath.includes('/subtitles/');
    const isSRT = cleanPath.endsWith('.srt');
    const isTSSegment = cleanPath.endsWith('.ts') && !req.headers['range'];

    // FAST PATH: Serve TS segment from cache (0ms - memory hit)
    if (isTSSegment) {
      const cached = tsSegmentCache.get(targetURL);
      if (cached) {
        rawRes.writeHead(200, {
          'Content-Type': 'video/mp2t',
          'Content-Length': String(cached.length),
          'Cache-Control': 'public, max-age=600, immutable',
          'Access-Control-Allow-Origin': '*',
          'Accept-Ranges': 'bytes'
        });
        rawRes.end(cached);
        return;
      }
    }

    const outHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization, X-Requested-With',
      'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges',
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public, max-age=86400, immutable'
    };

    if (req.query.dl === '1' || req.query.download === '1') {
      const dlName = req.query.filename || 'video.mp4';
      outHeaders['Content-Disposition'] = `attachment; filename="${dlName}"`;
    }

    if (isVTT) {
      outHeaders['Content-Type'] = 'text/vtt; charset=utf-8';
    } else if (isSRT) {
      outHeaders['Content-Type'] = 'application/x-subrip';
    } else if (contentType) {
      outHeaders['Content-Type'] = contentType;
    } else {
      outHeaders['Content-Type'] = 'application/octet-stream';
    }

    const cl = upstreamRes.headers['content-length'];
    if (cl) {
      outHeaders['Content-Length'] = cl;
    }
    if (upstreamRes.headers['content-range']) {
      outHeaders['Content-Range'] = upstreamRes.headers['content-range'];
    }

    const iterator = upstreamRes.body[Symbol.asyncIterator]();
    const first = await iterator.next();

    if (first.done) {
      rawRes.writeHead(upstreamRes.statusCode, outHeaders);
      rawRes.end();
      return;
    }

    let firstChunk = Buffer.from(first.value);

    if (upstreamRes.statusCode === 200 && !isVTT && !isSRT) {
      // Fake PNG header check (252 bytes)
      if (
        firstChunk.length >= 253 &&
        firstChunk[0] === 0x89 && firstChunk[1] === 0x50 && firstChunk[2] === 0x4E && firstChunk[3] === 0x47 &&
        firstChunk[4] === 0x0D && firstChunk[5] === 0x0A && firstChunk[6] === 0x1A && firstChunk[7] === 0x0A &&
        firstChunk[252] === 0x47
      ) {
        outHeaders['Content-Type'] = 'video/mp2t';
        if (cl) {
          const total = parseInt(cl, 10);
          if (!isNaN(total) && total >= 252) {
            outHeaders['Content-Length'] = String(total - 252);
          }
        }
        firstChunk = firstChunk.subarray(252);
      } else if (firstChunk.length > 0 && firstChunk[0] === 0x47) {
        outHeaders['Content-Type'] = 'video/mp2t';
      }
    }

    rawRes.writeHead(upstreamRes.statusCode, outHeaders);

    // For TS segments: collect into buffer so we can cache AND stream simultaneously
    if (isTSSegment && upstreamRes.statusCode === 200) {
      const chunks = [firstChunk];
      let totalBytes = firstChunk.length;
      if (firstChunk.length > 0) rawRes.write(firstChunk);

      for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
        if (rawRes.destroyed) break;
        chunks.push(chunk);
        totalBytes += chunk.length;
        if (!rawRes.write(chunk)) {
          await new Promise(r => rawRes.once('drain', r));
        }
      }
      rawRes.end();

      // Cache if reasonable segment size (<= 10MB)
      if (totalBytes > 0 && totalBytes <= 10 * 1024 * 1024) {
        const full = Buffer.concat(chunks, totalBytes);
        tsSegmentCache.set(targetURL, full);
      }
      return;
    }

    // Standard streaming for MP4, VTT, SRT etc.
    if (firstChunk.length > 0) rawRes.write(firstChunk);
    for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
      if (rawRes.destroyed) break;
      if (!rawRes.write(chunk)) {
        await new Promise(r => rawRes.once('drain', r));
      }
    }
    rawRes.end();
  });
}

module.exports = {
  registerProxyRoutes
};
