const { request } = require('undici');
const crypto = require('node:crypto');
const { Readable, Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');

const { cdnRules, isPrivateHost } = require('../../config');
const { decryptToken, encryptPlaylistResponse } = require('../utils/crypto');
const { rewriteM3U8 } = require('../utils/m3u8');
const { m3u8PlaylistCache, stats } = require('../utils/cache');
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
 * Handles Abyss Chunked (Type B) video proxying with range clamping (5MB per request)
 */
async function handleAbyssChunked(req, reply, payload) {
  const totalSize = payload.ts || 0;
  const chunkSize = payload.cs || 5242880;

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

  // Cap range response to at most 1 chunk (5MB) per HTTP request
  let chunkEnd = (Math.floor(start / chunkSize) + 1) * chunkSize - 1;
  if (chunkEnd >= totalSize) chunkEnd = totalSize - 1;
  if (end > chunkEnd) end = chunkEnd;

  if (start > end || start >= totalSize) {
    reply.header('Content-Range', `bytes */${totalSize}`);
    return reply.code(416).send('Requested range not satisfiable');
  }

  const contentLength = end - start + 1;
  reply.code(206);
  reply.header('Content-Type', 'video/mp4');
  reply.header('Accept-Ranges', 'bytes');
  reply.header('Content-Length', String(contentLength));
  reply.header('Content-Range', `bytes ${start}-${end}/${totalSize}`);
  reply.header('Cache-Control', 'public, max-age=86400, immutable');

  const startChunkIdx = Math.floor(start / chunkSize);
  const endChunkIdx = Math.floor(end / chunkSize);

  const rawRes = reply.raw;

  for (let idx = startChunkIdx; idx <= endChunkIdx; idx++) {
    if (rawRes.destroyed) return;

    const cStartByte = idx * chunkSize;
    const cEndByte = cStartByte + chunkSize - 1;
    let actualCEnd = cEndByte;
    if (actualCEnd >= totalSize) actualCEnd = totalSize - 1;

    let partIdx = idx + 1;
    if (payload.ps && payload.ps > 0) {
      partIdx = Math.floor(cStartByte / payload.ps) + 1;
    }

    let chunkURL = payload.url;
    if (payload.dom) {
      chunkURL = `https://${payload.dom}/${payload.mid}_${payload.rid}/${partIdx}.mp4`;
    }

    const cReqRange = `bytes=${cStartByte}-${actualCEnd}`;
    try {
      const upstreamRes = await request(chunkURL, {
        method: 'GET',
        headers: {
          'user-agent': DEFAULT_UA,
          referer: 'https://abyssplayer.com/',
          origin: 'https://abyssplayer.com',
          range: cReqRange
        },
        dispatcher: globalAgent
      });

      const chunkBuffer = Buffer.from(await upstreamRes.body.arrayBuffer());

      let sliceStart = 0;
      let sliceEnd = chunkBuffer.length;

      if (start > cStartByte) {
        sliceStart = start - cStartByte;
      }
      if (end < actualCEnd) {
        sliceEnd = sliceStart + (end - Math.max(start, cStartByte) + 1);
      }

      if (sliceStart < chunkBuffer.length) {
        const toSend = chunkBuffer.subarray(sliceStart, Math.min(sliceEnd, chunkBuffer.length));
        if (!rawRes.write(toSend)) {
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
  reply.header('Content-Type', 'video/mp4');
  reply.header('Accept-Ranges', 'bytes');
  if (upstreamRes.headers['content-length']) {
    reply.header('Content-Length', upstreamRes.headers['content-length']);
  }
  if (upstreamRes.headers['content-range']) {
    reply.header('Content-Range', upstreamRes.headers['content-range']);
  }
  reply.code(upstreamRes.statusCode);

  const rawRes = reply.raw;
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
    Readable.fromWeb(upstreamRes.body).pipe(rawRes);
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

  Readable.fromWeb(upstreamRes.body).pipe(transform).pipe(rawRes);
}

async function registerProxyRoutes(fastify) {
  fastify.get('/p/*', async (req, reply) => {
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
    const isVTT = cleanPath.endsWith('.vtt') || cleanPath.includes('/subtitles/');
    const isSRT = cleanPath.endsWith('.srt');

    if (isVTT) {
      reply.header('Content-Type', 'text/vtt; charset=utf-8');
    } else if (isSRT) {
      reply.header('Content-Type', 'application/x-subrip');
    } else if (contentType) {
      reply.header('Content-Type', contentType);
    } else {
      reply.header('Content-Type', 'application/octet-stream');
    }

    reply.header('Cache-Control', 'public, max-age=86400, immutable');
    if (upstreamRes.headers['content-length']) {
      reply.header('Content-Length', upstreamRes.headers['content-length']);
    }
    if (upstreamRes.headers['content-range']) {
      reply.header('Content-Range', upstreamRes.headers['content-range']);
    }

    reply.code(upstreamRes.statusCode);

    const rawRes = reply.raw;
    const bodyStream = Readable.fromWeb(upstreamRes.body);

    // PNG Header Stripping Transform Stream
    let firstChunkChecked = false;
    let isFakePNG = false;

    const pngStripper = new Transform({
      transform(chunk, encoding, callback) {
        if (!firstChunkChecked) {
          firstChunkChecked = true;
          // Check for PNG magic: \x89PNG\r\n\x1a\n and byte 252 == 0x47 (TS sync byte)
          if (
            chunk.length >= 253 &&
            chunk[0] === 0x89 && chunk[1] === 0x50 && chunk[2] === 0x4E && chunk[3] === 0x47 &&
            chunk[4] === 0x0D && chunk[5] === 0x0A && chunk[6] === 0x1A && chunk[7] === 0x0A &&
            chunk[252] === 0x47
          ) {
            isFakePNG = true;
            if (!rawRes.headersSent) {
              rawRes.setHeader('Content-Type', 'video/mp2t');
              const cl = upstreamRes.headers['content-length'];
              if (cl) {
                const total = parseInt(cl, 10);
                if (!isNaN(total) && total >= 252) {
                  rawRes.setHeader('Content-Length', String(total - 252));
                }
              }
            }
            callback(null, chunk.subarray(252));
            return;
          }

          if (chunk.length > 0 && chunk[0] === 0x47) {
            if (!rawRes.headersSent) {
              rawRes.setHeader('Content-Type', 'video/mp2t');
            }
          }
        }
        callback(null, chunk);
      }
    });

    bodyStream.pipe(pngStripper).pipe(rawRes);
  });
}

module.exports = {
  registerProxyRoutes
};
