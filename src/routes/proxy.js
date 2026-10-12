const { request } = require('undici');
const crypto = require('node:crypto');
const { Transform } = require('node:stream');

const { cdnRules, isPrivateHost } = require('../../config');
const { decryptToken, encryptPlaylistResponse, genSoraToken } = require('../utils/crypto');
const { rewriteM3U8, resolveAbsoluteURL } = require('../utils/m3u8');
const { m3u8PlaylistCache, tsSegmentCache, abyssChunkCache, segmentIndex, stats } = require('../utils/cache');
const { globalAgent, DEFAULT_UA } = require('../utils/http');

// Segment engine tunables
const SEGMENT_BUFFER_CAP = 8 * 1024 * 1024;     // Cache segments up to 8MB (reduced from 16MB); larger = passthrough stream
const ABYSS_MAX_CACHED_CHUNK = 8 * 1024 * 1024; // Abyss chunks are ~5MB; 8MB is sufficient (reduced from 12MB)
const PREFETCH_LOOKAHEAD = 8;                   // Prefetch next 8 segments (~1 min ahead of playhead, reduced from 15)
const PREFETCH_MAX_INFLIGHT = 4;                // Global concurrent prefetch cap (reduced from 6 for less memory pressure)
const BODY_STALL_MS = parseInt(process.env.BODY_STALL_MS || '30000', 10); // Abort upstream bodies that go silent (tunable)
const PREFETCH_YIELD_POLL_MS = 50;              // Re-check client traffic every 50ms (reduced from 100ms for faster response)

const segFlight = new Map();   // Dedupe concurrent fetches (segments + abyss chunks, prefixed keys)
const prefetchSet = new Set(); // Prefetch de-dup guard
let prefetchInflight = 0;
let clientInflight = 0;        // Prefetches yield to real client traffic

// Periodic cleanup for flight maps to prevent memory buildup
setInterval(() => {
  // Clean up orphaned flights that should have been deleted
  const now = Date.now();
  for (const [key, flight] of segFlight.entries()) {
    // If flight is stale (no promise status), remove it
    // This handles edge cases where the finally block didn't execute
    if (flight && typeof flight.then !== 'function') {
      segFlight.delete(key);
    }
  }
  // Clean up stale prefetch entries
  prefetchSet.clear(); // Clear all - prefetches are short-lived anyway
}, 60 * 1000); // Every minute

/**
 * Wraps an upstream body iterator with an inactivity timeout: if no chunk
 * arrives for BODY_STALL_MS the body is destroyed so the pending next()
 * rejects instead of hanging the request forever.
 */
function timedIterator(body) {
  const iterator = body[Symbol.asyncIterator]();
  let timer = null;
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      try { body.destroy(); } catch {}
    }, BODY_STALL_MS);
  };
  arm();
  return {
    [Symbol.asyncIterator]() { return this; },
    next() {
      return iterator.next().then(
        (v) => {
          if (v.done) clearTimeout(timer); else arm();
          return v;
        },
        (err) => {
          clearTimeout(timer);
          throw err;
        }
      );
    },
    return() {
      clearTimeout(timer);
      return iterator.return ? iterator.return() : Promise.resolve({ done: true });
    },
    // Used by prefetches that pause mid-stream while clients have priority:
    // disarm the stall timer during the pause, re-arm it when reading resumes.
    disarm() {
      clearTimeout(timer);
      timer = null;
    },
    touch() {
      arm();
    }
  };
}

async function readBodyText(body) {
  const chunks = [];
  let total = 0;
  for await (const chunk of timedIterator(body)) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    chunks.push(buf);
    total += buf.length;
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

function waitDrain(rawRes) {
  return new Promise((resolve) => {
    const done = () => {
      rawRes.off('drain', done);
      rawRes.off('close', done);
      rawRes.off('error', done);
      resolve();
    };
    rawRes.once('drain', done);
    rawRes.once('close', done);
    rawRes.once('error', done);
  });
}

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  return req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.socket?.remoteAddress || '127.0.0.1';
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, Content-Type, Authorization, X-Requested-With',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges',
    'Accept-Ranges': 'bytes'
  };
}

function setCORS(reply) {
  reply.header('Access-Control-Allow-Origin', '*');
  reply.header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  reply.header('Access-Control-Allow-Headers', 'Range, Content-Type, Authorization, X-Requested-With');
  reply.header('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges');
  reply.header('Accept-Ranges', 'bytes');
}

function isFakePngTs(buf) {
  return (
    buf.length >= 253 &&
    buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 &&
    buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A &&
    buf[252] === 0x47
  );
}

/**
 * Normalizes a buffered media body: strips fake PNG prefixes from disguised
 * TS segments (kira CDN serves .jpg/.html that are really MPEG-TS) and picks
 * the right Content-Type.
 */
function normalizeSegmentBody(buf, upstreamHeaders) {
  let body = buf;
  let contentType = (upstreamHeaders['content-type'] || '').toLowerCase();
  if (isFakePngTs(buf)) {
    body = buf.subarray(252);
    contentType = 'video/mp2t';
  } else if (buf.length > 0 && buf[0] === 0x47) {
    contentType = 'video/mp2t';
  }
  if (!contentType) contentType = 'application/octet-stream';
  return { body, contentType };
}

async function fetchSegmentRaw(targetURL, headers) {
  return request(targetURL, {
    method: 'GET',
    headers,
    dispatcher: globalAgent
  });
}

/**
 * Buffers an upstream segment response up to SEGMENT_BUFFER_CAP bytes while
 * fanning the arriving chunks out to every registered waiter (clients that
 * joined an in-flight prefetch). A waiter joining mid-flight gets the buffered
 * prefix replayed first so it always receives the COMPLETE segment from byte 0
 * (a tail-only body would break hls.js TS parsing and trigger error loops).
 * Prefetch-origin flights pause while real client traffic is in flight.
 * Returns { kind: 'buffered', body } or { kind: 'stream', iterator, chunks }
 * when the payload is too large.
 */
async function bufferAndFanout(upstreamRes, flight) {
  const waiters = flight.waiters;
  const cl = parseInt(upstreamRes.headers['content-length'] || '0', 10);
  const iterator = timedIterator(upstreamRes.body);
  if (cl > SEGMENT_BUFFER_CAP) {
    return { kind: 'stream', upstreamRes, iterator, chunks: [] };
  }

  const chunks = [];
  let total = 0;
  try {
    while (true) {
      // Bandwidth priority: a prefetch with no client attached pauses while
      // any client fetch is in flight (clients' own segments stream unthrottled).
      while (clientInflight > 0 && waiters.length === 0) {
        iterator.disarm();
        await new Promise((r) => setTimeout(r, PREFETCH_YIELD_POLL_MS));
        iterator.touch();
      }

      const { done, value } = await iterator.next();
      if (done) break;
      const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);

      if (!flight.overCap) {
        chunks.push(buf);
        total += buf.length;
        if (total > SEGMENT_BUFFER_CAP) {
          flight.overCap = true;
          chunks.length = 0;
          total = 0;
          // No client is receiving this uncacheable body and no new waiter
          // can join now — abort instead of draining a huge payload.
          if (waiters.length === 0) {
            try { upstreamRes.body.destroy(); } catch {}
            return { kind: 'stream', upstreamRes, iterator, chunks: [], streamConsumed: true };
          }
        }
      }

      for (let i = waiters.length - 1; i >= 0; i--) {
        const w = waiters[i];
        if (!w || w.rawRes.destroyed) {
          waiters.splice(i, 1);
          continue;
        }
        try {
          if (!w.headersSent) {
            w.headersSent = true;
            const first = chunks.length ? chunks[0] : buf;
            let ct = (upstreamRes.headers['content-type'] || 'application/octet-stream').toLowerCase();
            let strip = 0;
            if (upstreamRes.statusCode === 200 && isFakePngTs(first)) {
              ct = 'video/mp2t';
              strip = 252;
            } else if (first.length > 0 && first[0] === 0x47) {
              ct = 'video/mp2t';
            }
            w.rawRes.writeHead(upstreamRes.statusCode || 200, {
              'Content-Type': ct,
              'Cache-Control': 'public, max-age=86400, immutable',
              ...corsHeaders(),
              ...(w.extraHeaders || {})
            });
            if (first.length > strip && !w.rawRes.write(first.subarray(strip))) await waitDrain(w.rawRes);
            for (let j = 1; j < chunks.length; j++) {
              if (w.rawRes.destroyed) break;
              if (!w.rawRes.write(chunks[j])) await waitDrain(w.rawRes);
            }
          } else if (buf.length > 0 && !w.rawRes.write(buf)) {
            await waitDrain(w.rawRes);
          }
        } catch {
          waiters.splice(i, 1);
        }
      }
    }

    for (const w of waiters) {
      // Waiters that never got headers are served the full buffered body by
      // handleSegmentRequest once the flight completes.
      if (w && w.headersSent && !w.rawRes.destroyed && !w.rawRes.writableEnded) w.rawRes.end();
    }
    waiters.length = 0;
  } catch (err) {
    for (const w of waiters) {
      try { if (!w.rawRes.destroyed) w.rawRes.destroy(); } catch {}
    }
    waiters.length = 0;
    throw err;
  }

  if (flight.overCap) {
    return { kind: 'stream', upstreamRes, iterator, chunks: [], streamConsumed: true };
  }
  return { kind: 'buffered', upstreamRes, body: Buffer.concat(chunks, total) };
}

/**
 * Streams the upstream segment to the creator client WHILE filling the buffer
 * pool: the player receives bytes progressively (fast start / fast seeks) and
 * the full body lands in tsSegmentCache when done. Late-joining clients
 * (waiters) get the buffered prefix replayed then the live tail fanned out —
 * every client receives the complete segment. Oversized bodies (> cap) stop
 * accumulating and become a plain passthrough stream.
 */
async function teeSegmentToClient(upstreamRes, tee, flight) {
  const rawRes = tee.rawRes;
  const waiters = flight.waiters;
  const headers = {
    'Content-Type': (upstreamRes.headers['content-type'] || 'application/octet-stream').toLowerCase(),
    'Cache-Control': 'public, max-age=86400, immutable',
    ...corsHeaders(),
    ...(tee.extraHeaders || {})
  };
  const clHeader = upstreamRes.headers['content-length'];
  const cl = parseInt(clHeader || '0', 10);
  const iterator = timedIterator(upstreamRes.body);

  let chunks = [];
  let total = 0;
  let overCap = cl > SEGMENT_BUFFER_CAP;
  let sniffed = false;
  let strip = 0;

  async function fanToWaiters(buf) {
    for (let i = waiters.length - 1; i >= 0; i--) {
      const w = waiters[i];
      if (!w || w.rawRes.destroyed) {
        waiters.splice(i, 1);
        continue;
      }
      try {
        if (!w.headersSent) {
          w.headersSent = true;
          const first = chunks.length ? chunks[0] : buf;
          let ct = (upstreamRes.headers['content-type'] || 'application/octet-stream').toLowerCase();
          let wstrip = 0;
          if (upstreamRes.statusCode === 200 && isFakePngTs(first)) {
            ct = 'video/mp2t';
            wstrip = 252;
          } else if (first.length > 0 && first[0] === 0x47) {
            ct = 'video/mp2t';
          }
          w.rawRes.writeHead(upstreamRes.statusCode || 200, {
            'Content-Type': ct,
            'Cache-Control': 'public, max-age=86400, immutable',
            ...corsHeaders(),
            ...(w.extraHeaders || {})
          });
          if (first.length > wstrip && !w.rawRes.write(first.subarray(wstrip))) await waitDrain(w.rawRes);
          for (let j = 1; j < chunks.length; j++) {
            if (w.rawRes.destroyed) break;
            if (!w.rawRes.write(chunks[j])) await waitDrain(w.rawRes);
          }
        } else if (buf.length > 0 && !w.rawRes.write(buf)) {
          await waitDrain(w.rawRes);
        }
      } catch {
        waiters.splice(i, 1);
      }
    }
  }

  try {
    while (true) {
      const { done, value } = await iterator.next();
      if (done) break;
      const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);

      if (!sniffed) {
        sniffed = true;
        if (upstreamRes.statusCode === 200 && isFakePngTs(buf)) {
          headers['Content-Type'] = 'video/mp2t';
          strip = 252;
        } else if (buf.length > 0 && buf[0] === 0x47) {
          headers['Content-Type'] = 'video/mp2t';
        }
        if (clHeader) {
          const t = parseInt(clHeader, 10);
          if (!isNaN(t)) headers['Content-Length'] = String(Math.max(0, t - strip));
        } else if (upstreamRes.headers['content-range']) {
          headers['Content-Range'] = upstreamRes.headers['content-range'];
        }
        if (!rawRes.headersSent && !rawRes.destroyed) {
          rawRes.writeHead(upstreamRes.statusCode || 200, headers);
        }
      }

      if (!overCap) {
        chunks.push(buf);
        total += buf.length;
        if (total > SEGMENT_BUFFER_CAP) {
          overCap = true;
          flight.overCap = true;
          chunks = [];
          total = 0;
        }
      }

      await fanToWaiters(buf);

      const out = strip > 0 ? buf.subarray(strip) : buf;
      if (out.length > 0 && !rawRes.destroyed) {
        if (!rawRes.write(out)) await waitDrain(rawRes);
      } else if (overCap && waiters.length === 0) {
        // Creator gone, nothing cacheable left, nobody else listening — abort.
        try { upstreamRes.body.destroy(); } catch {}
        break;
      }
    }

    if (!rawRes.writableEnded && !rawRes.destroyed) rawRes.end();
    for (const w of waiters) {
      if (w && w.headersSent && !w.rawRes.destroyed && !w.rawRes.writableEnded) w.rawRes.end();
    }
    waiters.length = 0;
  } catch (err) {
    for (const w of waiters) {
      try { if (!w.rawRes.destroyed) w.rawRes.destroy(); } catch {}
    }
    waiters.length = 0;
    throw err;
  }

  if (overCap || !sniffed) {
    return { kind: 'stream', upstreamRes, iterator, chunks: [], streamConsumed: true };
  }
  return { kind: 'buffered', upstreamRes, body: Buffer.concat(chunks, total), streamConsumed: true };
}

/**
 * Singleflight segment fetch: while one request is in flight (client or
 * prefetch), everyone else shares its result instead of hitting the CDN again.
 * The creator optionally tees the body straight to its client while buffering;
 * late-joining clients (waiters) of a prefetch-origin flight get the arriving
 * chunks fanned out to them progressively.
 */
function startSegmentFlight(cacheKey, targetURL, headers, tee) {
  const flight = (async () => {
    stats.segmentUpstream++;
    const upstreamRes = await fetchSegmentRaw(targetURL, headers);

    const upCT = (upstreamRes.headers['content-type'] || '').toLowerCase();
    if (upCT.includes('mpegurl')) {
      try { upstreamRes.body.destroy(); } catch {}
      const e = new Error('Playlist served from a media-shaped URL');
      e.code = 'IS_PLAYLIST';
      throw e;
    }

    const result = tee
      ? await teeSegmentToClient(upstreamRes, tee, flight)
      : await bufferAndFanout(upstreamRes, flight);
    result.statusCode = upstreamRes.statusCode;

    if (result.kind === 'buffered') {
      result.entry = normalizeSegmentBody(result.body, upstreamRes.headers);
      if (upstreamRes.statusCode === 200) {
        tsSegmentCache.set(cacheKey, result.entry);
      }
    }
    return result;
  })();

  flight.creatorTee = Boolean(tee);
  flight.waiters = [];
  flight.overCap = false;
  segFlight.set(cacheKey, flight);
  flight.then(() => segFlight.delete(cacheKey), () => segFlight.delete(cacheKey));
  return flight;
}

/**
 * Streams an upstream media body to the client, stripping a fake PNG prefix
 * from the first chunk if present. Used for oversized passthrough responses.
 */
async function streamSegmentResponse(rawRes, upstreamRes, iterator, prefixChunks, extraHeaders) {
  const headers = {
    'Content-Type': (upstreamRes.headers['content-type'] || 'application/octet-stream').toLowerCase(),
    'Cache-Control': 'public, max-age=86400, immutable',
    ...corsHeaders(),
    ...(extraHeaders || {})
  };

  let prefix = prefixChunks && prefixChunks.length ? prefixChunks : null;
  let firstChunk;
  if (prefix) {
    firstChunk = prefix[0];
  } else {
    const n = await iterator.next();
    if (n.done) {
      const cl = upstreamRes.headers['content-length'];
      if (cl) headers['Content-Length'] = cl;
      rawRes.writeHead(upstreamRes.statusCode || 200, headers);
      rawRes.end();
      return;
    }
    firstChunk = Buffer.isBuffer(n.value) ? n.value : Buffer.from(n.value);
  }

  let stripBytes = 0;
  if (upstreamRes.statusCode === 200 && isFakePngTs(firstChunk)) {
    headers['Content-Type'] = 'video/mp2t';
    stripBytes = 252;
  } else if (firstChunk.length > 0 && firstChunk[0] === 0x47) {
    headers['Content-Type'] = 'video/mp2t';
  }

  const cl = upstreamRes.headers['content-length'];
  if (cl) {
    const total = parseInt(cl, 10);
    if (!isNaN(total)) headers['Content-Length'] = String(Math.max(0, total - stripBytes));
  }
  if (upstreamRes.headers['content-range']) {
    headers['Content-Range'] = upstreamRes.headers['content-range'];
  }

  rawRes.writeHead(upstreamRes.statusCode || 200, headers);

  if (firstChunk.length > stripBytes) rawRes.write(firstChunk.subarray(stripBytes));
  if (prefix) {
    for (let i = 1; i < prefix.length; i++) {
      if (rawRes.destroyed) return;
      if (!rawRes.write(prefix[i])) {
        await waitDrain(rawRes);
      }
    }
  }
  for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
    if (rawRes.destroyed) break;
    if (!rawRes.write(chunk)) {
      await waitDrain(rawRes);
    }
  }
  if (!rawRes.writableEnded) rawRes.end();
}

/**
 * Serves a segment-candidate request: memory cache -> deduped flight (creator
 * tees to its client while caching) -> oversize passthrough. Returns true when
 * the response was fully handled.
 */
async function handleSegmentRequest(req, reply, targetURL, upstreamHeaders, dlName) {
  const extraHeaders = dlName ? { 'Content-Disposition': `attachment; filename="${dlName}"` } : undefined;

  const cached = tsSegmentCache.get(targetURL);
  if (cached) {
    stats.segmentHits++;
    reply.hijack();
    const rawRes = reply.raw;
    rawRes.writeHead(200, {
      'Content-Type': cached.contentType,
      'Content-Length': String(cached.body.length),
      'Cache-Control': 'public, max-age=86400, immutable',
      ...corsHeaders(),
      ...(extraHeaders || {})
    });
    rawRes.end(cached.body);
    notifySegmentServed(targetURL);
    return true;
  }

  clientInflight++;
  stats.clientInflight = clientInflight;
  let notifyURL = null;
  try {
    const existing = segFlight.get(targetURL);
    const isCreator = !existing;
    // Join any in-flight flight as a fanned waiter: receive the buffered
    // prefix replayed + the live tail, so this client streams progressively
    // and still gets the complete segment (fast seeks into the prefetch
    // window AND concurrent clients on the same segment).
    const waiter = !isCreator && existing && !existing.overCap
      ? { rawRes: reply.raw, extraHeaders, headersSent: false }
      : null;
    if (waiter) existing.waiters.push(waiter);

    const flight = existing || startSegmentFlight(targetURL, targetURL, upstreamHeaders, {
      rawRes: reply.raw,
      extraHeaders
    });

    let result;
    try {
      result = await flight;
    } catch (err) {
      if (err.code === 'IS_PLAYLIST') return false;
      if (!reply.raw.headersSent) {
        reply.code(502).send({ error: `Upstream gateway error: ${err.message}` });
      } else if (!reply.raw.writableEnded) {
        reply.raw.destroy();
      }
      return true;
    }

    if (result.kind === 'buffered') {
      // Creator already streamed its copy during the fetch; fanned waiters
      // received the body chunk by chunk; a waiter that joined at the very
      // end (never got headers) serves the shared buffer now.
      if (!isCreator && result.entry && (!waiter || !waiter.headersSent) && !reply.raw.destroyed && !reply.raw.writableEnded) {
        const entry = result.entry;
        reply.hijack();
        const rawRes = reply.raw;
        rawRes.writeHead(result.statusCode || 200, {
          'Content-Type': entry.contentType,
          'Content-Length': String(entry.body.length),
          'Cache-Control': 'public, max-age=86400, immutable',
          ...corsHeaders(),
          ...(extraHeaders || {})
        });
        rawRes.end(entry.body);
      } else if (waiter && waiter.headersSent && !reply.raw.destroyed && !reply.raw.writableEnded) {
        reply.raw.end();
      }
      notifyURL = targetURL;
      return true;
    }

    // Oversized stream result
    if (result.streamConsumed) {
      if (isCreator) return true; // already proxied by the tee
      if (waiter && waiter.headersSent) return true; // already fanned out
      return passthroughSegment(targetURL, upstreamHeaders, reply, extraHeaders);
    }
    if (!result.claimed) {
      result.claimed = true;
      reply.hijack();
      try {
        await streamSegmentResponse(reply.raw, result.upstreamRes, result.iterator, result.chunks, extraHeaders);
      } catch {
        if (!reply.raw.writableEnded) reply.raw.destroy();
      }
      return true;
    }
    return passthroughSegment(targetURL, upstreamHeaders, reply, extraHeaders);
  } finally {
    clientInflight--;
    stats.clientInflight = clientInflight;
    if (notifyURL) notifySegmentServed(notifyURL);
  }
}

async function passthroughSegment(targetURL, upstreamHeaders, reply, extraHeaders) {
  let freshRes;
  try {
    freshRes = await fetchSegmentRaw(targetURL, upstreamHeaders);
  } catch (err) {
    if (!reply.raw.headersSent) {
      reply.code(502).send({ error: `Upstream gateway error: ${err.message}` });
    }
    return true;
  }
  reply.hijack();
  try {
    await streamSegmentResponse(reply.raw, freshRes, timedIterator(freshRes.body), [], extraHeaders);
  } catch {
    if (!reply.raw.writableEnded) reply.raw.destroy();
  }
  return true;
}

function extractSegmentURLs(text, baseURL) {
  const urls = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let cand = null;
    if (trimmed.startsWith('#')) {
      const m = trimmed.match(/URI="([^"]+)"/);
      if (!m) continue;
      cand = m[1];
    } else {
      cand = trimmed;
    }
    const abs = resolveAbsoluteURL(cand, baseURL);
    const clean = abs.split('?')[0].toLowerCase();
    if (clean.includes('.m3u8') || clean.includes('.key')) continue;
    if (clean.endsWith('.vtt') || clean.endsWith('.srt')) continue;
    urls.push(abs);
  }
  return urls;
}

/**
 * Background prefetch: fills tsSegmentCache for upcoming segments so the
 * player's next requests are served from memory (~0ms). Yields to real client
 * traffic and shares in-flight fetches with clients (never double-fetches).
 */
function prefetchSegment(url, headers) {
  if (!url || !headers) return;
  if (tsSegmentCache.has(url) || prefetchSet.has(url)) return;
  if (clientInflight > 0) return; // player traffic has priority
  if (prefetchInflight >= PREFETCH_MAX_INFLIGHT) return;
  prefetchInflight++;
  stats.prefetchInflight = prefetchInflight;
  prefetchSet.add(url);
  stats.segmentPrefetch++;

  const flight = segFlight.get(url) || startSegmentFlight(url, url, headers, null);
  flight.then((result) => {
    if (result && result.kind === 'stream' && !result.streamConsumed && !result.claimed) {
      // Oversized body nobody claimed — release it after a grace period.
      setTimeout(() => {
        if (!result.claimed) {
          try { result.upstreamRes.body.destroy(); } catch {}
        }
      }, 15000);
    }
  }).catch(() => {}).finally(() => {
    prefetchInflight--;
    stats.prefetchInflight = prefetchInflight;
    prefetchSet.delete(url);
  });
}

/**
 * Warms the segments AFTER `skip`: the player's own request for the first
 * segment(s) must stay a creator tee (progressive first bytes), while the
 * immediately following segments land in cache before the player asks for them.
 */
function warmSegments(entry, skip, count) {
  if (!entry || !entry.segments) return;
  const end = Math.min(skip + count, entry.segments.length);
  for (let i = skip; i < end; i++) {
    prefetchSegment(entry.segments[i], entry.upstreamHeaders);
  }
}

/**
 * After a segment is served, prefetch the next N segments of its playlist.
 */
function notifySegmentServed(servedURL) {
  const info = segmentIndex.get(servedURL);
  if (!info) return;
  const entry = m3u8PlaylistCache.get(info.playlistKey);
  if (!entry || !entry.segments) return;
  for (let i = 1; i <= PREFETCH_LOOKAHEAD; i++) {
    const next = entry.segments[info.idx + i];
    if (!next) break;
    prefetchSegment(next, entry.upstreamHeaders);
  }
}

// --- Abyss (haiku) chunked video ---

function abyssUpstreamHeaders() {
  return {
    'user-agent': DEFAULT_UA,
    referer: 'https://abyssplayer.com/',
    origin: 'https://abyssplayer.com',
    connection: 'keep-alive',
    'sec-fetch-dest': 'video',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site'
  };
}

function buildAbyssChunkURL(payload, totalSize, chunkSize, idx) {
  const soraPath = `/mp4/${payload.mid}/${payload.rid}/${totalSize}/${chunkSize}/${idx}`;
  const soraToken = genSoraToken(soraPath, totalSize);
  return `https://${payload.dom}/sora/${totalSize}/${soraToken}`;
}

function abyssChunkCacheKey(payload, totalSize, chunkSize, idx) {
  return `a|${payload.dom}|${payload.mid}|${payload.rid}|${totalSize}|${chunkSize}|${idx}`;
}

/**
 * Buffers a full abyss chunk up to ABYSS_MAX_CACHED_CHUNK; larger responses
 * degrade to a plain stream (never cached).
 */
async function bufferAbyssChunk(upstreamRes) {
  const iterator = timedIterator(upstreamRes.body);
  const chunks = [];
  let total = 0;
  while (true) {
    // Prefetch-only fetch: yield bandwidth to live client traffic.
    while (clientInflight > 0) {
      iterator.disarm();
      await new Promise((r) => setTimeout(r, PREFETCH_YIELD_POLL_MS));
      iterator.touch();
    }
    const { done, value } = await iterator.next();
    if (done) break;
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
    chunks.push(buf);
    total += buf.length;
    if (total > ABYSS_MAX_CACHED_CHUNK) {
      return { kind: 'stream', upstreamRes, iterator, chunks };
    }
  }
  return { kind: 'buffered', upstreamRes, body: Buffer.concat(chunks, total) };
}

/**
 * Streams the requested byte window [a..b] inside an abyss chunk to the client
 * WHILE buffering the whole chunk for the cache. The player gets its bytes
 * progressively (fast start / fast seeks) and the chunk lands in memory.
 */
async function teeAbyssChunk(upstreamRes, tee) {
  const rawRes = tee.rawRes;
  const a = tee.a;
  const b = tee.b;
  const iterator = timedIterator(upstreamRes.body);

  let chunks = [];
  let total = 0;
  let overCap = false;
  let offset = 0;

  while (true) {
    const { done, value } = await iterator.next();
    if (done) break;
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);

    if (!overCap) {
      chunks.push(buf);
      total += buf.length;
      if (total > ABYSS_MAX_CACHED_CHUNK) { overCap = true; chunks = []; total = 0; }
    }

    const lo = Math.max(a, offset);
    const hi = Math.min(b, offset + buf.length - 1);
    if (hi >= lo && !rawRes.destroyed) {
      const slice = buf.subarray(lo - offset, hi - offset + 1);
      if (slice.length > 0 && !rawRes.write(slice)) await waitDrain(rawRes);
    } else if (rawRes.destroyed && overCap) {
      // Client gone AND nothing cacheable is being collected — abort upstream.
      try { upstreamRes.body.destroy(); } catch {}
      break;
    }
    offset += buf.length;
  }

  if (overCap) {
    return { kind: 'stream', upstreamRes, iterator, chunks: [], streamConsumed: true };
  }
  return { kind: 'buffered', upstreamRes, body: Buffer.concat(chunks, total), streamConsumed: true };
}

/**
 * Singleflight abyss chunk fetch: concurrent client requests and prefetches for
 * the same chunk share one upstream download; the creator tees to its client.
 */
function startAbyssChunkFlight(payload, totalSize, chunkSize, idx, tee) {
  const key = abyssChunkCacheKey(payload, totalSize, chunkSize, idx);
  const flight = (async () => {
    stats.segmentUpstream++;
    const cStartByte = idx * chunkSize;
    let cEndByte = cStartByte + chunkSize - 1;
    if (cEndByte >= totalSize) cEndByte = totalSize - 1;

    const chunkURL = buildAbyssChunkURL(payload, totalSize, chunkSize, idx);
    const upstreamRes = await request(chunkURL, {
      method: 'GET',
      headers: { ...abyssUpstreamHeaders(), range: `bytes=0-${cEndByte - cStartByte}` },
      dispatcher: globalAgent
    });
    if (upstreamRes.statusCode >= 400) {
      try { upstreamRes.body.destroy(); } catch {}
      throw new Error(`Abyss chunk upstream status ${upstreamRes.statusCode}`);
    }

    const result = tee ? await teeAbyssChunk(upstreamRes, tee) : await bufferAbyssChunk(upstreamRes);
    if (result.kind === 'buffered' && result.body.length <= ABYSS_MAX_CACHED_CHUNK) {
      abyssChunkCache.set(key, result.body);
    }
    return result;
  })();

  segFlight.set(key, flight);
  flight.then(() => segFlight.delete(key), () => segFlight.delete(key));
  return flight;
}

function notifyAbyssServed(payload, totalSize, chunkSize, idx) {
  // Prefetch the next 2 chunks (~10MB) ahead of the playhead.
  for (let ahead = 1; ahead <= 2; ahead++) {
    const nextIdx = idx + ahead;
    if (nextIdx * chunkSize >= totalSize) break;
    const key = abyssChunkCacheKey(payload, totalSize, chunkSize, nextIdx);
    if (abyssChunkCache.has(key) || segFlight.has(key) || prefetchSet.has(key)) continue;
    if (clientInflight > 0) return; // player traffic has priority
    if (prefetchInflight >= PREFETCH_MAX_INFLIGHT) return;
    prefetchInflight++;
    stats.prefetchInflight = prefetchInflight;
    prefetchSet.add(key);
    stats.segmentPrefetch++;

    const flight = segFlight.get(key) || startAbyssChunkFlight(payload, totalSize, chunkSize, nextIdx, null);
    flight.then((result) => {
      if (result && result.kind === 'stream' && !result.streamConsumed && !result.claimed) {
        // Oversized body nobody claimed — release it after a grace period.
        setTimeout(() => {
          if (!result.claimed) {
            try { result.upstreamRes.body.destroy(); } catch {}
          }
        }, 15000);
      }
    }).catch(() => {}).finally(() => {
      prefetchInflight--;
      stats.prefetchInflight = prefetchInflight;
      prefetchSet.delete(key);
    });
  }
}

async function streamAbyssChunksLegacy(payload, totalSize, chunkSize, start, end, rawRes) {
  const startChunkIdx = Math.floor(start / chunkSize);
  const endChunkIdx = Math.floor(end / chunkSize);

  for (let idx = startChunkIdx; idx <= endChunkIdx; idx++) {
    if (rawRes.destroyed) return;

    const cStartByte = idx * chunkSize;
    let cEndByte = cStartByte + chunkSize - 1;
    if (cEndByte >= totalSize) cEndByte = totalSize - 1;

    let reqStartInChunk = 0;
    if (start > cStartByte) reqStartInChunk = start - cStartByte;

    let reqEndInChunk = cEndByte - cStartByte;
    if (end < cEndByte) reqEndInChunk = end - cStartByte;

    const chunkURL = buildAbyssChunkURL(payload, totalSize, chunkSize, idx);
    try {
      const upstreamRes = await request(chunkURL, {
        method: 'GET',
        headers: { ...abyssUpstreamHeaders(), range: `bytes=${reqStartInChunk}-${reqEndInChunk}` },
        dispatcher: globalAgent
      });
      for await (const chunk of timedIterator(upstreamRes.body)) {
        if (rawRes.destroyed) return;
        if (!rawRes.write(chunk)) {
          await waitDrain(rawRes);
        }
      }
    } catch {
      break;
    }
  }
}

/**
 * Handles Abyss Chunked (Type B) video proxying with Sora tokens and range
 * clamping. Full chunks are memory-cached (768MB pool) with next-chunk prefetch.
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

  // Rare layouts with huge chunks exceed the cache budget — stream them directly.
  if (chunkSize > ABYSS_MAX_CACHED_CHUNK) {
    await streamAbyssChunksLegacy(payload, totalSize, chunkSize, start, end, rawRes);
    rawRes.end();
    return;
  }

  // The clamped range always lives inside a single chunk.
  const idx = Math.floor(start / chunkSize);
  const a = start - idx * chunkSize;
  const b = end - idx * chunkSize;
  const key = abyssChunkCacheKey(payload, totalSize, chunkSize, idx);

  const cached = abyssChunkCache.get(key);
  if (cached) {
    stats.segmentHits++;
    const slice = cached.subarray(a, b + 1);
    if (slice.length > 0 && !rawRes.destroyed && !rawRes.write(slice)) {
      await waitDrain(rawRes);
    }
    if (!rawRes.destroyed && !rawRes.writableEnded) rawRes.end();
    notifyAbyssServed(payload, totalSize, chunkSize, idx);
    return;
  }

  clientInflight++;
  stats.clientInflight = clientInflight;
  let served = false;
  try {
    const existing = segFlight.get(key);
    const isCreator = !existing;
    const flight = existing || startAbyssChunkFlight(payload, totalSize, chunkSize, idx, { rawRes, a, b });
    let result = null;
    try {
      result = await flight;
    } catch {}

    if (result) {
      served = true;
      if (result.kind === 'buffered') {
        // Creator: the tee already delivered the requested bytes progressively.
        if (!isCreator) {
          const slice = result.body.subarray(a, b + 1);
          if (slice.length > 0 && !rawRes.destroyed && !rawRes.write(slice)) {
            await waitDrain(rawRes);
          }
        }
      } else if (!isCreator) {
        await streamAbyssChunksLegacy(payload, totalSize, chunkSize, start, end, rawRes);
      }
    }
  } finally {
    clientInflight--;
    stats.clientInflight = clientInflight;
    if (served) notifyAbyssServed(payload, totalSize, chunkSize, idx);
    if (!rawRes.destroyed && !rawRes.writableEnded) rawRes.end();
  }
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

    let dlName = null;
    if (req.query.dl === '1' || req.query.download === '1') {
      dlName = String(req.query.filename || 'video.mp4').replace(/[^\w.\-() ]/g, '_');
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

    // 2. Segment Engine — content-agnostic memory cache + dedupe + lookahead
    // prefetch. Applies to any media-shaped GET without a Range header:
    // plain .ts, disguised .jpg/.html TS chunks, fMP4 .m4s, .mp4, etc.
    const isKeyFile = cleanPath.endsWith('.key');
    const isVTTish = cleanPath.endsWith('.vtt') || cleanPath.endsWith('.srt') || cleanPath.includes('/subtitles/');
    const isSegmentCandidate =
      req.method === 'GET' &&
      !isM3U8Target &&
      !payload.cipher &&
      !req.headers['range'] &&
      !isVTTish &&
      !isKeyFile;

    if (isSegmentCandidate) {
      const handled = await handleSegmentRequest(req, reply, targetURL, upstreamHeaders, dlName);
      if (handled) return;
    }

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

    // 3. M3U8 Playlist Processing & Rewriting
    if (isM3U8) {
      let bodyText = await readBodyText(upstreamRes.body);

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

      let responseBody = rewritten;
      let responseContentType = 'application/vnd.apple.mpegurl';
      if (payload.key && isEncrypted) {
        try {
          responseBody = encryptPlaylistResponse(rewritten, payload.key);
          responseContentType = 'text/plain; charset=utf-8';
        } catch {
          responseBody = rewritten;
          responseContentType = 'application/vnd.apple.mpegurl';
        }
      }

      // Index segment URLs so served segments can trigger lookahead prefetches
      const segURLs = extractSegmentURLs(bodyText, targetURL);
      const playlistEntry = {
        body: responseBody,
        contentType: responseContentType,
        statusCode: upstreamRes.statusCode,
        segments: segURLs.length ? segURLs : undefined,
        upstreamHeaders
      };
      m3u8PlaylistCache.set(m3u8CacheKey, playlistEntry);

      if (segURLs.length) {
        for (let i = 0; i < segURLs.length; i++) {
          segmentIndex.set(segURLs[i], { playlistKey: m3u8CacheKey, idx: i });
        }
        // Warm the segments right after the first: the player's own request for
        // segment 0 stays a tee (instant first bytes), 1..4 land in cache.
        warmSegments(playlistEntry, 1, 4);
      }

      reply.header('Content-Type', responseContentType);
      reply.header('Cache-Control', 'no-cache');
      return reply.code(upstreamRes.statusCode).send(responseBody);
    }

    // 4. Abyss CTR Stream Cipher
    if (payload.cipher === 'abyss-ctr') {
      return handleAbyssCTR(req, reply, upstreamRes, payload);
    }

    // 5. Binary Streaming (Range requests, VTT/SRT subtitles, HEAD probes)
    reply.hijack();
    const rawRes = reply.raw;

    const isVTT = cleanPath.endsWith('.vtt') || cleanPath.includes('/subtitles/');
    const isSRT = cleanPath.endsWith('.srt');
    const isTSSegment = cleanPath.endsWith('.ts') && !req.headers['range'];

    const outHeaders = {
      ...corsHeaders(),
      'Cache-Control': 'public, max-age=86400, immutable'
    };

    if (dlName) {
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

    const iterator = timedIterator(upstreamRes.body);
    const first = await iterator.next();

    if (first.done) {
      rawRes.writeHead(upstreamRes.statusCode, outHeaders);
      rawRes.end();
      return;
    }

    let firstChunk = Buffer.from(first.value);

    if (upstreamRes.statusCode === 200 && !isVTT && !isSRT) {
      if (isFakePngTs(firstChunk)) {
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

    // Fallback cache-fill for .ts bodies that reach the raw stream path
    // (e.g. HEAD probes); regular segment GETs are handled by the segment engine.
    if (isTSSegment && upstreamRes.statusCode === 200) {
      const chunks = [firstChunk];
      let totalBytes = firstChunk.length;
      if (firstChunk.length > 0) rawRes.write(firstChunk);

      for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
        if (rawRes.destroyed) break;
        chunks.push(chunk);
        totalBytes += chunk.length;
        if (!rawRes.write(chunk)) {
          await waitDrain(rawRes);
        }
      }
      rawRes.end();

      if (totalBytes > 0 && totalBytes <= SEGMENT_BUFFER_CAP) {
        tsSegmentCache.set(targetURL, { body: Buffer.concat(chunks, totalBytes), contentType: 'video/mp2t' });
      }
      return;
    }

    // Standard streaming for MP4, VTT, SRT etc.
    if (firstChunk.length > 0) rawRes.write(firstChunk);
    for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) {
      if (rawRes.destroyed) break;
      if (!rawRes.write(chunk)) {
        await waitDrain(rawRes);
      }
    }
    rawRes.end();
  });
}

module.exports = {
  registerProxyRoutes,
  _internals: {
    timedIterator,
    bufferAndFanout,
    // Test hook: simulate concurrent client traffic for the prefetch yield gate.
    _setClientInflight: (n) => { clientInflight = n; }
  }
};
