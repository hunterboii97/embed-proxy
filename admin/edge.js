'use strict';

const fs = require('node:fs');
const { emptyEdgeBucket } = require('./store');

const LATENCY_BUCKETS = [10, 50, 100, 250, 500, 1000, 2500, 5000];
const ROUTE_FIELD = {
  seg: 'route_seg',
  playlist: 'route_playlist',
  embed: 'route_embed',
  api: 'route_api',
  docs: 'route_docs',
  asset: 'route_asset',
  telemetry: 'route_telemetry',
  download: 'route_download',
  other: 'route_other'
};

function classifyPath(uri) {
  if (uri.startsWith('/p/')) {
    const clean = uri.split('?')[0].toLowerCase();
    return /\.m3u8$/.test(clean) ? 'playlist' : 'seg';
  }
  if (uri === '/embed' || uri.startsWith('/embed/') || uri === '/player' || uri.startsWith('/player/')) return 'embed';
  if (uri === '/api' || uri.startsWith('/api/') || uri.startsWith('/stream/') || uri === '/health') return 'api';
  if (uri === '/docs' || uri === '/') return 'docs';
  if (uri.startsWith('/player-assets/') || uri === '/hls.min.js') return 'asset';
  if (uri === '/telemetry') return 'telemetry';
  if (uri === '/download' || uri.startsWith('/download/') || uri.startsWith('/api/download')) return 'download';
  return 'other';
}

function providerOf(uri) {
  if (/^\/(?:embed|player)\/(?:zoko|naoka)(?:\/|$)/.test(uri)) return 'zoko';
  if (/^\/(?:embed|player)\/(?:haiku|animesalt|salt|as-cdn|haiku-cdn)(?:\/|$)/.test(uri)) return 'haiku';
  if (/^\/(?:embed|player)\/(?:kira|megaplay)(?:\/|$)/.test(uri)) return 'kira';
  return 'other';
}

function latencyIndex(ms) {
  for (let i = 0; i < LATENCY_BUCKETS.length; i++) {
    if (ms <= LATENCY_BUCKETS[i]) return i;
  }
  return LATENCY_BUCKETS.length - 1;
}

function normalizeHost(value) {
  try {
    const host = new URL(value).hostname.toLowerCase().replace(/^www\./, '');
    return host.replace(/\.$/, '');
  } catch {
    return '';
  }
}

function originFromReferer(referer, requestHost, ignoreOrigins) {
  if (!referer) return '';
  let host;
  try {
    host = new URL(String(referer)).hostname.toLowerCase();
  } catch {
    return '';
  }
  host = host.replace(/^www\./, '').replace(/\.$/, '');
  if (!host || host.length > 253) return '';
  if (!/^[a-z0-9.-]+$/.test(host)) return '';
  if (host === requestHost || ignoreOrigins.has(host)) return '';
  return host;
}

function safePath(uri) {
  const clean = String(uri || '').split('?')[0].slice(0, 300);
  if (clean.startsWith('/p/')) {
    return clean.replace(/^\/p\/[^/]+\/?/, '/p/<token>/');
  }
  return clean;
}

function bucketLatency(bucket, ms) {
  bucket.rt_sum += ms;
  if (ms > bucket.rt_max) bucket.rt_max = ms;
  bucket[`rt_b${latencyIndex(ms)}`] += 1;
}

function addLine(bucket, line, now) {
  const status = Number(line.status) || 0;
  const bytes = Math.max(0, Number(line.bytes) || 0);
  const ms = Math.max(0, Math.min(600000, (Number(line.rt) || 0) * 1000));
  const uri = String(line.uri || '/');
  const method = String(line.m || 'GET').toUpperCase();
  const route = classifyPath(uri);

  bucket.requests += 1;
  bucket.bytes += bytes;
  if (status >= 500) bucket.s5xx += 1;
  else if (status >= 400) bucket.s4xx += 1;
  else if (status >= 300) bucket.s3xx += 1;
  else if (status >= 200) bucket.s2xx += 1;
  if (status === 403) bucket.s403 += 1;
  else if (status === 404) bucket.s404 += 1;
  else if (status === 429) bucket.s429 += 1;
  else if (status === 499) bucket.s499 += 1;
  else if (status === 502) bucket.s502 += 1;

  const cache = String(line.cache || '').toUpperCase();
  if (cache === 'BYPASS') bucket.cache_bypass += 1;
  else if (cache === 'MISS' || cache === 'EXPIRED') bucket.cache_miss += 1;
  else if (cache === 'HIT' || cache === 'STALE' || cache === 'UPDATING' || cache === 'REVALIDATED') {
    bucket.cache_hit += 1;
  }

  bucketLatency(bucket, ms);
  bucket[ROUTE_FIELD[route]] = (bucket[ROUTE_FIELD[route]] || 0) + 1;

  const provider = route === 'embed' ? providerOf(uri) : '';
  if (provider && provider !== 'other') bucket[`p_${provider}`] = (bucket[`p_${provider}`] || 0) + 1;

  return { status, bytes, ms, uri, method, route, cache, provider, ts: now };
}

function createEdgeIngestor({ config, store, logger }) {
  const ignoreOrigins = new Set(config.ignoreOrigins.map((h) => h.toLowerCase().replace(/^www\./, '')));
  const edgeHosts = new Set(config.edgeHosts.map((h) => h.toLowerCase()));
  let workerTimer = null;
  let currentMinute = null;
  let bucket = emptyEdgeBucket();
  let originAgg = new Map();
  let bufferedEvents = [];
  let partial = '';
  let offset = 0;
  let inode = null;
  let pollTimer = null;
  let lastPollAt = 0;
  let lastLineAt = 0;
  let lastPositionSave = 0;
  let lastError = '';
  let running = false;
  let droppedLogs = 0;
  let logSecond = 0;
  let logSecondCount = 0;
  let fd = null;
  let flushing = false;

  const stats = {
    enabled: Boolean(config.edgeLogPath),
    path: config.edgeLogPath,
    lines: 0,
    parsed: 0,
    bad: 0,
    running: false,
    lastLineAt: 0,
    lastPollAt: 0,
    error: '',
    droppedLogs: 0,
    startedAt: Date.now()
  };

  function persistPosition(force = false) {
    const now = Date.now();
    if (!force && now - lastPositionSave < 10000) return;
    lastPositionSave = now;
    try {
      if (inode != null) store.setMeta('edge_inode', inode);
      store.setMeta('edge_offset', offset);
    } catch { /* best effort */ }
  }

  function restorePosition(stat) {
    const savedInode = store.getMeta('edge_inode');
    const savedOffset = Number(store.getMeta('edge_offset'));
    if (savedInode != null && String(savedInode) === String(stat.ino)) {
      offset = Number.isFinite(savedOffset) && savedOffset >= 0 && savedOffset <= stat.size ? savedOffset : stat.size;
    } else if (savedInode == null) {
      // First run: start at the current end, don't ingest a huge backlog.
      offset = stat.size;
    } else {
      // Rotated file: ingest the new file from the beginning.
      offset = 0;
    }
    inode = stat.ino;
    persistPosition(true);
  }

  function logRecord(record, force) {
    if (!force) {
      const second = Math.floor(record.ts / 1000);
      if (second !== logSecond) { logSecond = second; logSecondCount = 0; }
      if (logSecondCount >= 60) { droppedLogs += 1; return; }
      logSecondCount += 1;
    }
    const level = record.status >= 500 ? 'error'
      : record.status >= 400 || record.ms >= 1000 ? 'warn'
        : 'info';
    bufferedEvents.push({
      ts: record.ts,
      level,
      source: 'edge',
      kind: 'request',
      message: `${record.method} ${safePath(record.uri)} -> ${record.status} ${Math.round(record.ms)}ms${record.cache ? ` ${record.cache}` : ''}`,
      data: {
        path: safePath(record.uri),
        status: record.status,
        ms: Math.round(record.ms),
        cache: record.cache || '',
        group: record.route,
        host: String(record.host || '').slice(0, 100),
        origin: record.origin || '',
        provider: record.provider || ''
      }
    });
  }

  function flushEvents() {
    if (!bufferedEvents.length) return;
    const events = bufferedEvents;
    bufferedEvents = [];
    try { store.insertEvents(events); } catch (error) { lastError = error.message; }
  }

  function flushBucket() {
    if (currentMinute == null) return;
    if (flushing) return;
    flushing = true;
    try {
      store.flushEdge(currentMinute, bucket);
      if (originAgg.size) {
        store.flushOriginMinute(currentMinute, Array.from(originAgg.values()));
      }
      currentMinute = null;
      bucket = emptyEdgeBucket();
      originAgg = new Map();
    } catch (error) {
      lastError = error.message;
    } finally {
      flushing = false;
    }
  }

  function addToMinute(minute, line) {
    if (currentMinute == null) currentMinute = minute;
    if (minute > currentMinute) {
      flushEvents();
      flushBucket();
      currentMinute = minute;
    }
    if (minute < currentMinute) {
      // Late line from a previous minute (log backlog). Fold into the current
      // bucket rather than rewriting an already-flushed row.
      minute = currentMinute;
    }
    const record = addLine(bucket, line, Date.now());
    record.ts = minute * 60000;
    record.host = String(line.host || '').toLowerCase();

    if (line.ref && record.route === 'embed' && record.method === 'GET' && record.status === 200) {
      const host = normalizeHost(`http://${record.host || 'x'}`);
      const origin = originFromReferer(line.ref, host, ignoreOrigins);
      if (origin) {
        record.origin = origin;
        const key = `${origin}|${record.provider}`;
        const entry = originAgg.get(key) || { origin, provider: record.provider, requests: 0 };
        entry.requests += 1;
        originAgg.set(key, entry);
      } else {
        record.origin = '';
      }
    }

    // Persist errors, slow requests and a fraction of normal traffic. Rate
    // limiting in nginx produces 403/404 storms; sampling keeps the DB bounded.
    if (record.route === 'embed') {
      logRecord(record, false);
    } else if (record.status >= 500 || record.status === 429 || record.ms >= 1000) {
      logRecord(record, false);
    } else if (record.status >= 400) {
      if (Math.random() < 0.05) logRecord(record, false);
    } else if (Math.random() < config.logSample) {
      logRecord(record, false);
    }
  }

  function processText(text, now) {
    if (!text) return;
    const lines = text.split('\n');
    partial = lines.pop() || '';
    if (partial.length > 65536) partial = '';
    for (const raw of lines) {
      if (!raw) continue;
      stats.lines += 1;
      let line;
      try {
        line = JSON.parse(raw);
      } catch {
        stats.bad += 1;
        continue;
      }
      if (!line || typeof line.uri !== 'string') { stats.bad += 1; continue; }
      if (edgeHosts.size) {
        const host = String(line.host || '').toLowerCase();
        if (!edgeHosts.has(host)) continue;
      }
      const ts = Number(line.ts) > 0 ? Number(line.ts) * 1000 : now;
      const minute = Math.floor(ts / 60000);
      addToMinute(minute, line);
      stats.parsed += 1;
      lastLineAt = Date.now();
    }
  }

  function poll() {
    if (!running || !config.edgeLogPath) return;
    lastPollAt = Date.now();
    stats.lastPollAt = lastPollAt;
    try {
      let stat;
      try {
        stat = fs.statSync(config.edgeLogPath);
      } catch (error) {
        if (lastError !== error.message) {
          lastError = error.message;
          logger(`[edge] cannot stat ${config.edgeLogPath}: ${error.message}`, 'warn');
        }
        return;
      }
      if (!fd || inode !== stat.ino) {
        if (fd) { try { fs.closeSync(fd); } catch { /* ignore */ } fd = null; }
        fd = fs.openSync(config.edgeLogPath, 'r');
        restorePosition(stat);
      }
      if (stat.size < offset) {
        offset = 0;
        persistPosition(true);
      }
      // Live minute rollover without waiting for the next request.
      if (currentMinute != null && Date.now() >= (currentMinute + 1) * 60000) {
        flushEvents();
        flushBucket();
        persistPosition(true);
      }

      let budget = 8 * 1024 * 1024;
      while (budget > 0 && offset < stat.size) {
        const toRead = Math.min(1024 * 1024, stat.size - offset, budget);
        const buffer = Buffer.allocUnsafe(toRead);
        const bytes = fs.readSync(fd, buffer, 0, toRead, offset);
        if (!bytes) break;
        offset += bytes;
        budget -= bytes;
        processText(partial + buffer.toString('utf8', 0, bytes), Date.now());
      }
      if (lastError) lastError = '';
      if (bufferedEvents.length > 300) flushEvents();
      persistPosition();
      stats.error = '';
    } catch (error) {
      if (lastError !== error.message) {
        lastError = error.message;
        logger(`[edge] ingest error: ${error.message}`, 'error');
      }
      stats.error = error.message;
    }
  }

  function start() {
    if (!config.edgeLogPath) {
      stats.running = false;
      return;
    }
    try {
      const stat = fs.statSync(config.edgeLogPath);
      fd = fs.openSync(config.edgeLogPath, 'r');
      restorePosition(stat);
      running = true;
      stats.running = true;
      pollTimer = setInterval(poll, 2000);
      pollTimer.unref();
      workerTimer = setInterval(flushEvents, 1000);
      workerTimer.unref();
      poll();
      logger(`[edge] tailing ${config.edgeLogPath} from offset ${offset}`);
    } catch (error) {
      stats.error = error.message;
      lastError = error.message;
      logger(`[edge] disabled: ${error.message}`, 'warn');
    }
  }

  function stop() {
    running = false;
    stats.running = false;
    if (pollTimer) clearInterval(pollTimer);
    if (workerTimer) clearInterval(workerTimer);
    flushEvents();
    flushBucket();
    persistPosition(true);
    if (fd) { try { fs.closeSync(fd); } catch { /* ignore */ } fd = null; }
  }

  function live() {
    const now = Date.now();
    const liveBucket = currentMinute != null ? bucket : emptyEdgeBucket();
    return {
      minute: currentMinute,
      elapsedMs: currentMinute != null ? Math.max(1000, now - currentMinute * 60000) : 0,
      bucket: liveBucket,
      origins: Array.from(originAgg.values()),
      lastLineAt,
      configured: Boolean(config.edgeLogPath)
    };
  }

  return {
    start,
    stop,
    poll,
    live,
    stats: () => ({
      ...stats,
      lastLineAt,
      offset,
      droppedLogs,
      error: lastError
    })
  };
}

module.exports = {
  createEdgeIngestor,
  classifyPath,
  providerOf,
  latencyIndex,
  LATENCY_BUCKETS
};
