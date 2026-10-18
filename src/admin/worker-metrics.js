'use strict';

/**
 * Worker-side metrics, off by default (ADMIN_METRICS=1 enables).
 *
 * Adds O(1) request counters and a 30 s loopback snapshot POST to the admin
 * collector. No SQLite, no disk I/O and no admin routes run inside the player
 * worker: if the collector is down or slow, snapshots fail fast and playback
 * is unaffected.
 */

const http = require('node:http');
const {
  stats,
  m3u8PlaylistCache,
  tsSegmentCache,
  abyssChunkCache,
  segmentIndex
} = require('../utils/cache');
const { inflightCount } = require('../utils/singleflight');
const pkg = require('../../package.json');

function enabled() {
  return /^(1|true|yes|on)$/i.test(String(process.env.ADMIN_METRICS || '').trim());
}

function integer(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function routeClass(rawUrl) {
  const uri = String(rawUrl || '/').split('?')[0];
  if (uri.startsWith('/p/')) return /\.m3u8$/.test(uri.toLowerCase()) ? 'playlist' : 'seg';
  if (uri === '/embed' || uri.startsWith('/embed/') || uri === '/player' || uri.startsWith('/player/')) return 'embed';
  if (uri === '/api' || uri.startsWith('/api/') || uri.startsWith('/stream/') || uri === '/health') return 'api';
  if (uri === '/docs' || uri === '/') return 'docs';
  if (uri.startsWith('/player-assets/') || uri === '/hls.min.js') return 'asset';
  if (uri === '/telemetry') return 'telemetry';
  if (uri === '/download' || uri.startsWith('/download/') || uri.startsWith('/api/download')) return 'download';
  return 'other';
}

// Whole-request durations are only meaningful for control routes; a segment
// stays open for the entire playback buffer, so counting it as "slow" would
// flag every healthy stream.
const STREAM_ROUTES = new Set(['seg', 'playlist', 'download', 'asset']);

function attach(app) {
  if (!enabled()) return null;

  const port = integer(process.env.PORT, 5001, 1, 65535);
  const workerId = String(process.env.ADMIN_WORKER_ID || `worker-${port}`)
    .replace(/[^a-zA-Z0-9:._-]/g, '')
    .slice(0, 64) || `worker-${port}`;
  const collectorPort = integer(process.env.ADMIN_PORT, 5100, 1, 65535);
  const token = String(process.env.ADMIN_INGEST_TOKEN || '').trim();
  const snapshotMs = integer(process.env.ADMIN_SNAPSHOT_MS, 30000, 5000, 300000);
  const slowMs = integer(process.env.ADMIN_SLOW_MS, 2000, 200, 60000);

  const counters = { requests: 0, req4xx: 0, req5xx: 0, slow: 0 };
  const routes = { seg: 0, playlist: 0, embed: 0, api: 0, docs: 0, asset: 0, telemetry: 0, download: 0, other: 0 };
  const statusClasses = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
  let eventLoopLagMs = 0;
  let lastLoopTick = Date.now();
  let lastCpu = process.cpuUsage();
  let lastCpuAt = Date.now();
  let timer = null;
  let lastWarnAt = 0;
  let sent = 0;
  let failed = 0;

  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });

  app.addHook('onResponse', (req, reply) => {
    const route = routeClass(req.raw.url);
    counters.requests += 1;
    routes[route] = (routes[route] || 0) + 1;
    const code = reply.statusCode;
    if (code >= 500) counters.req5xx += 1;
    else if (code >= 400) counters.req4xx += 1;
    const cls = code >= 500 ? '5xx' : code >= 400 ? '4xx' : code >= 300 ? '3xx' : '2xx';
    statusClasses[cls] += 1;
    if (!STREAM_ROUTES.has(route) && reply.elapsedTime > slowMs) counters.slow += 1;

    // Log slow requests and errors
    if (code >= 500 || (!STREAM_ROUTES.has(route) && reply.elapsedTime > slowMs)) {
      const logBody = {
        ts: Date.now(),
        level: code >= 500 ? 'error' : 'warn',
        source: 'worker',
        kind: code >= 500 ? 'server_error' : 'slow_request',
        message: `${code} ${req.raw.method} ${req.raw.url} (${Math.round(reply.elapsedTime)}ms)`,
        data: {
          worker: workerId,
          route,
          statusCode: code,
          elapsed: Math.round(reply.elapsedTime)
        }
      };
      // Send log to collector
      const logReq = http.request({
        host: '127.0.0.1',
        port: collectorPort,
        path: '/internal/log',
        method: 'POST',
        agent,
        timeout: 2000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(JSON.stringify(logBody)),
          'X-Admin-Token': token
        }
      }, (res) => {
        res.resume();
      });
      logReq.on('error', () => {});
      logReq.on('timeout', () => logReq.destroy());
      logReq.end(JSON.stringify(logBody));
    }
  });

  const loopTimer = setInterval(() => {
    const now = Date.now();
    const lag = Math.max(0, now - lastLoopTick - 1000);
    if (lag > eventLoopLagMs) eventLoopLagMs = lag;
    lastLoopTick = now;
  }, 1000);
  loopTimer.unref();

  function warn(message) {
    const now = Date.now();
    if (now - lastWarnAt < 60000) return;
    lastWarnAt = now;
    console.error(`[admin-metrics] ${message}`);
  }

  function buildSnapshot() {
    const now = Date.now();
    const mem = process.memoryUsage();
    const cpu = process.cpuUsage(lastCpu);
    const elapsedMs = Math.max(1, now - lastCpuAt);
    const cpuPct = ((cpu.user + cpu.system) / 1000 / elapsedMs) * 100;
    lastCpu = process.cpuUsage();
    lastCpuAt = now;

    const snapshot = {
      worker: workerId,
      port,
      requests: counters.requests,
      req4xx: counters.req4xx,
      req5xx: counters.req5xx,
      slow: counters.slow,
      inflight: inflightCount(),
      rssMB: Math.round((mem.rss / 1024 / 1024) * 10) / 10,
      heapMB: Math.round((mem.heapUsed / 1024 / 1024) * 10) / 10,
      cpuPct: Math.round(Math.min(100, Math.max(0, cpuPct)) * 10) / 10,
      elagMs: eventLoopLagMs,
      cacheHits: stats.segmentHits,
      cacheUpstream: stats.segmentUpstream,
      prefetch: stats.prefetchInflight || 0,
      clientInflight: stats.clientInflight || 0,
      cacheMB: Math.round((tsSegmentCache.calculatedSize || 0) / 1024 / 1024),
      uptimeS: Math.round(process.uptime()),
      version: pkg.version,
      data: {
        routes: { ...routes },
        status: { ...statusClasses },
        cacheSizes: {
          m3u8: m3u8PlaylistCache.size,
          segments: tsSegmentCache.size,
          abyssChunks: abyssChunkCache.size,
          segmentIndex: segmentIndex.size
        }
      }
    };

    counters.requests = 0;
    counters.req4xx = 0;
    counters.req5xx = 0;
    counters.slow = 0;
    for (const key of Object.keys(routes)) routes[key] = 0;
    for (const key of Object.keys(statusClasses)) statusClasses[key] = 0;
    eventLoopLagMs = 0;
    return snapshot;
  }

  function send() {
    if (!token) {
      warn('ADMIN_INGEST_TOKEN is empty; snapshots not sent');
      return;
    }
    const body = Buffer.from(JSON.stringify(buildSnapshot()));
    const req = http.request({
      host: '127.0.0.1',
      port: collectorPort,
      path: '/internal/snapshot',
      method: 'POST',
      agent,
      timeout: 2000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': body.length,
        'X-Admin-Token': token
      }
    }, (res) => {
      res.resume();
      if (res.statusCode === 204) sent += 1;
      else { failed += 1; warn(`collector returned ${res.statusCode}`); }
    });
    req.on('timeout', () => req.destroy(new Error('collector timeout')));
    req.on('error', (error) => {
      failed += 1;
      warn(`snapshot failed: ${error.message}`);
    });
    req.end(body);
  }

  timer = setInterval(send, snapshotMs);
  timer.unref();
  send();

  app.addHook('onClose', () => {
    if (timer) clearInterval(timer);
    clearInterval(loopTimer);
    agent.destroy();
  });

  return {
    workerId,
    snapshot: send,
    state: () => ({ sent, failed, snapshotMs, workerId })
  };
}

module.exports = { attach, enabled, routeClass };
