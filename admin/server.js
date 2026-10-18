'use strict';

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { compileAllowlist, resolveClientIP, isAllowed, safeEqual, sendNotFound, applySecurityHeaders } = require('./security');
const aggregate = require('./aggregate');

const STATIC_FILES = {
  '/admin/assets/style.css': 'text/css; charset=utf-8',
  '/admin/assets/app.js': 'application/javascript; charset=utf-8',
  '/admin/assets/charts.js': 'application/javascript; charset=utf-8'
};

function sanitizePath(value) {
  return String(value || '').split('?')[0].slice(0, 160);
}

function maskIP(ip) {
  if (!ip) return '';
  if (ip.includes(':')) {
    const parts = ip.split(':').filter(Boolean);
    return `${parts.slice(0, 3).join(':')}::x`;
  }
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.x.x`;
  return 'x';
}

function createAdminServer({ config, store, edge, ingest, alerts, system, logger }) {
  const allowlist = compileAllowlist(config.allowedIPs);
  const staticCache = new Map();
  const sseClients = new Set();
  let server = null;
  let tickTimer = null;
  let deniedCount = 0;
  let lastDeniedLog = 0;
  let startedAt = Date.now();

  if (allowlist.invalid.length) {
    logger(`[admin] ignoring invalid ADMIN_ALLOWED_IPS entries: ${allowlist.invalid.join(', ')}`, 'warn');
  }
  for (const [url, mime] of Object.entries(STATIC_FILES)) {
    const file = path.join(__dirname, 'public', url.replace('/admin/assets/', ''));
    try {
      staticCache.set(url, { body: fs.readFileSync(file), mime });
    } catch (error) {
      logger(`[admin] missing static asset ${file}: ${error.message}`, 'error');
    }
  }
  try {
    staticCache.set('/admin', {
      body: fs.readFileSync(path.join(__dirname, 'public', 'index.html')),
      mime: 'text/html; charset=utf-8'
    });
  } catch (error) {
    logger(`[admin] missing index.html: ${error.message}`, 'error');
  }

  function send(res, status, contentType, body, extraHeaders = {}) {
    if (res.headersSent) return;
    const buffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    res.writeHead(status, {
      'Content-Type': contentType,
      'Content-Length': buffer.length,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    });
    res.end(buffer);
  }

  function sendJson(res, status, payload) {
    send(res, status, 'application/json; charset=utf-8', JSON.stringify(payload));
  }

  function noteDenied(req, ip, pathname) {
    deniedCount += 1;
    const now = Date.now();
    if (now - lastDeniedLog < 10000) return;
    lastDeniedLog = now;
    try {
      store.insertEvents([{
        ts: now,
        level: 'warn',
        source: 'collector',
        kind: 'admin_denied',
        message: `Blocked admin request from ${maskIP(ip)} to ${sanitizePath(pathname)}`,
        data: { ip: maskIP(ip), path: sanitizePath(pathname) }
      }]);
    } catch { /* best effort */ }
  }

  function readBody(req, maxBytes) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      let settled = false;
      req.on('data', (chunk) => {
        if (settled) return;
        size += chunk.length;
        if (size > maxBytes) {
          settled = true;
          reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
          req.removeAllListeners('data');
          req.resume();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      });
      req.on('error', (error) => {
        if (settled) return;
        settled = true;
        reject(error);
      });
    });
  }

  function requireAdmin(req, res, pathname) {
    const ip = resolveClientIP(req);
    if (isAllowed(ip, allowlist)) return true;
    noteDenied(req, ip, pathname);
    sendNotFound(res);
    return false;
  }

  function rangeParam(url, fallback = '24h') {
    const range = String(url.searchParams.get('range') || fallback);
    return aggregate.RANGES[range] ? range : fallback;
  }

  function sseBroadcast() {
    if (!sseClients.size) return;
    const now = Date.now();
    const active = ingest.activeSessions();
    const workers = ingest.workerSummary();
    const alertList = alerts.list();
    const payload = JSON.stringify({
      ts: now,
      activeViewers: active.active,
      onlineWorkers: workers.online,
      expectedWorkers: workers.expected,
      alerts: alertList.filter((alert) => alert.level !== 'info').length,
      critical: alertList.filter((alert) => alert.level === 'critical').length
    });
    for (const res of sseClients) {
      try {
        res.write(`event: tick\ndata: ${payload}\n\n`);
      } catch {
        sseClients.delete(res);
      }
    }
  }

  function handleSse(req, res) {
    if (req.method !== 'GET') return sendNotFound(res);
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    res.write('retry: 10000\n\n');
    res.write(`event: ready\ndata: {"ts":${Date.now()}}\n\n`);
    sseClients.add(res);
    const ping = setInterval(() => {
      try { res.write(': ping\n\n'); } catch { /* closed */ }
    }, 15000);
    ping.unref();
    const cleanup = () => {
      clearInterval(ping);
      sseClients.delete(res);
    };
    req.on('close', cleanup);
    res.on('close', cleanup);
  }

  async function handleTelemetry(req, res) {
    if (req.method !== 'POST') return sendNotFound(res);
    const ip = resolveClientIP(req);
    let payload = null;
    try {
      const raw = await readBody(req, 8192);
      if (raw) payload = JSON.parse(raw);
    } catch {
      payload = null;
    }
    try {
      if (payload) ingest.handleTelemetry(payload, ip, Date.now());
    } catch (error) {
      logger(`[telemetry] ${error.message}`, 'warn');
    }
    send(res, 204, 'text/plain; charset=utf-8', '');
  }

  async function handleSnapshot(req, res) {
    if (req.method !== 'POST') return sendNotFound(res);
    const ip = resolveClientIP(req);
    if (!config.ingestToken || !safeEqual(req.headers['x-admin-token'], config.ingestToken)) {
      return sendNotFound(res);
    }
    if (!requireLoopback(req, res)) return;
    let body;
    try {
      body = JSON.parse(await readBody(req, 65536));
    } catch {
      return sendJson(res, 400, { error: 'invalid snapshot' });
    }
    if (!ingest.acceptSnapshot(body, ip)) {
      return sendJson(res, 400, { error: 'invalid snapshot' });
    }
    send(res, 204, 'text/plain; charset=utf-8', '');
  }

  function requireLoopback(req, res) {
    const socketIP = req.socket && req.socket.remoteAddress;
    const { isLoopback } = require('./security');
    if (isLoopback(socketIP)) return true;
    const ip = resolveClientIP(req);
    if (isLoopback(ip)) return true;
    sendNotFound(res);
    return false;
  }

  function handleAdminApi(req, res, url) {
    const pathname = url.pathname;
    applySecurityHeaders(res);
    if (pathname === '/admin/api/events') return handleSse(req, res);
    if (req.method !== 'GET') return sendNotFound(res);

    try {
      if (pathname === '/admin/api/overview') {
        return sendJson(res, 200, aggregate.getOverview({
          store, edge, ingest, config, alerts: alerts.list()
        }));
      }
      if (pathname === '/admin/api/traffic') {
        return sendJson(res, 200, aggregate.getTraffic(store, edge, rangeParam(url), Date.now()));
      }
      if (pathname === '/admin/api/origins') {
        const range = ['1h', '6h', '24h', '7d', 'all'].includes(url.searchParams.get('range'))
          ? url.searchParams.get('range') : '24h';
        return sendJson(res, 200, aggregate.getOrigins(store, ingest, range, edge));
      }
      if (pathname === '/admin/api/providers') {
        return sendJson(res, 200, aggregate.getProviders(store, ingest, rangeParam(url), edge));
      }
      if (pathname === '/admin/api/workers') {
        return sendJson(res, 200, aggregate.getWorkers(store, ingest, config));
      }
      if (pathname === '/admin/api/system') {
        return sendJson(res, 200, aggregate.getSystem(store, config, ingest, edge));
      }
      if (pathname === '/admin/api/logs') {
        return sendJson(res, 200, aggregate.getLogs(store, {
          limit: url.searchParams.get('limit'),
          level: url.searchParams.get('level'),
          source: url.searchParams.get('source'),
          q: url.searchParams.get('q'),
          before: url.searchParams.get('before')
        }));
      }
      if (pathname === '/admin/api/security') {
        return sendJson(res, 200, aggregate.getSecurity(store, rangeParam(url), edge));
      }
      if (pathname === '/admin/api/data') {
        return sendJson(res, 200, aggregate.getData(store, config, {
          edge: edge.stats(),
          ingest: ingest.stats(),
          lastPrune: store.lastPrune || null
        }));
      }
      if (pathname === '/admin/api/health') {
        return sendJson(res, 200, {
          ok: true,
          ts: Date.now(),
          uptimeMs: Date.now() - startedAt,
          node: process.version,
          version: config.version,
          dbSizeMB: Math.round((store.dbSizeBytes() / 1024 / 1024) * 10) / 10,
          deniedRequests: deniedCount,
          sseClients: sseClients.size,
          edge: edge.stats(),
          ingest: ingest.stats(),
          workers: ingest.workerSummary(),
          system: system.latest()
        });
      }
      return sendNotFound(res);
    } catch (error) {
      logger(`[admin] ${pathname} failed: ${error.stack || error.message}`, 'error');
      return sendJson(res, 500, { error: 'collector query failed' });
    }
  }

  function handleRequest(req, res) {
    const url = new URL(req.url || '/', 'http://localhost');
    const pathname = url.pathname;

    if (pathname.startsWith('/admin')) {
      if (!requireAdmin(req, res, pathname)) return;
      if (pathname === '/admin' || pathname === '/admin/') {
        const asset = staticCache.get('/admin');
        if (!asset) return sendNotFound(res);
        applySecurityHeaders(res);
        return send(res, 200, asset.mime, asset.body);
      }
      if (STATIC_FILES[pathname]) {
        const asset = staticCache.get(pathname);
        if (!asset) return sendNotFound(res);
        applySecurityHeaders(res);
        return send(res, 200, asset.mime, asset.body);
      }
      if (pathname.startsWith('/admin/api/')) {
        return handleAdminApi(req, res, url);
      }
      return sendNotFound(res);
    }

    if (pathname === '/telemetry') {
      handleTelemetry(req, res).catch((error) => {
        logger(`[telemetry] ${error.message}`, 'warn');
        if (!res.headersSent) send(res, 204, 'text/plain; charset=utf-8', '');
      });
      return;
    }

    if (pathname === '/internal/snapshot') {
      handleSnapshot(req, res).catch((error) => {
        logger(`[snapshot] ${error.message}`, 'warn');
        if (!res.headersSent) sendJson(res, 500, { error: 'snapshot failed' });
      });
      return;
    }

    sendNotFound(res);
  }

  function start() {
    server = http.createServer(handleRequest);
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;
    server.requestTimeout = 30000;
    server.on('clientError', (_error, socket) => {
      try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch { /* broken */ }
    });
    server.listen(config.port, config.host, () => {
      startedAt = Date.now();
      logger(`[admin] collector listening on http://${config.host}:${config.port} (${allowlist.rules.length ? `${allowlist.rules.length} allowlist rule(s)` : 'loopback only'})`);
    });
    tickTimer = setInterval(sseBroadcast, config.snapshotMs);
    tickTimer.unref();
  }

  function stop() {
    if (tickTimer) clearInterval(tickTimer);
    for (const res of sseClients) {
      try { res.end(); } catch { /* closed */ }
    }
    sseClients.clear();
    return new Promise((resolve) => {
      if (!server) return resolve();
      server.close(() => resolve());
      setTimeout(resolve, 1500).unref();
    });
  }

  return { start, stop, server: () => server, noteDenied: () => deniedCount };
}

module.exports = { createAdminServer };
