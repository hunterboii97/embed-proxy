'use strict';

/**
 * Ingestion for the two live sources:
 *  - loopback worker snapshots (trusted, token-authenticated)
 *  - player beacons (self-reported, rate-limited and clamped)
 *
 * Nothing here runs inside a player worker.
 */

const { VIEWER_FIELDS } = require('./store');

const PROVIDERS = new Set(['zoko', 'kira', 'haiku', 'other']);
const TIERS = new Set(['partner', 'free']);
const EVENT_NAMES = new Set(['play', 'pause', 'ended', 'stall', 'fatal', 'fallback', 'seek', 'error']);

function clamp(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function cleanString(value, max = 64) {
  return String(value == null ? '' : value)
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, max);
}

function cleanOrigin(value) {
  const raw = cleanString(value, 300);
  if (!raw) return '';
  let host;
  try {
    host = new URL(raw.includes('://') ? raw : `https://${raw}`).hostname.toLowerCase();
  } catch {
    return '';
  }
  host = host.replace(/^www\./, '').replace(/\.$/, '');
  if (!host || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) return '';
  return host;
}

function cleanIdentity(value, fallback = '') {
  const text = cleanString(value, 64);
  return /^[a-zA-Z0-9:._-]{1,64}$/.test(text) ? text : fallback;
}

function normalizeSnapshot(body, now) {
  const data = body && typeof body.data === 'object' && body.data ? body.data : {};
  let dataJson = '';
  try {
    const encoded = JSON.stringify(data);
    dataJson = encoded.length <= 16384 ? encoded : encoded.slice(0, 16384);
  } catch {
    dataJson = '';
  }
  return {
    ts: now,
    worker: cleanIdentity(body.worker, 'unknown') || 'unknown',
    port: Math.round(clamp(body.port, 0, 65535)) || null,
    requests: Math.round(clamp(body.requests, 0, 1e9)),
    req4xx: Math.round(clamp(body.req4xx, 0, 1e9)),
    req5xx: Math.round(clamp(body.req5xx, 0, 1e9)),
    slow: Math.round(clamp(body.slow, 0, 1e9)),
    inflight: Math.round(clamp(body.inflight, 0, 1e6)),
    rssMB: clamp(body.rssMB, 0, 1e6),
    heapMB: clamp(body.heapMB, 0, 1e6),
    cpuPct: clamp(body.cpuPct, 0, 100),
    elagMs: clamp(body.elagMs, 0, 1e6),
    cacheHits: Math.round(clamp(body.cacheHits, 0, 1e12)),
    cacheUpstream: Math.round(clamp(body.cacheUpstream, 0, 1e12)),
    prefetch: Math.round(clamp(body.prefetch, 0, 1e12)),
    clientInflight: Math.round(clamp(body.clientInflight, 0, 1e6)),
    cacheMB: clamp(body.cacheMB, 0, 1e7),
    uptimeS: Math.round(clamp(body.uptimeS, 0, 1e10)),
    version: cleanString(body.version, 32),
    data: dataJson
  };
}

function createIngest({ config, store, logger }) {
  const sessions = new Map();
  const latestWorkers = new Map();
  const telemetryBudget = new Map();
  let viewerRows = new Map();
  let currentMinute = null;
  let lastFlushedMinute = null;
  let eventBuffer = [];
  let flushTimer = null;
  let eventTimer = null;
  let sweepTimer = null;
  let stopped = false;
  let lastBootAt = 0;
  let lastTelemetryAt = 0;
  let droppedEvents = 0;
  let logSecond = 0;
  let logSecondCount = 0;

  function sessionKey(session) {
    return `${session.origin || 'unknown'}|${session.provider}|${session.tier}|${session.content}|${session.episode}`;
  }

  function getRow(session) {
    const key = sessionKey(session);
    let row = viewerRows.get(key);
    if (!row) {
      row = {
        origin: session.origin || 'unknown',
        provider: session.provider,
        tier: session.tier,
        content: session.content,
        episode: session.episode,
        session_minutes: 0,
        boots: 0,
        plays: 0,
        stalls: 0,
        errors: 0,
        bytes_est: 0,
        watch_s: 0,
        q_sd: 0,
        q_hd: 0,
        q_fhd: 0,
        q_uhd: 0
      };
      viewerRows.set(key, row);
    }
    return row;
  }

  function ensureBucket(now) {
    const minute = Math.floor(now / 60000);
    if (currentMinute == null) {
      currentMinute = minute;
      return;
    }
    if (minute > currentMinute) {
      flushViewerMinute(now);
      currentMinute = minute;
    }
  }

  function flushViewerMinute(now = Date.now()) {
    if (currentMinute == null || currentMinute === lastFlushedMinute) return;
    const minuteToWrite = currentMinute;
    const activeCutoff = now - 90000;
    for (const session of sessions.values()) {
      if (session.lastSeen < activeCutoff) continue;
      getRow(session).session_minutes += 1;
    }
    const rows = Array.from(viewerRows.values()).filter((row) =>
      row.session_minutes || row.boots || row.plays || row.stalls || row.errors || row.bytes_est || row.watch_s
    );
    try {
      if (rows.length) store.flushViewers(rows, minuteToWrite);
    } catch (error) {
      logger(`[ingest] viewer flush failed: ${error.message}`, 'error');
    }
    viewerRows = new Map();
    lastFlushedMinute = minuteToWrite;
  }

  function flushEvents() {
    if (!eventBuffer.length) return;
    const events = eventBuffer;
    eventBuffer = [];
    try {
      store.insertEvents(events);
    } catch (error) {
      logger(`[ingest] event flush failed: ${error.message}`, 'error');
    }
  }

  function logEvent(event, force = false) {
    if (!force) {
      const second = Math.floor(event.ts / 1000);
      if (second !== logSecond) { logSecond = second; logSecondCount = 0; }
      if (logSecondCount >= 30) { droppedEvents += 1; return; }
      logSecondCount += 1;
    }
    eventBuffer.push(event);
    if (eventBuffer.length >= 25) flushEvents();
  }

  function pruneTelemetryBudget(now) {
    if (telemetryBudget.size < 20000) return;
    const cutoff = now - 120000;
    for (const [ip, entry] of telemetryBudget) {
      if (entry.resetAt < cutoff) telemetryBudget.delete(ip);
    }
  }

  function allowTelemetry(ip, now) {
    if (!ip) return false;
    const minute = Math.floor(now / 60000);
    let entry = telemetryBudget.get(ip);
    if (!entry || entry.minute !== minute) {
      entry = { minute, count: 0, resetAt: now };
      telemetryBudget.set(ip, entry);
      pruneTelemetryBudget(now);
    }
    entry.resetAt = now;
    entry.count += 1;
    return entry.count <= config.telemetryPerMin;
  }

  function getSession(sid, payload, now) {
    let session = sessions.get(sid);
    if (!session) {
      session = {
        sid,
        origin: cleanOrigin(payload.origin) || 'unknown',
        provider: PROVIDERS.has(payload.provider) ? payload.provider : 'other',
        tier: TIERS.has(payload.tier) ? payload.tier : 'free',
        content: cleanIdentity(payload.content),
        episode: cleanIdentity(payload.episode),
        startedAt: now,
        lastSeen: now,
        bytes: 0,
        watchS: 0,
        count: 0,
        isNew: true
      };
      sessions.set(sid, session);
    } else {
      session.lastSeen = now;
      session.isNew = false;
      if (payload.origin) session.origin = cleanOrigin(payload.origin) || session.origin;
      if (PROVIDERS.has(payload.provider)) session.provider = payload.provider;
      if (TIERS.has(payload.tier)) session.tier = payload.tier;
      if (payload.content) session.content = cleanIdentity(payload.content) || session.content;
      if (payload.episode) session.episode = cleanIdentity(payload.episode) || session.episode;
    }
    return session;
  }

  function qualityField(height) {
    if (height >= 1440) return 'q_uhd';
    if (height >= 1000) return 'q_fhd';
    if (height >= 700) return 'q_hd';
    return 'q_sd';
  }

  function handleTelemetry(payload, ip, now) {
    if (!config.telemetryEnabled) return { ok: false, reason: 'disabled' };
    if (!payload || typeof payload !== 'object') return { ok: false, reason: 'bad' };
    if (!allowTelemetry(ip, now)) return { ok: false, reason: 'rate' };
    const sid = cleanString(payload.sid, 64);
    if (!/^[a-zA-Z0-9_-]{8,64}$/.test(sid)) return { ok: false, reason: 'sid' };

    ensureBucket(now);
    lastTelemetryAt = now;
    const session = getSession(sid, payload, now);
    const row = getRow(session);
    const type = cleanString(payload.type, 24);

    if (type === 'boot') {
      if (session.isNew) {
        row.boots += 1;
        lastBootAt = now;
      }
      session.isNew = false;
      if (payload.meta && typeof payload.meta === 'object') {
        session.content = cleanIdentity(payload.meta.content) || session.content;
        session.episode = cleanIdentity(payload.meta.episode) || session.episode;
      }
      return { ok: true };
    }

    if (type === 'heartbeat') {
      const deltaMs = clamp(payload.elapsedMs, 0, 120000);
      const watchS = Math.min(120, Math.round(deltaMs / 1000));
      const bytes = Math.round(clamp(payload.bytes, 0, 200 * 1024 * 1024));
      const height = Math.round(clamp(payload.height, 0, 4320));
      row.watch_s += watchS;
      row.bytes_est += bytes;
      row[qualityField(height)] += 1;
      session.bytes += bytes;
      session.watchS += watchS;
      session.count += 1;
      session.isNew = false;
      return { ok: true };
    }

    if (type === 'event') {
      const name = cleanString(payload.name, 24);
      if (!EVENT_NAMES.has(name)) return { ok: false, reason: 'event' };
      session.isNew = false;
      if (name === 'play') row.plays += 1;
      if (name === 'stall') row.stalls += 1;
      if (name === 'fatal' || name === 'error') row.errors += 1;
      if (name === 'fatal' || name === 'fallback' || name === 'stall') {
        logEvent({
          ts: now,
          level: name === 'fatal' ? 'error' : 'warn',
          source: 'player',
          kind: name,
          message: `${name}${payload.message ? `: ${cleanString(payload.message, 180)}` : ''}`,
          data: {
            origin: session.origin,
            provider: session.provider,
            tier: session.tier,
            content: session.content,
            episode: session.episode,
            position: Math.round(clamp(payload.position, 0, 86400)),
            state: cleanString(payload.state, 32)
          }
        }, name === 'fatal');
      }
      return { ok: true };
    }

    return { ok: false, reason: 'type' };
  }

  function acceptSnapshot(body, ip) {
    if (!body || typeof body !== 'object') return false;
    const now = Date.now();
    const snap = normalizeSnapshot(body, now);
    try {
      store.recordSnapshots([snap], now);
    } catch (error) {
      logger(`[ingest] snapshot failed: ${error.message}`, 'error');
      return false;
    }
    latestWorkers.set(snap.worker, {
      ...snap,
      lastSeen: now,
      data: (() => {
        if (!snap.data) return {};
        try { return JSON.parse(snap.data); } catch { return {}; }
      })()
    });
    return true;
  }

  function sweep() {
    const cutoff = Date.now() - 10 * 60000;
    for (const [sid, session] of sessions) {
      if (session.lastSeen < cutoff) sessions.delete(sid);
    }
    if (sessions.size > 100000) {
      const keepFrom = Date.now() - 30000;
      for (const [sid, session] of sessions) {
        if (session.lastSeen < keepFrom) sessions.delete(sid);
      }
    }
    flushEvents();
  }

  function start() {
    flushTimer = setInterval(() => {
      const now = Date.now();
      const minute = Math.floor(now / 60000);
      if (currentMinute != null && minute > currentMinute) {
        flushViewerMinute(now);
        currentMinute = minute;
      }
    }, 5000);
    flushTimer.unref();
    eventTimer = setInterval(flushEvents, 2000);
    eventTimer.unref();
    sweepTimer = setInterval(sweep, 30000);
    sweepTimer.unref();
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    if (flushTimer) clearInterval(flushTimer);
    if (eventTimer) clearInterval(eventTimer);
    if (sweepTimer) clearInterval(sweepTimer);
    flushViewerMinute();
    flushEvents();
  }

  function activeSessions() {
    const now = Date.now();
    const cutoff = now - 90000;
    let active = 0;
    const byProvider = {};
    const byOrigin = {};
    for (const session of sessions.values()) {
      if (session.lastSeen < cutoff) continue;
      active += 1;
      byProvider[session.provider] = (byProvider[session.provider] || 0) + 1;
      byOrigin[session.origin] = (byOrigin[session.origin] || 0) + 1;
    }
    return { active, byProvider, byOrigin };
  }

  function workerSummary() {
    const now = Date.now();
    let online = 0;
    let rssMB = 0;
    for (const snap of latestWorkers.values()) {
      if (now - snap.lastSeen <= 90000) {
        online += 1;
        rssMB += snap.rssMB || 0;
      }
    }
    return { online, rssMB: Math.round(rssMB), expected: config.expectedWorkers };
  }

  // Partial counters since the last minute flush. Aggregation adds these on
  // top of the DB so the dashboard is live, not up to a minute behind.
  function liveTotals() {
    const totals = {};
    for (const field of VIEWER_FIELDS) totals[field] = 0;
    const byProvider = {};
    const byOrigin = {};
    const byTitle = {};
    for (const row of viewerRows.values()) {
      for (const field of VIEWER_FIELDS) totals[field] += row[field] || 0;
      let provider = byProvider[row.provider];
      if (!provider) {
        provider = { provider: row.provider, session_minutes: 0, boots: 0, plays: 0, bytes_est: 0, q_sd: 0, q_hd: 0, q_fhd: 0, q_uhd: 0 };
        byProvider[row.provider] = provider;
      }
      for (const field of VIEWER_FIELDS) provider[field] += row[field] || 0;

      let origin = byOrigin[row.origin];
      if (!origin) {
        origin = { origin: row.origin, boots: 0, session_minutes: 0, plays: 0, bytes_est: 0, provider: row.provider, tier: row.tier };
        byOrigin[row.origin] = origin;
      }
      origin.boots += row.boots;
      origin.session_minutes += row.session_minutes;
      origin.plays += row.plays;
      origin.bytes_est += row.bytes_est;

      if (row.content) {
        const key = `${row.provider}|${row.content}|${row.episode || ''}`;
        let title = byTitle[key];
        if (!title) {
          title = { provider: row.provider, content: row.content, episode: row.episode || '', session_minutes: 0, plays: 0, bytes_est: 0 };
          byTitle[key] = title;
        }
        title.session_minutes += row.session_minutes;
        title.plays += row.plays;
        title.bytes_est += row.bytes_est;
      }
    }
    return { totals, byProvider, byOrigin, byTitle };
  }

  return {
    start,
    stop,
    flush: () => { flushViewerMinute(); flushEvents(); },
    flushEvents,
    handleTelemetry,
    acceptSnapshot,
    activeSessions,
    workerSummary,
    liveTotals,
    latestWorkers,
    stats: () => ({
      telemetryEnabled: config.telemetryEnabled,
      activeSessions: activeSessions().active,
      sessionsTracked: sessions.size,
      lastBootAt,
      lastTelemetryAt,
      droppedEvents
    })
  };
}

module.exports = { createIngest, normalizeSnapshot, cleanOrigin };
