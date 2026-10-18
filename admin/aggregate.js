'use strict';

const { EDGE_FIELDS } = require('./store');
const { LATENCY_BUCKETS } = require('./edge');

const RANGES = {
  '1h': { ms: 60 * 60 * 1000, stepMinutes: 1, table: 'edge_minute' },
  '6h': { ms: 6 * 60 * 60 * 1000, stepMinutes: 5, table: 'edge_minute' },
  '24h': { ms: 24 * 60 * 60 * 1000, stepMinutes: 15, table: 'edge_minute' },
  '7d': { ms: 7 * 24 * 60 * 60 * 1000, stepMinutes: 60, table: 'edge_hour' },
  '30d': { ms: 30 * 24 * 60 * 60 * 1000, stepMinutes: 360, table: 'edge_hour' }
};

const ORIGIN_RANGES = {
  '1h': 60 * 60 * 1000,
  '6h': 6 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  all: null
};

function number(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function sumSelect() {
  return EDGE_FIELDS
    .map((field) => field === 'rt_max'
      ? `MAX(${field}) AS ${field}`
      : `SUM(${field}) AS ${field}`)
    .join(', ');
}

function emptyTotals() {
  const totals = {};
  for (const field of EDGE_FIELDS) totals[field] = 0;
  return totals;
}

function percentile(row, p) {
  const counts = LATENCY_BUCKETS.map((_, i) => number(row[`rt_b${i}`]));
  const total = counts.reduce((a, b) => a + b, 0);
  if (!total) return 0;
  const target = (total * p) / 100;
  let seen = 0;
  for (let i = 0; i < counts.length; i++) {
    seen += counts[i];
    if (seen >= target) return LATENCY_BUCKETS[i];
  }
  return LATENCY_BUCKETS[LATENCY_BUCKETS.length - 1];
}

function addBuckets(target, source) {
  for (const field of EDGE_FIELDS) {
    if (field === 'rt_max') target[field] = Math.max(number(target[field]), number(source[field]));
    else target[field] += number(source[field]);
  }
}

function derive(bucket) {
  const requests = number(bucket.requests);
  const cacheSamples = number(bucket.cache_hit) + number(bucket.cache_miss) + number(bucket.cache_bypass);
  return {
    requests,
    bytes: number(bucket.bytes),
    errorRate: requests ? (number(bucket.s5xx) / requests) * 100 : 0,
    clientErrorRate: requests ? (number(bucket.s4xx) / requests) * 100 : 0,
    cacheHitPct: cacheSamples ? (number(bucket.cache_hit) / cacheSamples) * 100 : 0,
    avgMs: requests ? number(bucket.rt_sum) / requests : 0,
    p95Ms: percentile(bucket, 95)
  };
}

function rangeInfo(name) {
  return RANGES[name] || RANGES['24h'];
}

function querySeries(store, rangeName, now = Date.now()) {
  const range = rangeInfo(rangeName);
  const step = range.stepMinutes;
  const nowBucket = Math.floor(now / 60000);
  const fromBucket = nowBucket - Math.floor(range.ms / 60000);
  const startBucket = Math.floor(fromBucket / step) * step;
  const rows = store.db.prepare(`
    SELECT CAST(bucket / ? AS INTEGER) AS b, ${sumSelect()}
    FROM ${range.table}
    WHERE bucket >= ? AND bucket <= ?
    GROUP BY CAST(bucket / ? AS INTEGER)
    ORDER BY b ASC
  `).all(step, startBucket, nowBucket, step);
  const totalsRow = store.db.prepare(`
    SELECT ${sumSelect()} FROM ${range.table} WHERE bucket >= ? AND bucket <= ?
  `).get(startBucket, nowBucket) || emptyTotals();

  const byBucket = new Map(rows.map((row) => [number(row.b) * step, row]));
  const points = [];
  for (let b = startBucket; b <= nowBucket; b += step) {
    const row = byBucket.get(b) || emptyTotals();
    const point = {
      ts: b * 60000,
      requests: number(row.requests),
      bytes: number(row.bytes),
      s2xx: number(row.s2xx),
      s3xx: number(row.s3xx),
      s4xx: number(row.s4xx),
      s5xx: number(row.s5xx),
      s403: number(row.s403),
      s404: number(row.s404),
      s429: number(row.s429),
      s499: number(row.s499),
      s502: number(row.s502),
      cache_hit: number(row.cache_hit),
      cache_miss: number(row.cache_miss),
      cache_bypass: number(row.cache_bypass),
      rt_sum: number(row.rt_sum),
      rt_max: number(row.rt_max),
      rt_b0: number(row.rt_b0),
      rt_b1: number(row.rt_b1),
      rt_b2: number(row.rt_b2),
      rt_b3: number(row.rt_b3),
      rt_b4: number(row.rt_b4),
      rt_b5: number(row.rt_b5),
      rt_b6: number(row.rt_b6),
      rt_b7: number(row.rt_b7),
      live: false
    };
    points.push(point);
  }
  const totals = {};
  for (const field of EDGE_FIELDS) totals[field] = number(totalsRow[field]);
  return { rangeName, range, step, startBucket, nowBucket, points, totals, rows };
}

function mergeLive(points, totals, live) {
  if (!live || live.minute == null || live.elapsedMs < 5000) return false;
  const point = points[points.length - 1];
  if (!point) return false;
  const bucket = live.bucket;
  addBuckets(point, bucket);
  point.live = true;
  addBuckets(totals, bucket);
  return true;
}

function slimPoints(points) {
  return points.map((point) => {
    const d = derive(point);
    return {
      ts: point.ts,
      requests: d.requests,
      bytes: d.bytes,
      s4xx: point.s4xx,
      s5xx: point.s5xx,
      p95: d.p95Ms,
      cacheHitPct: Math.round(d.cacheHitPct * 10) / 10,
      live: point.live
    };
  });
}

function routeTotals(totals) {
  return {
    seg: number(totals.route_seg),
    playlist: number(totals.route_playlist),
    embed: number(totals.route_embed),
    api: number(totals.route_api),
    docs: number(totals.route_docs),
    asset: number(totals.route_asset),
    telemetry: number(totals.route_telemetry),
    download: number(totals.route_download),
    other: number(totals.route_other)
  };
}

function providerEmbeds(totals) {
  return {
    zoko: number(totals.p_zoko),
    kira: number(totals.p_kira),
    haiku: number(totals.p_haiku)
  };
}

function last5Minutes(store, now) {
  const nowBucket = Math.floor(now / 60000);
  return store.db.prepare(`SELECT ${sumSelect()} FROM edge_minute WHERE bucket >= ? AND bucket < ?`)
    .get(nowBucket - 5, nowBucket) || emptyTotals();
}

function getTraffic(store, edge, rangeName = '24h', now = Date.now()) {
  const { points, totals, range, step } = querySeries(store, rangeName, now);
  const live = edge ? edge.live() : null;
  mergeLive(points, totals, live);
  return {
    range: rangeName,
    from: points.length ? points[0].ts : now,
    to: now,
    stepMs: step * 60000,
    points: slimPoints(points),
    totals: {
      requests: number(totals.requests),
      bytes: number(totals.bytes),
      s2xx: number(totals.s2xx),
      s3xx: number(totals.s3xx),
      s4xx: number(totals.s4xx),
      s5xx: number(totals.s5xx),
      s403: number(totals.s403),
      s404: number(totals.s404),
      s429: number(totals.s429),
      s499: number(totals.s499),
      s502: number(totals.s502),
      cache_hit: number(totals.cache_hit),
      cache_miss: number(totals.cache_miss),
      cache_bypass: number(totals.cache_bypass)
    },
    derived: derive(totals),
    routes: routeTotals(totals),
    providers: providerEmbeds(totals)
  };
}

function getOverview({ store, edge, ingest, config, alerts }) {
  const now = Date.now();
  const live = edge ? edge.live() : { minute: null, elapsedMs: 0, bucket: emptyTotals(), lastLineAt: 0, configured: false };
  const range = querySeries(store, '1h', now);
  const liveMerged = mergeLive(range.points, range.totals, live);
  const last5 = last5Minutes(store, now);
  const window15 = store.db.prepare(`
    SELECT ${sumSelect()} FROM edge_minute WHERE bucket >= ? AND bucket <= ?
  `).get(Math.floor(now / 60000) - 15, Math.floor(now / 60000)) || emptyTotals();
  const window24 = store.db.prepare(`
    SELECT SUM(requests) AS requests, SUM(bytes) AS bytes FROM edge_minute WHERE bucket >= ?
  `).get(Math.floor((now - 24 * 3600000) / 60000)) || { requests: 0, bytes: 0 };

  const active = ingest.activeSessions();
  const workers = ingest.workerSummary();
  const latest = Array.from(ingest.latestWorkers.values());
  const inflight = latest.reduce((sum, w) => sum + number(w.inflight), 0);
  const prefetch = latest.reduce((sum, w) => sum + number(w.prefetch), 0);

  const liveBucket = live.bucket || emptyTotals();
  const liveFresh = live.lastLineAt && now - live.lastLineAt < 15000;
  const liveElapsedMin = live.elapsedMs >= 5000 ? live.elapsedMs / 60000 : 0;
  const liveRpm = liveFresh && liveElapsedMin > 0 ? number(liveBucket.requests) / liveElapsedMin : null;
  const liveBps = liveFresh && live.elapsedMs >= 5000
    ? number(liveBucket.bytes) / (live.elapsedMs / 1000)
    : null;
  const requestsPerMin = liveRpm != null
    ? liveRpm
    : number(last5.requests) / 5 || latest.reduce((sum, w) => sum + number(w.requests), 0) * (60000 / config.snapshotMs);
  const bytesPerSec = liveBps != null ? liveBps : number(last5.bytes) / 300;

  addBuckets(window15, liveBucket);
  const error = derive(window15);

  const origins = store.db.prepare(`
    SELECT origin, requests, boots, session_minutes, plays, bytes_est, last_seen, last_provider
    FROM origins ORDER BY requests DESC, last_seen DESC LIMIT 6
  `).all();

  const providerRows = store.db.prepare(`
    SELECT provider,
      SUM(session_minutes) AS session_minutes,
      SUM(boots) AS boots,
      SUM(plays) AS plays,
      SUM(bytes_est) AS bytes_est
    FROM viewers_minute WHERE minute >= ?
    GROUP BY provider ORDER BY bytes_est DESC
  `).all(Math.floor((now - 24 * 3600000) / 60000));
  const embedTotals = store.db.prepare(`
    SELECT ${sumSelect()} FROM edge_minute WHERE bucket >= ?
  `).get(Math.floor((now - 24 * 3600000) / 60000)) || emptyTotals();
  if (live.minute != null) addBuckets(embedTotals, live.bucket);
  const embeds = providerEmbeds(embedTotals);
  const providerMap = new Map();
  for (const provider of ['zoko', 'kira', 'haiku', 'other']) {
    providerMap.set(provider, {
      provider,
      active: active.byProvider[provider] || 0,
      embeds24h: embeds[provider] || 0,
      session_minutes: 0,
      boots: 0,
      plays: 0,
      bytes_est: 0
    });
  }
  for (const row of providerRows) {
    const entry = providerMap.get(row.provider) || providerMap.get('other');
    entry.session_minutes += number(row.session_minutes);
    entry.boots += number(row.boots);
    entry.plays += number(row.plays);
    entry.bytes_est += number(row.bytes_est);
  }

  const viewerTotals = store.db.prepare(`
    SELECT
      SUM(session_minutes) AS session_minutes,
      SUM(boots) AS boots,
      SUM(plays) AS plays,
      SUM(bytes_est) AS bytes_est,
      SUM(stalls) AS stalls,
      SUM(errors) AS errors
    FROM viewers_minute WHERE minute >= ?
  `).get(Math.floor((now - 24 * 3600000) / 60000)) || {};

  const quality = store.db.prepare(`
    SELECT SUM(q_sd) AS sd, SUM(q_hd) AS hd, SUM(q_fhd) AS fhd, SUM(q_uhd) AS uhd
    FROM viewers_minute WHERE minute >= ?
  `).get(Math.floor((now - 24 * 3600000) / 60000)) || {};

  const liveView = ingest.liveTotals();
  const liveTotals = liveView.totals;
  for (const row of Object.values(liveView.byProvider)) {
    const entry = providerMap.get(row.provider) || providerMap.get('other');
    entry.session_minutes += row.session_minutes;
    entry.boots += row.boots;
    entry.plays += row.plays;
    entry.bytes_est += row.bytes_est;
  }
  const originMap = new Map();
  for (const o of origins) {
    originMap.set(o.origin, {
      origin: o.origin,
      requests: number(o.requests),
      boots: number(o.boots),
      sessionMinutes: number(o.session_minutes),
      plays: number(o.plays),
      bytesEst: number(o.bytes_est),
      lastSeen: number(o.last_seen),
      provider: o.last_provider || '',
      active: active.byOrigin[o.origin] || 0
    });
  }
  for (const liveOrigin of live.origins || []) {
    const entry = originMap.get(liveOrigin.origin) || {
      origin: liveOrigin.origin,
      requests: 0,
      boots: 0,
      sessionMinutes: 0,
      plays: 0,
      bytesEst: 0,
      lastSeen: now,
      provider: '',
      active: 0
    };
    entry.requests += number(liveOrigin.requests);
    entry.provider = liveOrigin.provider || entry.provider;
    entry.active = active.byOrigin[liveOrigin.origin] || 0;
    originMap.set(liveOrigin.origin, entry);
  }
  for (const liveRow of Object.values(liveView.byOrigin)) {
    const entry = originMap.get(liveRow.origin) || {
      origin: liveRow.origin,
      requests: 0,
      boots: 0,
      sessionMinutes: 0,
      plays: 0,
      bytesEst: 0,
      lastSeen: now,
      provider: '',
      active: 0
    };
    entry.boots += liveRow.boots;
    entry.sessionMinutes += liveRow.session_minutes;
    entry.plays += liveRow.plays;
    entry.bytesEst += liveRow.bytes_est;
    entry.lastSeen = now;
    entry.provider = liveRow.provider || entry.provider;
    entry.active = active.byOrigin[liveRow.origin] || 0;
    originMap.set(liveRow.origin, entry);
  }
  const originList = Array.from(originMap.values())
    .sort((a, b) => (b.active - a.active) || (b.requests - a.requests) || (b.lastSeen - a.lastSeen))
    .slice(0, 6);

  return {
    ts: now,
    live: {
      activeViewers: active.active,
      requestsPerMin: Math.round(requestsPerMin),
      bytesPerSec: Math.round(bytesPerSec),
      errorRate: Math.round(error.errorRate * 100) / 100,
      p95Ms: Math.round(error.p95Ms),
      cacheHitPct: Math.round(error.cacheHitPct * 10) / 10,
      onlineWorkers: workers.online,
      expectedWorkers: workers.expected,
      inflight,
      prefetch,
      liveEdge: liveMerged
    },
    series: slimPoints(range.points),
    totals24h: {
      requests: number(window24.requests),
      bytes: number(window24.bytes),
      watchMinutes: number(viewerTotals.session_minutes) + number(liveTotals.session_minutes),
      boots: number(viewerTotals.boots) + number(liveTotals.boots),
      plays: number(viewerTotals.plays) + number(liveTotals.plays),
      bytesEst: number(viewerTotals.bytes_est) + number(liveTotals.bytes_est),
      stalls: number(viewerTotals.stalls) + number(liveTotals.stalls),
      errors: number(viewerTotals.errors) + number(liveTotals.errors)
    },
    quality: {
      sd: number(quality.sd) + number(liveTotals.q_sd),
      hd: number(quality.hd) + number(liveTotals.q_hd),
      fhd: number(quality.fhd) + number(liveTotals.q_fhd),
      uhd: number(quality.uhd) + number(liveTotals.q_uhd)
    },
    origins: originList,
    providers: Array.from(providerMap.values()),
    workers: workers,
    alerts: alerts || [],
    meta: {
      version: config.version,
      uptimeMs: now - config.startedAt,
      snapshotMs: config.snapshotMs,
      expectedWorkers: config.expectedWorkers,
      telemetryEnabled: config.telemetryEnabled,
      edge: edge ? edge.stats() : { enabled: false },
      node: process.version
    }
  };
}

function getOriginRange(store, rangeName) {
  const ms = ORIGIN_RANGES[rangeName];
  if (ms == null) return null;
  return Math.floor((Date.now() - ms) / 60000);
}

function getOrigins(store, ingest, rangeName = '24h', edge = null) {
  const now = Date.now();
  const fromMinute = getOriginRange(store, rangeName);
  const active = ingest.activeSessions();

  const requestRows = fromMinute == null
    ? store.db.prepare('SELECT origin, requests FROM origins').all()
    : store.db.prepare(`SELECT origin, SUM(requests) AS requests FROM origin_minute
        WHERE minute >= ? GROUP BY origin`).all(fromMinute);
  const requestMap = new Map(requestRows.map((row) => [row.origin, number(row.requests)]));
  const liveEdge = edge ? edge.live() : null;
  if (liveEdge && liveEdge.minute != null) {
    for (const entry of liveEdge.origins || []) {
      requestMap.set(entry.origin, number(requestMap.get(entry.origin)) + number(entry.requests));
    }
  }

  const telemetryRows = fromMinute == null
    ? store.db.prepare(`SELECT origin, boots, session_minutes, plays, bytes_est, last_seen, last_provider, last_tier
        FROM origins`).all()
    : store.db.prepare(`SELECT origin,
          SUM(boots) AS boots, SUM(session_minutes) AS session_minutes,
          SUM(plays) AS plays, SUM(bytes_est) AS bytes_est
        FROM viewers_minute WHERE minute >= ? GROUP BY origin`).all(fromMinute);
  const telemetryMap = new Map(telemetryRows.map((row) => [row.origin, row]));

  const allMeta = store.db.prepare(`
    SELECT origin, first_seen, last_seen, requests, boots, session_minutes, plays, bytes_est,
           last_provider, last_tier
    FROM origins ORDER BY last_seen DESC
  `).all();
  const metaMap = new Map(allMeta.map((row) => [row.origin, row]));

  const live = ingest.liveTotals().byOrigin;
  const origins = new Set([...requestMap.keys(), ...telemetryMap.keys(), ...Object.keys(live)]);
  const list = [];
  for (const origin of origins) {
    const meta = metaMap.get(origin) || {};
    const telemetry = telemetryMap.get(origin) || {};
    const liveRow = live[origin] || {};
    const embedRequests = number(requestMap.get(origin));
    const sessionMinutes = number(telemetry.session_minutes) + number(liveRow.session_minutes);
    const boots = fromMinute == null
      ? number(meta.boots) + number(liveRow.boots)
      : number(telemetry.boots) + number(liveRow.boots);
    const plays = number(telemetry.plays) + number(liveRow.plays);
    const bytesEst = number(telemetry.bytes_est) + number(liveRow.bytes_est);
    if (!embedRequests && !sessionMinutes && !boots && !plays && !bytesEst) continue;
    list.push({
      origin,
      requests: embedRequests,
      boots,
      sessionMinutes,
      plays,
      bytesEst,
      active: active.byOrigin[origin] || 0,
      lastSeen: number(meta.last_seen) || (liveRow.origin ? now : 0),
      lastProvider: meta.last_provider || liveRow.provider || '',
      lastTier: meta.last_tier || liveRow.tier || ''
    });
  }
  list.sort((a, b) => (b.requests - a.requests) || (b.sessionMinutes - a.sessionMinutes) || (b.lastSeen - a.lastSeen));
  const limited = list.slice(0, 200);
  const totals = limited.reduce((acc, row) => ({
    requests: acc.requests + row.requests,
    sessionMinutes: acc.sessionMinutes + row.sessionMinutes,
    plays: acc.plays + row.plays,
    bytesEst: acc.bytesEst + row.bytesEst
  }), { requests: 0, sessionMinutes: 0, plays: 0, bytesEst: 0 });

  return {
    range: rangeName,
    origins: limited,
    totals,
    activeViewers: active.active,
    telemetryEnabled: ingest.stats().telemetryEnabled,
    generatedAt: now
  };
}

function getProviders(store, ingest, rangeName = '24h', edge = null) {
  const range = rangeInfo(rangeName);
  const now = Date.now();
  const useDay = rangeName === '30d';
  const viewerTable = useDay ? 'viewers_day' : 'viewers_minute';
  const viewerKey = useDay ? 'day' : 'minute';
  const fromValue = useDay
    ? Math.floor((now - range.ms) / 86400000) * 1440
    : Math.floor((now - range.ms) / 60000);
  const active = ingest.activeSessions();

  const viewerRows = store.db.prepare(`
    SELECT provider,
      SUM(session_minutes) AS session_minutes, SUM(boots) AS boots,
      SUM(plays) AS plays, SUM(bytes_est) AS bytes_est,
      SUM(q_sd) AS q_sd, SUM(q_hd) AS q_hd, SUM(q_fhd) AS q_fhd, SUM(q_uhd) AS q_uhd
    FROM ${viewerTable} WHERE ${viewerKey} >= ? GROUP BY provider
  `).all(fromValue);

  const edgeRows = store.db.prepare(`
    SELECT ${sumSelect()} FROM ${range.table} WHERE bucket >= ?
  `).get(Math.floor((now - range.ms) / 60000)) || emptyTotals();
  const liveEdge = edge ? edge.live() : null;
  if (liveEdge && liveEdge.minute != null) addBuckets(edgeRows, liveEdge.bucket);
  const embeds = providerEmbeds(edgeRows);

  const map = new Map();
  for (const provider of ['zoko', 'kira', 'haiku', 'other']) {
    map.set(provider, {
      provider,
      active: active.byProvider[provider] || 0,
      embeds: embeds[provider] || 0,
      session_minutes: 0,
      boots: 0,
      plays: 0,
      bytes_est: 0,
      quality: { sd: 0, hd: 0, fhd: 0, uhd: 0 }
    });
  }
  for (const row of viewerRows) {
    const entry = map.get(row.provider) || map.get('other');
    entry.session_minutes += number(row.session_minutes);
    entry.boots += number(row.boots);
    entry.plays += number(row.plays);
    entry.bytes_est += number(row.bytes_est);
    entry.quality.sd += number(row.q_sd);
    entry.quality.hd += number(row.q_hd);
    entry.quality.fhd += number(row.q_fhd);
    entry.quality.uhd += number(row.q_uhd);
  }

  const titles = store.db.prepare(`
    SELECT provider, content, episode,
      SUM(session_minutes) AS session_minutes, SUM(plays) AS plays, SUM(bytes_est) AS bytes_est
    FROM ${viewerTable} WHERE ${viewerKey} >= ?
    GROUP BY provider, content, episode
    ORDER BY plays DESC, bytes_est DESC LIMIT 25
  `).all(fromValue).filter((row) => row.content);

  const live = ingest.liveTotals();
  for (const row of Object.values(live.byProvider)) {
    const entry = map.get(row.provider) || map.get('other');
    entry.session_minutes += row.session_minutes;
    entry.boots += row.boots;
    entry.plays += row.plays;
    entry.bytes_est += row.bytes_est;
    entry.quality.sd += row.q_sd;
    entry.quality.hd += row.q_hd;
    entry.quality.fhd += row.q_fhd;
    entry.quality.uhd += row.q_uhd;
  }

  const titleMap = new Map();
  for (const row of titles) {
    titleMap.set(`${row.provider}|${row.content}|${row.episode || ''}`, {
      provider: row.provider,
      content: row.content,
      episode: row.episode || '',
      sessionMinutes: number(row.session_minutes),
      plays: number(row.plays),
      bytesEst: number(row.bytes_est)
    });
  }
  for (const [key, row] of Object.entries(live.byTitle)) {
    const entry = titleMap.get(key) || {
      provider: row.provider,
      content: row.content,
      episode: row.episode || '',
      sessionMinutes: 0,
      plays: 0,
      bytesEst: 0
    };
    entry.sessionMinutes += row.session_minutes;
    entry.plays += row.plays;
    entry.bytesEst += row.bytes_est;
    titleMap.set(key, entry);
  }
  const titleList = Array.from(titleMap.values())
    .sort((a, b) => (b.plays - a.plays) || (b.bytesEst - a.bytesEst))
    .slice(0, 25);

  return {
    range: rangeName,
    providers: Array.from(map.values()),
    titles: titleList,
    telemetryEnabled: ingest.stats().telemetryEnabled,
    generatedAt: now
  };
}

function getWorkers(store, ingest, config) {
  const now = Date.now();
  const from = now - 30 * 60000;
  const rows = store.db.prepare(`SELECT * FROM snapshots WHERE ts >= ? ORDER BY ts ASC`).all(from);
  const byWorker = new Map();
  for (const row of rows) {
    let entry = byWorker.get(row.worker);
    if (!entry) {
      entry = { worker: row.worker, port: row.port, history: [] };
      byWorker.set(row.worker, entry);
    }
    entry.lastRow = row;
    entry.history.push({
      ts: number(row.ts),
      requests: number(row.requests),
      cpuPct: number(row.cpu_pct),
      rssMB: number(row.rss_mb),
      elagMs: number(row.elag_ms),
      inflight: number(row.inflight)
    });
    if (entry.history.length > 120) entry.history.shift();
  }

  const latest = ingest.latestWorkers;
  for (const [worker, snap] of latest) {
    let entry = byWorker.get(worker);
    if (!entry) {
      entry = { worker, port: snap.port, history: [] };
      byWorker.set(worker, entry);
    }
    entry.latest = snap;
  }

  const workers = Array.from(byWorker.values()).map((entry) => {
    const snap = entry.latest || null;
    const lastRow = entry.lastRow || null;
    const online = snap ? now - snap.lastSeen <= 90000 : false;
    const pick = (camel, snake, fallback = 0) => {
      if (snap) return number(snap[camel]);
      return lastRow ? number(lastRow[snake]) : fallback;
    };
    const cacheHits = pick('cacheHits', 'cache_hits');
    const cacheUpstream = pick('cacheUpstream', 'cache_upstream');
    const cacheTotal = cacheHits + cacheUpstream;
    let data = snap && snap.data ? snap.data : {};
    if (!snap && lastRow && lastRow.data) {
      try { data = JSON.parse(lastRow.data) || {}; } catch { data = {}; }
    }
    return {
      worker: entry.worker,
      port: entry.port || (snap && snap.port) || (lastRow && lastRow.port) || null,
      online,
      lastSeen: snap ? snap.lastSeen : (lastRow ? number(lastRow.ts) : 0),
      uptimeS: pick('uptimeS', 'uptime_s'),
      version: snap ? snap.version : (lastRow ? lastRow.version || '' : ''),
      requests: pick('requests', 'requests'),
      requestsPerMin: Math.round(pick('requests', 'requests') * (60000 / config.snapshotMs)),
      req4xx: pick('req4xx', 'req4xx'),
      req5xx: pick('req5xx', 'req5xx'),
      slow: pick('slow', 'slow'),
      inflight: pick('inflight', 'inflight'),
      rssMB: pick('rssMB', 'rss_mb'),
      heapMB: pick('heapMB', 'heap_mb'),
      cpuPct: pick('cpuPct', 'cpu_pct'),
      elagMs: pick('elagMs', 'elag_ms'),
      cacheHitPct: cacheTotal ? (cacheHits / cacheTotal) * 100 : 0,
      cacheMB: pick('cacheMB', 'cache_mb'),
      prefetch: pick('prefetch', 'prefetch'),
      clientInflight: pick('clientInflight', 'client_inflight'),
      routes: data.routes || {},
      status: data.status || {},
      cacheSizes: data.cacheSizes || {},
      history: entry.history
    };
  });
  workers.sort((a, b) => String(a.worker).localeCompare(String(b.worker)));
  const summary = ingest.workerSummary();
  return {
    workers,
    expected: config.expectedWorkers,
    online: summary.online,
    metricsSeen: workers.length > 0,
    generatedAt: now
  };
}

function getSystem(store, config, ingest, edge) {
  const now = Date.now();
  const from = now - 24 * 3600000;
  const rows = store.db.prepare(`SELECT * FROM system_samples WHERE ts >= ? ORDER BY ts ASC`).all(from);
  const stride = Math.max(1, Math.ceil(rows.length / 240));
  const points = [];
  for (let i = 0; i < rows.length; i += stride) {
    const slice = rows.slice(i, i + stride);
    const avg = (field) => slice.reduce((sum, row) => sum + number(row[field]), 0) / slice.length;
    points.push({
      ts: number(slice[slice.length - 1].ts),
      cpuPct: Math.round(avg('cpu_pct') * 10) / 10,
      memUsedMB: Math.round(avg('mem_used_mb')),
      memTotalMB: Math.round(avg('mem_total_mb')),
      netRxBps: Math.round(avg('net_rx_bps')),
      netTxBps: Math.round(avg('net_tx_bps')),
      nginxActive: Math.round(avg('nginx_active')),
      nginxRps: Math.round(avg('nginx_rps') * 10) / 10,
      workerRssMB: Math.round(avg('worker_rss_mb'))
    });
  }
  const last = rows.length ? rows[rows.length - 1] : null;
  return {
    points,
    latest: last ? {
      ts: number(last.ts),
      cpuPct: number(last.cpu_pct),
      load1: number(last.load1),
      load5: number(last.load5),
      load15: number(last.load15),
      memUsedMB: number(last.mem_used_mb),
      memTotalMB: number(last.mem_total_mb),
      swapUsedMB: number(last.swap_used_mb),
      diskUsedGB: number(last.disk_used_gb),
      diskTotalGB: number(last.disk_total_gb),
      netRxBps: number(last.net_rx_bps),
      netTxBps: number(last.net_tx_bps),
      nginxActive: last.nginx_active == null ? null : number(last.nginx_active),
      nginxRps: last.nginx_rps == null ? null : number(last.nginx_rps),
      workersOnline: number(last.workers_online),
      workerRssMB: number(last.worker_rss_mb)
    } : null,
    db: {
      sizeMB: Math.round((store.dbSizeBytes() / 1024 / 1024) * 10) / 10,
      maxMB: config.dbMaxMB,
      rows: store.rowCounts()
    },
    edge: edge ? edge.stats() : { enabled: false },
    ingest: ingest.stats(),
    retention: config.retention,
    generatedAt: now
  };
}

function getLogs(store, params = {}) {
  const limit = Math.min(300, Math.max(1, Number(params.limit) || 100));
  const where = [];
  const args = [];
  const level = String(params.level || 'all').toLowerCase();
  const source = String(params.source || 'all').toLowerCase();
  if (['info', 'warn', 'error'].includes(level)) {
    where.push('level = ?');
    args.push(level);
  }
  if (['edge', 'player', 'collector', 'worker'].includes(source)) {
    where.push('source = ?');
    args.push(source);
  }
  const q = String(params.q || '').trim().slice(0, 120);
  if (q) {
    where.push("(message LIKE ? ESCAPE '\\' OR data LIKE ? ESCAPE '\\')");
    const escaped = q.replace(/[\\%_]/g, (m) => `\\${m}`);
    args.push(`%${escaped}%`, `%${escaped}%`);
  }
  const before = Number(params.before);
  if (Number.isFinite(before) && before > 0) {
    where.push('id < ?');
    args.push(before);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const rows = store.db.prepare(`SELECT id, ts, level, source, kind, message, data
    FROM events ${clause} ORDER BY id DESC LIMIT ?`).all(...args, limit);
  const stats = store.db.prepare(`SELECT level, COUNT(*) AS n FROM events
    WHERE ts >= ? GROUP BY level`).all(Date.now() - 24 * 3600000);
  const levelCounts = { info: 0, warn: 0, error: 0 };
  for (const row of stats) levelCounts[row.level] = number(row.n);
  return {
    entries: rows.map((row) => {
      let data = null;
      if (row.data) {
        try { data = JSON.parse(row.data); } catch { data = null; }
      }
      return {
        id: number(row.id),
        ts: number(row.ts),
        level: row.level,
        source: row.source,
        kind: row.kind,
        message: row.message,
        data
      };
    }),
    nextBefore: rows.length === limit ? number(rows[rows.length - 1].id) : null,
    levelCounts24h: levelCounts
  };
}

function getSecurity(store, rangeName = '24h', edge = null) {
  const range = rangeInfo(rangeName);
  const now = Date.now();
  const fromBucket = Math.floor((now - range.ms) / 60000);
  const totals = store.db.prepare(`
    SELECT ${sumSelect()} FROM ${range.table} WHERE bucket >= ?
  `).get(fromBucket) || emptyTotals();
  const liveEdge = edge ? edge.live() : null;
  if (liveEdge && liveEdge.minute != null) addBuckets(totals, liveEdge.bucket);
  const denied = store.db.prepare(`
    SELECT COUNT(*) AS n FROM events WHERE source = 'collector' AND kind = 'admin_denied' AND ts >= ?
  `).get(now - range.ms);
  const recent = store.db.prepare(`
    SELECT id, ts, level, source, kind, message, data FROM events
    WHERE ts >= ? AND (source = 'player' OR source = 'collector' OR level IN ('warn', 'error'))
    ORDER BY id DESC LIMIT 40
  `).all(now - range.ms);
  return {
    range: rangeName,
    status: {
      requests: number(totals.requests),
      s4xx: number(totals.s4xx),
      s5xx: number(totals.s5xx),
      s403: number(totals.s403),
      s404: number(totals.s404),
      s429: number(totals.s429),
      s499: number(totals.s499),
      s502: number(totals.s502),
      adminDenied: number(denied.n)
    },
    recent: recent.map((row) => {
      let data = null;
      if (row.data) {
        try { data = JSON.parse(row.data); } catch { data = null; }
      }
      return { id: number(row.id), ts: number(row.ts), level: row.level, source: row.source, kind: row.kind, message: row.message, data };
    })
  };
}

function getData(store, config, extra = {}) {
  return {
    db: {
      sizeMB: Math.round((store.dbSizeBytes() / 1024 / 1024) * 100) / 100,
      maxMB: config.dbMaxMB,
      rows: store.rowCounts()
    },
    retention: config.retention,
    originMax: config.originMax,
    titleMax: config.titleMax,
    snapshotMs: config.snapshotMs,
    logSample: config.logSample,
    edge: extra.edge || null,
    ingest: extra.ingest || null,
    lastPrune: extra.lastPrune || null,
    generatedAt: Date.now()
  };
}

module.exports = {
  RANGES,
  getTraffic,
  getOverview,
  getOrigins,
  getProviders,
  getWorkers,
  getSystem,
  getLogs,
  getSecurity,
  getData,
  derive,
  percentile
};
