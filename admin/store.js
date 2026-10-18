'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const EDGE_FIELDS = [
  'requests', 'bytes',
  's2xx', 's3xx', 's4xx', 's5xx',
  's403', 's404', 's429', 's499', 's502',
  'cache_hit', 'cache_miss', 'cache_bypass',
  'rt_sum', 'rt_max',
  'rt_b0', 'rt_b1', 'rt_b2', 'rt_b3', 'rt_b4', 'rt_b5', 'rt_b6', 'rt_b7',
  'route_seg', 'route_playlist', 'route_embed', 'route_api',
  'route_docs', 'route_asset', 'route_telemetry', 'route_download', 'route_other',
  'p_zoko', 'p_kira', 'p_haiku'
];

const VIEWER_FIELDS = [
  'session_minutes', 'boots', 'plays', 'stalls', 'errors',
  'bytes_est', 'watch_s', 'q_sd', 'q_hd', 'q_fhd', 'q_uhd'
];

function emptyEdgeBucket() {
  const bucket = {};
  for (const field of EDGE_FIELDS) bucket[field] = 0;
  return bucket;
}

function edgeTableSql(table) {
  const columns = EDGE_FIELDS.map((field) =>
    `${field} ${field === 'rt_sum' || field === 'rt_max' ? 'REAL' : 'INTEGER'} NOT NULL DEFAULT 0`
  ).join(',\n      ');
  return `CREATE TABLE IF NOT EXISTS ${table} (
      bucket INTEGER PRIMARY KEY,
      ${columns}
    ) WITHOUT ROWID;`;
}

function viewerTableSql(table, key) {
  const columns = VIEWER_FIELDS.map((field) => `${field} INTEGER NOT NULL DEFAULT 0`).join(',\n      ');
  return `CREATE TABLE IF NOT EXISTS ${table} (
      ${key} INTEGER NOT NULL,
      origin TEXT NOT NULL,
      provider TEXT NOT NULL,
      tier TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      episode TEXT NOT NULL DEFAULT '',
      ${columns},
      PRIMARY KEY (${key}, origin, provider, tier, content, episode)
    ) WITHOUT ROWID;`;
}

function upsertSql(table, key, fields, { maxFields = [], dimensionFields = [] } = {}) {
  const columns = [key, ...dimensionFields, ...fields];
  const placeholders = columns.map(() => '?').join(', ');
  const updates = fields
    .map((field) => maxFields.includes(field)
      ? `${field} = MAX(${field}, excluded.${field})`
      : `${field} = ${field} + excluded.${field}`)
    .join(', ');
  const conflict = [key, ...dimensionFields].join(', ');
  return `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})
    ON CONFLICT(${conflict}) DO UPDATE SET ${updates}`;
}

function openStore(config) {
  fs.mkdirSync(config.dataDir, { recursive: true });
  const db = new DatabaseSync(config.dbPath);
  const schemaVersion = Number((db.prepare('PRAGMA user_version').get() || {}).user_version) || 0;
  if (schemaVersion < 2) {
    // Viewer rows gained content/episode dimensions; these are monitoring
    // aggregates only, so rebuilding them is cheaper than an ALTER dance.
    db.exec('DROP TABLE IF EXISTS viewers_minute; DROP TABLE IF EXISTS viewers_day;');
  }
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA temp_store = MEMORY;
    PRAGMA auto_vacuum = INCREMENTAL;

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS snapshots (
      ts INTEGER NOT NULL,
      worker TEXT NOT NULL,
      port INTEGER,
      requests INTEGER NOT NULL DEFAULT 0,
      req4xx INTEGER NOT NULL DEFAULT 0,
      req5xx INTEGER NOT NULL DEFAULT 0,
      slow INTEGER NOT NULL DEFAULT 0,
      inflight INTEGER NOT NULL DEFAULT 0,
      rss_mb REAL NOT NULL DEFAULT 0,
      heap_mb REAL NOT NULL DEFAULT 0,
      cpu_pct REAL NOT NULL DEFAULT 0,
      elag_ms REAL NOT NULL DEFAULT 0,
      cache_hits INTEGER NOT NULL DEFAULT 0,
      cache_upstream INTEGER NOT NULL DEFAULT 0,
      prefetch INTEGER NOT NULL DEFAULT 0,
      client_inflight INTEGER NOT NULL DEFAULT 0,
      cache_mb REAL NOT NULL DEFAULT 0,
      uptime_s INTEGER NOT NULL DEFAULT 0,
      data TEXT,
      PRIMARY KEY (ts, worker)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);

    CREATE TABLE IF NOT EXISTS workers (
      worker TEXT PRIMARY KEY,
      port INTEGER,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      uptime_s INTEGER NOT NULL DEFAULT 0,
      version TEXT,
      data TEXT
    ) WITHOUT ROWID;

    ${edgeTableSql('edge_minute')}
    ${edgeTableSql('edge_hour')}
    ${edgeTableSql('edge_day')}

    ${viewerTableSql('viewers_minute', 'minute')}
    ${viewerTableSql('viewers_day', 'day')}

    CREATE TABLE IF NOT EXISTS origins (
      origin TEXT PRIMARY KEY,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      requests INTEGER NOT NULL DEFAULT 0,
      boots INTEGER NOT NULL DEFAULT 0,
      session_minutes INTEGER NOT NULL DEFAULT 0,
      plays INTEGER NOT NULL DEFAULT 0,
      bytes_est INTEGER NOT NULL DEFAULT 0,
      last_provider TEXT,
      last_tier TEXT
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS idx_origins_last_seen ON origins(last_seen);
    CREATE INDEX IF NOT EXISTS idx_origins_requests ON origins(requests);

    CREATE TABLE IF NOT EXISTS origin_minute (
      minute INTEGER NOT NULL,
      origin TEXT NOT NULL,
      provider TEXT NOT NULL,
      requests INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (minute, origin, provider)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS titles (
      key TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      content TEXT NOT NULL,
      episode TEXT NOT NULL,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      boots INTEGER NOT NULL DEFAULT 0,
      session_minutes INTEGER NOT NULL DEFAULT 0,
      plays INTEGER NOT NULL DEFAULT 0,
      bytes_est INTEGER NOT NULL DEFAULT 0,
      watch_s INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS idx_titles_last_seen ON titles(last_seen);

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      level TEXT NOT NULL,
      source TEXT NOT NULL,
      kind TEXT NOT NULL,
      message TEXT NOT NULL,
      data TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source, ts);

    CREATE TABLE IF NOT EXISTS system_samples (
      ts INTEGER PRIMARY KEY,
      cpu_pct REAL NOT NULL DEFAULT 0,
      load1 REAL NOT NULL DEFAULT 0,
      load5 REAL NOT NULL DEFAULT 0,
      load15 REAL NOT NULL DEFAULT 0,
      mem_used_mb REAL NOT NULL DEFAULT 0,
      mem_total_mb REAL NOT NULL DEFAULT 0,
      swap_used_mb REAL NOT NULL DEFAULT 0,
      disk_used_gb REAL NOT NULL DEFAULT 0,
      disk_total_gb REAL NOT NULL DEFAULT 0,
      net_rx_bps REAL NOT NULL DEFAULT 0,
      net_tx_bps REAL NOT NULL DEFAULT 0,
      nginx_active INTEGER,
      nginx_rps REAL,
      workers_online INTEGER NOT NULL DEFAULT 0,
      worker_rss_mb REAL NOT NULL DEFAULT 0
    ) WITHOUT ROWID;
  `);
  db.exec('PRAGMA user_version = 2');

  const stmt = {
    insertSnapshot: db.prepare(`INSERT OR REPLACE INTO snapshots
      (ts, worker, port, requests, req4xx, req5xx, slow, inflight, rss_mb, heap_mb,
       cpu_pct, elag_ms, cache_hits, cache_upstream, prefetch, client_inflight, cache_mb, uptime_s, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    upsertWorker: db.prepare(`INSERT INTO workers (worker, port, first_seen, last_seen, uptime_s, version, data)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(worker) DO UPDATE SET
        port = excluded.port,
        last_seen = excluded.last_seen,
        uptime_s = excluded.uptime_s,
        version = excluded.version,
        data = excluded.data`),
    edgeMinute: db.prepare(upsertSql('edge_minute', 'bucket', EDGE_FIELDS, { maxFields: ['rt_max'] })),
    edgeHour: db.prepare(upsertSql('edge_hour', 'bucket', EDGE_FIELDS, { maxFields: ['rt_max'] })),
    edgeDay: db.prepare(upsertSql('edge_day', 'bucket', EDGE_FIELDS, { maxFields: ['rt_max'] })),
    viewersMinute: db.prepare(upsertSql('viewers_minute', 'minute', VIEWER_FIELDS, {
      dimensionFields: ['origin', 'provider', 'tier', 'content', 'episode']
    })),
    viewersDay: db.prepare(upsertSql('viewers_day', 'day', VIEWER_FIELDS, {
      dimensionFields: ['origin', 'provider', 'tier', 'content', 'episode']
    })),
    upsertOrigin: db.prepare(`INSERT INTO origins
      (origin, first_seen, last_seen, requests, boots, session_minutes, plays, bytes_est, last_provider, last_tier)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(origin) DO UPDATE SET
        last_seen = excluded.last_seen,
        requests = requests + excluded.requests,
        boots = boots + excluded.boots,
        session_minutes = session_minutes + excluded.session_minutes,
        plays = plays + excluded.plays,
        bytes_est = bytes_est + excluded.bytes_est,
        last_provider = excluded.last_provider,
        last_tier = excluded.last_tier`),
    bumpOriginRequest: db.prepare(`INSERT INTO origins
      (origin, first_seen, last_seen, requests, last_provider, last_tier)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(origin) DO UPDATE SET
        last_seen = excluded.last_seen,
        requests = requests + excluded.requests,
        last_provider = excluded.last_provider,
        last_tier = excluded.last_tier`),
    upsertOriginMinute: db.prepare(`INSERT INTO origin_minute (minute, origin, provider, requests)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(minute, origin, provider) DO UPDATE SET requests = requests + excluded.requests`),
    upsertTitle: db.prepare(`INSERT INTO titles
      (key, provider, content, episode, first_seen, last_seen, boots, session_minutes, plays, bytes_est, watch_s)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        last_seen = excluded.last_seen,
        boots = boots + excluded.boots,
        session_minutes = session_minutes + excluded.session_minutes,
        plays = plays + excluded.plays,
        bytes_est = bytes_est + excluded.bytes_est,
        watch_s = watch_s + excluded.watch_s`),
    insertEvent: db.prepare(`INSERT INTO events (ts, level, source, kind, message, data)
      VALUES (?, ?, ?, ?, ?, ?)`),
    insertSystemSample: db.prepare(`INSERT OR REPLACE INTO system_samples
      (ts, cpu_pct, load1, load5, load15, mem_used_mb, mem_total_mb, swap_used_mb,
       disk_used_gb, disk_total_gb, net_rx_bps, net_tx_bps, nginx_active, nginx_rps,
       workers_online, worker_rss_mb)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    getMeta: db.prepare('SELECT value FROM meta WHERE key = ?'),
    setMeta: db.prepare(`INSERT INTO meta (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
  };

  let transactionDepth = 0;
  function transaction(fn) {
    const outer = transactionDepth === 0;
    if (outer) db.exec('BEGIN');
    transactionDepth++;
    try {
      const result = fn();
      transactionDepth--;
      if (outer) db.exec('COMMIT');
      return result;
    } catch (error) {
      transactionDepth--;
      if (outer) {
        try { db.exec('ROLLBACK'); } catch { /* connection already broken */ }
      }
      throw error;
    }
  }

  function getMeta(key) {
    const row = stmt.getMeta.get(key);
    return row ? row.value : null;
  }

  function setMeta(key, value) {
    stmt.setMeta.run(key, String(value));
  }

  function recordSnapshots(snapshots, now) {
    const dataOf = (snap) => {
      if (!snap.data) return null;
      return typeof snap.data === 'string' ? snap.data : JSON.stringify(snap.data);
    };
    transaction(() => {
      for (const snap of snapshots) {
        const ts = Number(snap.ts) || now;
        stmt.insertSnapshot.run(
          ts,
          String(snap.worker || 'unknown'),
          Number(snap.port) || null,
          Number(snap.requests) || 0,
          Number(snap.req4xx) || 0,
          Number(snap.req5xx) || 0,
          Number(snap.slow) || 0,
          Number(snap.inflight) || 0,
          Number(snap.rssMB) || 0,
          Number(snap.heapMB) || 0,
          Number(snap.cpuPct) || 0,
          Number(snap.elagMs) || 0,
          Number(snap.cacheHits) || 0,
          Number(snap.cacheUpstream) || 0,
          Number(snap.prefetch) || 0,
          Number(snap.clientInflight) || 0,
          Number(snap.cacheMB) || 0,
          Number(snap.uptimeS) || 0,
          dataOf(snap)
        );
        stmt.upsertWorker.run(
          String(snap.worker || 'unknown'),
          Number(snap.port) || null,
          Number(snap.firstSeen) || now,
          now,
          Number(snap.uptimeS) || 0,
          snap.version || null,
          dataOf(snap)
        );
      }
    });
  }

  function flushEdge(minute, bucket) {
    const values = [minute, ...EDGE_FIELDS.map((field) => Number(bucket[field]) || 0)];
    const hour = Math.floor(minute / 60) * 60;
    const day = Math.floor(minute / 1440) * 1440;
    transaction(() => {
      stmt.edgeMinute.run(...values);
      stmt.edgeHour.run(hour, ...values.slice(1));
      stmt.edgeDay.run(day, ...values.slice(1));
    });
  }

  function flushViewers(rows, minute) {
    if (!rows.length) return;
    const hour = Math.floor(minute / 60) * 60;
    const day = Math.floor(minute / 1440) * 1440;
    transaction(() => {
      for (const row of rows) {
        const values = VIEWER_FIELDS.map((field) => Number(row[field]) || 0);
        stmt.viewersMinute.run(minute, row.origin, row.provider, row.tier, row.content || '', row.episode || '', ...values);
        stmt.viewersDay.run(day, row.origin, row.provider, row.tier, row.content || '', row.episode || '', ...values);
        stmt.upsertOrigin.run(
          row.origin,
          minute * 60000,
          minute * 60000,
          0,
          Number(row.boots) || 0,
          Number(row.session_minutes) || 0,
          Number(row.plays) || 0,
          Number(row.bytes_est) || 0,
          row.provider,
          row.tier
        );
        if (row.content) {
          stmt.upsertTitle.run(
            `${row.provider}|${row.content}|${row.episode || ''}`,
            row.provider,
            row.content,
            row.episode || '',
            minute * 60000,
            minute * 60000,
            Number(row.boots) || 0,
            Number(row.session_minutes) || 0,
            Number(row.plays) || 0,
            Number(row.bytes_est) || 0,
            Number(row.watch_s) || 0
          );
        }
      }
    });
  }

  // Embed-page Referer hits from nginx. Aggregated per minute by edge.js.
  function flushOriginMinute(minute, entries) {
    if (!entries.length) return;
    const now = minute * 60000;
    transaction(() => {
      for (const entry of entries) {
        const requests = Number(entry.requests) || 0;
        stmt.upsertOriginMinute.run(minute, entry.origin, entry.provider || 'other', requests);
        stmt.bumpOriginRequest.run(
          entry.origin,
          now,
          now,
          requests,
          entry.provider || null,
          entry.tier || null
        );
      }
    });
  }

  function insertEvents(events) {
    if (!events.length) return;
    transaction(() => {
      for (const event of events) {
        stmt.insertEvent.run(
          Number(event.ts) || Date.now(),
          event.level || 'info',
          event.source || 'collector',
          event.kind || 'event',
          String(event.message || '').slice(0, 2000),
          event.data ? JSON.stringify(event.data).slice(0, 8000) : null
        );
      }
    });
  }

  function insertSystemSample(sample) {
    stmt.insertSystemSample.run(
      Number(sample.ts) || Date.now(),
      Number(sample.cpuPct) || 0,
      Number(sample.load1) || 0,
      Number(sample.load5) || 0,
      Number(sample.load15) || 0,
      Number(sample.memUsedMB) || 0,
      Number(sample.memTotalMB) || 0,
      Number(sample.swapUsedMB) || 0,
      Number(sample.diskUsedGB) || 0,
      Number(sample.diskTotalGB) || 0,
      Number(sample.netRxBps) || 0,
      Number(sample.netTxBps) || 0,
      sample.nginxActive == null ? null : Number(sample.nginxActive),
      sample.nginxRps == null ? null : Number(sample.nginxRps),
      Number(sample.workersOnline) || 0,
      Number(sample.workerRssMB) || 0
    );
  }

  function dbSizeBytes() {
    try {
      const pageCount = Number(db.prepare('PRAGMA page_count').get().page_count) || 0;
      const pageSize = Number(db.prepare('PRAGMA page_size').get().page_size) || 0;
      return pageCount * pageSize;
    } catch {
      return 0;
    }
  }

  function prune(now = Date.now()) {
    const { retention, originMax, titleMax, dbMaxMB } = config;
    const day = 86400000;
    const counts = {};
    transaction(() => {
      counts.snapshots = db.prepare('DELETE FROM snapshots WHERE ts < ?')
        .run(now - retention.rawHours * 3600000).changes;
      counts.rawRequests = db.prepare("DELETE FROM events WHERE source = 'edge' AND kind = 'request' AND ts < ?")
        .run(now - retention.rawRequestHours * 3600000).changes;
      counts.events = db.prepare('DELETE FROM events WHERE ts < ?')
        .run(now - retention.eventDays * day).changes;
      counts.edgeMinute = db.prepare('DELETE FROM edge_minute WHERE bucket < ?')
        .run(Math.floor((now - retention.minuteDays * day) / 60000)).changes;
      counts.viewersMinute = db.prepare('DELETE FROM viewers_minute WHERE minute < ?')
        .run(Math.floor((now - retention.minuteDays * day) / 60000)).changes;
      counts.originMinute = db.prepare('DELETE FROM origin_minute WHERE minute < ?')
        .run(Math.floor((now - retention.minuteDays * day) / 60000)).changes;
      counts.edgeHour = db.prepare('DELETE FROM edge_hour WHERE bucket < ?')
        .run(Math.floor((now - retention.hourDays * day) / 3600000)).changes;
      counts.edgeDay = db.prepare('DELETE FROM edge_day WHERE bucket < ?')
        .run(Math.floor((now - retention.dayDays * day) / 60000)).changes;
      counts.viewersDay = db.prepare('DELETE FROM viewers_day WHERE day < ?')
        .run(Math.floor((now - retention.dayDays * day) / 60000)).changes;
      counts.workers = db.prepare('DELETE FROM workers WHERE last_seen < ?')
        .run(now - 7 * day).changes;
      counts.origins = db.prepare(`DELETE FROM origins WHERE origin IN (
        SELECT origin FROM origins ORDER BY last_seen DESC LIMIT -1 OFFSET ?)`)
        .run(originMax).changes;
      counts.titles = db.prepare(`DELETE FROM titles WHERE key IN (
        SELECT key FROM titles ORDER BY last_seen DESC LIMIT -1 OFFSET ?)`)
        .run(titleMax).changes;
    });

    let size = dbSizeBytes();
    const cap = dbMaxMB * 1024 * 1024;
    if (size > cap) {
      transaction(() => {
        db.prepare("DELETE FROM events WHERE ts < ?").run(now - 12 * 3600000);
        db.prepare('DELETE FROM snapshots WHERE ts < ?').run(now - 6 * 3600000);
        db.prepare('DELETE FROM edge_minute WHERE bucket < ?').run(Math.floor((now - 2 * day) / 60000));
        db.prepare('DELETE FROM viewers_minute WHERE minute < ?').run(Math.floor((now - 2 * day) / 60000));
        db.prepare('DELETE FROM edge_hour WHERE bucket < ?').run(Math.floor((now - 60 * day) / 3600000));
      });
      size = dbSizeBytes();
      counts.emergency = true;
    }
    try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* busy */ }
    return { ...counts, size, overCap: size > cap, cap };
  }

  function rowCounts() {
    const one = (table) => Number(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n) || 0;
    return {
      snapshots: one('snapshots'),
      edgeMinute: one('edge_minute'),
      edgeHour: one('edge_hour'),
      edgeDay: one('edge_day'),
      viewersMinute: one('viewers_minute'),
      viewersDay: one('viewers_day'),
      originMinute: one('origin_minute'),
      origins: one('origins'),
      titles: one('titles'),
      events: one('events'),
      systemSamples: one('system_samples')
    };
  }

  function close() {
    try { db.close(); } catch { /* already closed */ }
  }

  return {
    db,
    getMeta,
    setMeta,
    recordSnapshots,
    flushEdge,
    flushViewers,
    flushOriginMinute,
    insertEvents,
    insertSystemSample,
    prune,
    dbSizeBytes,
    rowCounts,
    close
  };
}

module.exports = {
  openStore,
  emptyEdgeBucket,
  EDGE_FIELDS,
  VIEWER_FIELDS
};
