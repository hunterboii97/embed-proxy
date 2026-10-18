'use strict';

const { derive } = require('./aggregate');

function flagValue() {
  return /^(1|true|yes|on)$/i.test(String(process.env.ADMIN_METRICS || '').trim());
}

function createAlerts({ store, ingest, edge, config, logger }) {
  let active = new Map();
  let metricsEnabled = flagValue();
  let timer = null;

  function evaluate() {
    const now = Date.now();
    const next = new Map();
    const add = (key, level, title, message) => {
      next.set(key, { key, level, title, message, since: active.get(key)?.since || now });
    };

    const workers = ingest.workerSummary();
    // Fresh collectors have no snapshots for one interval; do not alarm on
    // the normal startup gap.
    const startupGrace = now - config.startedAt < Math.max(60000, config.snapshotMs * 3);
    if (metricsEnabled && !startupGrace) {
      if (workers.online === 0) {
        add('workers-down', 'critical', 'No worker snapshots', 'Worker metrics are enabled but no worker has reported recently.');
      } else if (workers.online < workers.expected) {
        add('workers-partial', 'warn', 'Worker offline', `${workers.online}/${workers.expected} workers are reporting.`);
      }
      const latest = Array.from(ingest.latestWorkers.values());
      const hotLoop = latest.find((snap) => snap.elagMs >= 250);
      if (hotLoop) {
        add('event-loop', hotLoop.elagMs >= 1000 ? 'critical' : 'warn',
          'Event loop lag',
          `${hotLoop.worker} event loop lag is ${Math.round(hotLoop.elagMs)} ms.`);
      }
      const fatWorker = latest.find((snap) => snap.rssMB >= 1500);
      if (fatWorker) {
        add('worker-memory', 'warn', 'Worker memory high',
          `${fatWorker.worker} RSS is ${Math.round(fatWorker.rssMB)} MB.`);
      }
      const prefetch = latest.reduce((sum, snap) => sum + (snap.prefetch || 0), 0);
      if (prefetch >= 48) {
        add('prefetch-load', 'warn', 'Prefetch backlog', `${prefetch} prefetch jobs are in flight.`);
      }
    }

    const nowBucket = Math.floor(now / 60000);
    const window = store.db.prepare(`
      SELECT SUM(requests) AS requests, SUM(s5xx) AS s5xx, SUM(cache_hit) AS cache_hit,
             SUM(cache_miss) AS cache_miss, SUM(cache_bypass) AS cache_bypass,
             SUM(rt_sum) AS rt_sum, SUM(rt_b0) AS rt_b0, SUM(rt_b1) AS rt_b1,
             SUM(rt_b2) AS rt_b2, SUM(rt_b3) AS rt_b3, SUM(rt_b4) AS rt_b4,
             SUM(rt_b5) AS rt_b5, SUM(rt_b6) AS rt_b6, SUM(rt_b7) AS rt_b7
      FROM edge_minute WHERE bucket >= ? AND bucket <= ?
    `).get(nowBucket - 15, nowBucket) || {};
    const live = edge ? edge.live() : null;
    if (live && live.minute != null) {
      for (const field of ['requests', 's5xx', 'cache_hit', 'cache_miss', 'cache_bypass', 'rt_sum',
        'rt_b0', 'rt_b1', 'rt_b2', 'rt_b3', 'rt_b4', 'rt_b5', 'rt_b6', 'rt_b7']) {
        window[field] = (Number(window[field]) || 0) + (Number(live.bucket[field]) || 0);
      }
    }
    const stats = derive(window);
    if (stats.requests > 200 && stats.errorRate > 3) {
      add('error-rate', 'critical', 'Elevated 5xx', `${stats.errorRate.toFixed(1)}% 5xx over the last 15 min.`);
    } else if (stats.requests > 200 && stats.errorRate > 1) {
      add('error-rate', 'warn', '5xx above baseline', `${stats.errorRate.toFixed(1)}% 5xx over the last 15 min.`);
    }
    if (stats.requests > 200 && stats.p95Ms > 5000) {
      add('latency', 'critical', 'Latency critical', `p95 is ${Math.round(stats.p95Ms)} ms over the last 15 min.`);
    } else if (stats.requests > 200 && stats.p95Ms > 2500) {
      add('latency', 'warn', 'Latency elevated', `p95 is ${Math.round(stats.p95Ms)} ms over the last 15 min.`);
    }
    if (stats.requests > 1000 && stats.cacheHitPct < 40) {
      add('cache-hit', 'warn', 'Cache hit rate low', `Cache hit rate is ${stats.cacheHitPct.toFixed(1)}% over the last 15 min.`);
    }

    const lastSys = store.db.prepare('SELECT * FROM system_samples ORDER BY ts DESC LIMIT 1').get();
    if (lastSys && now - Number(lastSys.ts) < 5 * 60000) {
      if (lastSys.disk_total_gb > 0) {
        const used = Number(lastSys.disk_used_gb) / Number(lastSys.disk_total_gb);
        if (used > 0.92) add('disk', 'critical', 'Disk almost full', `${(used * 100).toFixed(1)}% of disk is used.`);
        else if (used > 0.85) add('disk', 'warn', 'Disk usage high', `${(used * 100).toFixed(1)}% of disk is used.`);
      }
      if (lastSys.mem_total_mb > 0 && Number(lastSys.mem_used_mb) / Number(lastSys.mem_total_mb) > 0.93) {
        add('memory', 'warn', 'Host memory high', `${Math.round((Number(lastSys.mem_used_mb) / Number(lastSys.mem_total_mb)) * 100)}% of RAM is used.`);
      }
    }

    const edgeStats = edge ? edge.stats() : null;
    const lastEdgeSignal = edgeStats && (edgeStats.lastLineAt || edgeStats.startedAt);
    if (edgeStats && edgeStats.enabled && edgeStats.running && now - lastEdgeSignal > 5 * 60000) {
      add('edge-silent', 'warn', 'No edge log lines', 'nginx has not written a new log line for 5 minutes.');
    }
    if (edgeStats && edgeStats.error) {
      add('edge-error', 'warn', 'Edge ingestion error', edgeStats.error.slice(0, 160));
    }
    if (!config.ingestToken) {
      add('ingest-token', 'warn', 'Ingest token missing', 'ADMIN_INGEST_TOKEN is not set; worker snapshots are rejected.');
    }
    if (!config.telemetryEnabled) {
      add('telemetry-off', 'info', 'Player telemetry disabled', 'Viewers, embed origins and quality need ADMIN_TELEMETRY=1.');
    }

    const dbSize = store.dbSizeBytes();
    const cap = config.dbMaxMB * 1024 * 1024;
    if (dbSize > cap) add('db-size', 'critical', 'Database over cap', `${(dbSize / 1024 / 1024).toFixed(0)} MB used, cap is ${config.dbMaxMB} MB.`);
    else if (dbSize > cap * 0.8) add('db-size', 'warn', 'Database nearing cap', `${(dbSize / 1024 / 1024).toFixed(0)} MB of ${config.dbMaxMB} MB used.`);

    for (const [key, alert] of next) {
      if (!active.has(key)) {
        if (alert.level !== 'info') {
          logger(`[alert] ${alert.title}: ${alert.message}`, 'warn');
        }
        if (alert.level !== 'info' || active.size) {
          try {
            store.insertEvents([{
              ts: now,
              level: alert.level === 'critical' ? 'error' : alert.level === 'warn' ? 'warn' : 'info',
              source: 'collector',
              kind: 'alert',
              message: `${alert.title}: ${alert.message}`,
              data: { key }
            }]);
          } catch { /* non-fatal */ }
        }
      }
    }
    for (const [key, previous] of active) {
      if (!next.has(key) && previous.level !== 'info') {
        try {
          store.insertEvents([{
            ts: now,
            level: 'info',
            source: 'collector',
            kind: 'alert',
            message: `Resolved: ${previous.title}`,
            data: { key }
          }]);
        } catch { /* non-fatal */ }
      }
    }
    active = next;
    return list();
  }

  function list() {
    const order = { critical: 0, warn: 1, info: 2 };
    return Array.from(active.values()).sort((a, b) => order[a.level] - order[b.level]);
  }

  function start() {
    metricsEnabled = flagValue();
    evaluate();
    timer = setInterval(evaluate, Math.max(15000, config.snapshotMs));
    timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
  }

  return { start, stop, evaluate, list };
}

module.exports = { createAlerts };
