'use strict';

/**
 * Admin monitoring collector.
 *
 * Runs as its own process, separate from the player workers, so a slow query,
 * SQLite write or dashboard request can never touch playback. Workers push
 * small loopback snapshots; nginx feeds exact edge counters through a JSON
 * access log; the player sends opt-in beacons. This process owns all SQL
 * aggregation, retention and the admin UI.
 */

const config = require('./config');
const { openStore } = require('./store');
const { createIngest } = require('./ingest');
const { createEdgeIngestor } = require('./edge');
const { createSystemSampler } = require('./system');
const { createAlerts } = require('./alerts');
const { createAdminServer } = require('./server');

function stamp() {
  return new Date().toISOString().slice(11, 19);
}

function logger(message, level = 'info') {
  const prefix = level === 'error' ? 'ERR ' : level === 'warn' ? 'WRN ' : '';
  const line = `${stamp()} ${prefix}${message}`;
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

async function main() {
  let store;
  try {
    store = openStore(config);
  } catch (error) {
    logger(`Failed opening admin database at ${config.dbPath}: ${error.message}`, 'error');
    process.exit(1);
  }

  const ingest = createIngest({ config, store, logger });
  const edge = createEdgeIngestor({ config, store, logger });
  const system = createSystemSampler({
    config,
    store,
    logger,
    workersSummary: () => ingest.workerSummary()
  });
  const alerts = createAlerts({ store, ingest, edge, config, logger });
  const server = createAdminServer({ config, store, edge, ingest, alerts, system, logger });

  let pruneTimer = null;
  let shuttingDown = false;

  function pruneNow() {
    try {
      const result = store.prune(Date.now());
      store.lastPrune = { ...result, ts: Date.now() };
      logger(`[retention] pruned ${Object.entries(result)
        .filter(([key, value]) => key !== 'size' && key !== 'overCap' && key !== 'cap' && value)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ') || 'nothing'}; db=${(result.size / 1024 / 1024).toFixed(1)}MB`);
      if (result.overCap) {
        logger(`[retention] database still over ${result.cap / 1024 / 1024}MB cap after emergency prune`, 'warn');
      }
    } catch (error) {
      logger(`[retention] prune failed: ${error.message}`, 'error');
    }
  }

  try {
    store.insertEvents([{
      ts: Date.now(),
      level: 'info',
      source: 'collector',
      kind: 'startup',
      message: `Collector started (v${config.version}, node ${process.version})`,
      data: {
        port: config.port,
        snapshotMs: config.snapshotMs,
        edge: Boolean(config.edgeLogPath),
        telemetry: config.telemetryEnabled,
        allowlistRules: config.allowedIPs.length
      }
    }]);
  } catch { /* non-fatal */ }

  ingest.start();
  edge.start();
  system.start();
  alerts.start();
  server.start();
  pruneNow();
  pruneTimer = setInterval(pruneNow, 15 * 60 * 1000);
  pruneTimer.unref();

  logger(`[admin] ready — edge=${config.edgeLogPath || 'off'} telemetry=${config.telemetryEnabled ? 'on' : 'off'} snapshot=${config.snapshotMs}ms`);
  if (!config.allowedIPs.length) {
    logger('[admin] ADMIN_ALLOWED_IPS is empty; dashboard is reachable from loopback only');
  }
  if (!config.ingestToken) {
    logger('[admin] ADMIN_INGEST_TOKEN is empty; worker snapshots will be rejected');
  }

  async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    logger(`[admin] ${signal} received, shutting down`);
    if (pruneTimer) clearInterval(pruneTimer);
    alerts.stop();
    system.stop();
    edge.stop();
    ingest.stop();
    await server.stop();
    try {
      store.insertEvents([{
        ts: Date.now(),
        level: 'info',
        source: 'collector',
        kind: 'shutdown',
        message: `Collector stopped (${signal})`
      }]);
    } catch { /* non-fatal */ }
    store.close();
    process.exit(0);
  }

  process.on('SIGTERM', () => { shutdown('SIGTERM').catch(() => process.exit(1)); });
  process.on('SIGINT', () => { shutdown('SIGINT').catch(() => process.exit(1)); });
}

main().catch((error) => {
  logger(`Fatal: ${error.stack || error.message}`, 'error');
  process.exit(1);
});
