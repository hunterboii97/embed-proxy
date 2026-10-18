'use strict';

const path = require('node:path');
require('dotenv').config();

const ROOT = path.join(__dirname, '..');

function bool(value, fallback = false) {
  if (value === undefined || String(value).trim() === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function integer(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function list(value) {
  return String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const dataDir = path.resolve(process.env.ADMIN_DATA_DIR || path.join(ROOT, 'data', 'admin'));

module.exports = {
  ROOT,
  version: require('../package.json').version,

  // Collector listener. Never expose this port publicly: nginx is the only
  // public entry point, and the IP allowlist below is evaluated here.
  host: process.env.ADMIN_LISTEN_HOST || '127.0.0.1',
  port: integer(process.env.ADMIN_PORT, 5100, 1024, 65535),

  // Fail-closed allowlist. Empty = loopback only (local curl/testing).
  // Accepts exact IPv4/IPv6 addresses and CIDR ranges. Do NOT put Cloudflare
  // ranges here — nginx resolves the real viewer IP via set_real_ip_from.
  allowedIPs: list(process.env.ADMIN_ALLOWED_IPS),

  dataDir,
  dbPath: path.join(dataDir, 'admin.db'),

  // nginx edge source. Empty = edge ingestion disabled (workers/telemetry only).
  edgeLogPath: String(process.env.ADMIN_EDGE_LOG || '').trim(),
  // Optional host filter for shared access logs (comma separated).
  edgeHosts: list(process.env.ADMIN_EDGE_HOSTS || ''),
  nginxStatusUrl: String(process.env.ADMIN_NGINX_STATUS || '').trim(),

  // Shared secret for worker -> collector snapshots (loopback only).
  ingestToken: String(process.env.ADMIN_INGEST_TOKEN || '').trim(),

  // Player-side beacons. Off by default: enabling adds a tiny async POST per
  // player every 30 s and unlocks viewer/origin/quality telemetry.
  telemetryEnabled: bool(process.env.ADMIN_TELEMETRY, false),

  // 30 s default (user-facing cadence is also 30 s). Min 15 s to prevent a
  // misconfiguration from turning monitoring into a load source.
  snapshotMs: integer(process.env.ADMIN_SNAPSHOT_MS, 30000, 15000, 300000),
  expectedWorkers: integer(process.env.ADMIN_EXPECTED_WORKERS, 6, 1, 64),

  // Referer hosts that are our own site and should not appear as embedders.
  ignoreOrigins: list(process.env.ADMIN_IGNORE_ORIGINS || 'mikaza.buzz,www.mikaza.buzz'),

  // Retention. Raw = per-worker snapshots; zoom levels mirror the UI ranges.
  retention: {
    rawHours: integer(process.env.ADMIN_RAW_HOURS, 24, 1, 720),
    minuteDays: integer(process.env.ADMIN_MINUTE_DAYS, 7, 1, 90),
    hourDays: integer(process.env.ADMIN_HOUR_DAYS, 90, 1, 730),
    dayDays: integer(process.env.ADMIN_DAY_DAYS, 365, 7, 3650),
    eventDays: integer(process.env.ADMIN_EVENT_DAYS, 7, 1, 365),
    rawRequestHours: integer(process.env.ADMIN_RAW_REQUEST_HOURS, 24, 1, 168)
  },

  // Fraction of successful edge requests persisted as log lines. Errors and
  // slow requests are always kept (subject to a per-second writer budget).
  logSample: Math.min(1, Math.max(0, Number(process.env.ADMIN_LOG_SAMPLE || 0.02))),

  originMax: integer(process.env.ADMIN_ORIGIN_MAX, 4000, 100, 100000),
  titleMax: integer(process.env.ADMIN_TITLE_MAX, 5000, 100, 200000),
  dbMaxMB: integer(process.env.ADMIN_DB_MAX_MB, 512, 64, 65536),

  // Telemetry abuse guard (per source IP). Generous enough for large NAT
  // pools; telemetry is self-reported and cannot affect playback.
  telemetryPerMin: integer(process.env.ADMIN_TELEMETRY_PER_MIN, 1200, 60, 100000),

  startedAt: Date.now()
};
