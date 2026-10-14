const { getClientIP, rateLimitEnabled } = require('../../config');

// Fixed-window per-IP counters. In-memory only — fine for a single-node
// deployment; windows reset every minute.
const WINDOW_MS = 60000;
const buckets = new Map(); // `${name}:${ip}` -> { count, resetAt }

setInterval(() => {
  const now = Date.now();
  for (const [key, b] of buckets) {
    if (now >= b.resetAt) buckets.delete(key);
  }
}, WINDOW_MS).unref();

function rateLimited(req, name, maxPerMin) {
  if (!rateLimitEnabled) return false;
  if (!maxPerMin || maxPerMin <= 0) return false;
  const key = `${name}:${getClientIP(req)}`;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now >= b.resetAt) {
    b = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, b);
  }
  b.count++;
  return b.count > maxPerMin;
}

module.exports = { rateLimited };
