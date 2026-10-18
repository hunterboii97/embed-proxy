const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const LOCK_STALE_MS = 5000;
const LOCK_WAIT_MS = 750;
const FILE_TTL_MS = 7 * DAY_MS;
const PRUNE_INTERVAL_MS = 6 * 60 * 60 * 1000;

let lastPrune = 0;

// Atomics.wait gives us a tiny synchronous sleep without burning CPU. The
// lock is only contended when the same IP starts two downloads at once.
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function prune(dir) {
  const cutoff = Date.now() - FILE_TTL_MS;
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    try {
      if (fs.statSync(file).mtimeMs < cutoff) fs.unlinkSync(file);
    } catch {}
  }
}

function acquireLock(lockFile) {
  const start = Date.now();
  while (true) {
    try {
      fs.closeSync(fs.openSync(lockFile, 'wx'));
      return true;
    } catch (err) {
      if (err.code !== 'EEXIST') return false;
      try {
        if (Date.now() - fs.statSync(lockFile).mtimeMs > LOCK_STALE_MS) {
          fs.unlinkSync(lockFile);
          continue;
        }
      } catch {}
      if (Date.now() - start >= LOCK_WAIT_MS) return false;
      sleepSync(10);
    }
  }
}

// Enforces both limits across every worker: each IP gets one small append-only
// log, serialized by an O_EXCL lock file. Files live under data/ (gitignored).
function consumeDownloadQuota(ip, { dir, perMinute, perDay }) {
  if (!perMinute && !perDay) {
    return { allowed: true, reason: '', retryAfter: 0, remaining: Infinity };
  }

  fs.mkdirSync(dir, { recursive: true });
  const now = Date.now();
  if (now - lastPrune > PRUNE_INTERVAL_MS) {
    lastPrune = now;
    try { prune(dir); } catch {}
  }

  const key = crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex').slice(0, 32);
  const file = path.join(dir, `${key}.log`);
  const lockFile = `${file}.lock`;

  if (!acquireLock(lockFile)) {
    return { allowed: false, reason: 'busy', retryAfter: 2, remaining: 0 };
  }

  try {
    let stamps = [];
    try {
      stamps = fs.readFileSync(file, 'utf8')
        .split('\n')
        .map(line => parseInt(line, 10))
        .filter(stamp => Number.isFinite(stamp) && stamp > now - DAY_MS);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }

    const lastMinute = stamps.filter(stamp => stamp > now - MINUTE_MS).length;
    if (perMinute > 0 && lastMinute >= perMinute) {
      const oldest = stamps.find(stamp => stamp > now - MINUTE_MS) || now;
      return {
        allowed: false,
        reason: 'minute',
        retryAfter: Math.max(1, Math.ceil((oldest + MINUTE_MS - now) / 1000)),
        remaining: Math.max(0, perDay - stamps.length)
      };
    }
    if (perDay > 0 && stamps.length >= perDay) {
      const oldest = stamps[0] || now;
      return {
        allowed: false,
        reason: 'day',
        retryAfter: Math.max(1, Math.ceil((oldest + DAY_MS - now) / 1000)),
        remaining: 0
      };
    }

    stamps.push(now);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, stamps.join('\n') + '\n');
    fs.renameSync(tmp, file);
    return {
      allowed: true,
      reason: '',
      retryAfter: 0,
      remaining: perDay > 0 ? Math.max(0, perDay - stamps.length) : Infinity
    };
  } finally {
    try { fs.unlinkSync(lockFile); } catch {}
  }
}

module.exports = { consumeDownloadQuota };
