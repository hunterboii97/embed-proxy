const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const LOCK_STALE_MS = 5000;
const LOCK_WAIT_MS = 750;
const FILE_TTL_MS = 7 * DAY_MS;
const PRUNE_INTERVAL_MS = 6 * 60 * 60 * 1000;

let lastPrune = 0;
let pruneInflight = null;

async function prune(dir) {
  const cutoff = Date.now() - FILE_TTL_MS;
  const names = await fsp.readdir(dir);
  for (const name of names) {
    const file = path.join(dir, name);
    try {
      const st = await fsp.stat(file);
      if (st.mtimeMs < cutoff) await fsp.unlink(file);
    } catch {}
  }
}

// Polling with setTimeout instead of Atomics.wait: the old lock blocked the
// entire event loop for up to 750ms per contended download, freezing every
// other request served by this worker.
async function acquireLock(lockFile) {
  const start = Date.now();
  while (true) {
    try {
      const handle = await fsp.open(lockFile, 'wx');
      await handle.close();
      return true;
    } catch (err) {
      if (err.code !== 'EEXIST') return false;
      try {
        const st = await fsp.stat(lockFile);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          await fsp.unlink(lockFile).catch(() => {});
          continue;
        }
      } catch {}
      if (Date.now() - start >= LOCK_WAIT_MS) return false;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

// Enforces both limits across every worker: each IP gets one small append-only
// log, serialized by an O_EXCL lock file. Files live under data/ (gitignored).
async function consumeDownloadQuota(ip, { dir, perMinute, perDay }) {
  if (!perMinute && !perDay) {
    return { allowed: true, reason: '', retryAfter: 0, remaining: Infinity };
  }

  await fsp.mkdir(dir, { recursive: true });
  const now = Date.now();
  if (now - lastPrune > PRUNE_INTERVAL_MS && !pruneInflight) {
    lastPrune = now;
    pruneInflight = prune(dir)
      .catch(() => {})
      .finally(() => { pruneInflight = null; });
  }

  const key = crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex').slice(0, 32);
  const file = path.join(dir, `${key}.log`);
  const lockFile = `${file}.lock`;

  if (!(await acquireLock(lockFile))) {
    return { allowed: false, reason: 'busy', retryAfter: 2, remaining: 0 };
  }

  try {
    let stamps = [];
    try {
      stamps = (await fsp.readFile(file, 'utf8'))
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
    await fsp.writeFile(tmp, stamps.join('\n') + '\n');
    await fsp.rename(tmp, file);
    return {
      allowed: true,
      reason: '',
      retryAfter: 0,
      remaining: perDay > 0 ? Math.max(0, perDay - stamps.length) : Infinity
    };
  } finally {
    await fsp.unlink(lockFile).catch(() => {});
  }
}

module.exports = { consumeDownloadQuota };
