const fs = require('node:fs');
const path = require('node:path');

const LOCK_STALE_MS = 5000;
const MAX_WAIT_MS = 15000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ani.pm's nginx allows only ~14 download-link requests per 10 s per IP and
// answers the rest with a bare HTML 429 (no Retry-After). All workers share
// the same IP and session, so the gate lives on disk and spaces POSTs across
// every process.
function createAnipmLinkGate({ dir, minGapMs, cooldownMs }) {
  const statePath = path.join(dir, 'gate.json');
  const lockPath = path.join(dir, 'gate.lock');
  fs.mkdirSync(dir, { recursive: true });

  function readState() {
    try {
      const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  function writeState(state) {
    const tmp = `${statePath}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, statePath);
  }

  async function withLock(fn) {
    const deadline = Date.now() + LOCK_STALE_MS;
    for (;;) {
      let fd;
      try {
        fd = fs.openSync(lockPath, 'wx');
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        try {
          const stat = fs.statSync(lockPath);
          if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
            try { fs.unlinkSync(lockPath); } catch {}
            continue;
          }
        } catch {}
        if (Date.now() > deadline) throw new Error('ani.pm link gate lock timeout');
        await sleep(15 + Math.floor(Math.random() * 25));
        continue;
      }
      try {
        return fn();
      } finally {
        try { fs.closeSync(fd); } catch {}
        try { fs.unlinkSync(lockPath); } catch {}
      }
    }
  }

  async function acquire() {
    const started = Date.now();
    for (;;) {
      const waitMs = await withLock(() => {
        const state = readState();
        const now = Date.now();
        const readyAt = Math.max(
          Number(state.cooldownUntil) || 0,
          (Number(state.lastPostAt) || 0) + minGapMs
        );
        if (readyAt > now) return readyAt - now;
        writeState({ ...state, lastPostAt: now });
        return 0;
      });
      if (waitMs <= 0) return;
      if (Date.now() - started + waitMs > MAX_WAIT_MS) {
        const err = new Error('ani.pm link request budget exhausted');
        err.code = 'ANIPM_GATE_BUSY';
        err.retryAfter = Math.max(1, Math.ceil(waitMs / 1000));
        throw err;
      }
      await sleep(Math.min(waitMs, 1000) + Math.floor(Math.random() * 100));
    }
  }

  async function coolDown(ms) {
    const until = Date.now() + Math.max(0, ms || cooldownMs);
    await withLock(() => {
      const state = readState();
      if (until > (Number(state.cooldownUntil) || 0)) {
        writeState({ ...state, cooldownUntil: until });
      }
    });
  }

  return { acquire, coolDown };
}

module.exports = { createAnipmLinkGate };
