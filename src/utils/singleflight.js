// Deduplicates concurrent identical async work: while one call is in flight,
// waiters share the same promise instead of firing duplicate upstream requests.
const inflight = new Map();

function singleflight(key, fn) {
  const existing = inflight.get(key);
  if (existing) return existing;

  const p = (async () => {
    try {
      return await fn();
    } finally {
      inflight.delete(key);
    }
  })();

  inflight.set(key, p);
  return p;
}

function inflightCount() {
  return inflight.size;
}

module.exports = { singleflight, inflightCount };
