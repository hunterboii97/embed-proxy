// Bounded per-waiter writer. The shared segment fetch must never await a slow
// viewer; writes are queued and drained asynchronously, and a viewer whose
// backlog exceeds the cap is disconnected instead of throttling everyone else
// on the same flight.
const MAX_QUEUED_BYTES = Math.max(
  64 * 1024,
  parseInt(process.env.WAITER_QUEUE_CAP_BYTES || '', 10) || 4 * 1024 * 1024
);

function createWaiterSink(rawRes) {
  const queue = [];
  let queuedBytes = 0;
  let flushing = false;
  let ending = false;
  let dead = false;

  const fail = () => {
    if (dead) return;
    dead = true;
    queue.length = 0;
    queuedBytes = 0;
    try { rawRes.destroy(); } catch {}
  };

  const finish = () => {
    if (!ending || dead || flushing || queue.length) return;
    try { if (!rawRes.writableEnded) rawRes.end(); } catch {}
  };

  const pump = () => {
    if (dead || flushing) return;
    flushing = true;
    while (queue.length) {
      const buf = queue.shift();
      queuedBytes -= buf.length;
      if (rawRes.destroyed || rawRes.writableEnded) {
        fail();
        flushing = false;
        return;
      }
      let ok;
      try {
        ok = rawRes.write(buf);
      } catch {
        fail();
        flushing = false;
        return;
      }
      if (!ok) {
        const onGone = () => { cleanup(); flushing = false; fail(); };
        const onDrain = () => { cleanup(); flushing = false; pump(); };
        const cleanup = () => {
          rawRes.off('drain', onDrain);
          rawRes.off('close', onGone);
          rawRes.off('error', onGone);
        };
        rawRes.once('drain', onDrain);
        rawRes.once('close', onGone);
        rawRes.once('error', onGone);
        return;
      }
    }
    flushing = false;
    finish();
  };

  return {
    write(buf) {
      if (dead || ending || !buf || !buf.length) return;
      // Allow one oversized chunk through when the queue is empty; cap the
      // backlog that a slow viewer can make us hold.
      if (queuedBytes > 0 && queuedBytes + buf.length > MAX_QUEUED_BYTES) {
        fail();
        return;
      }
      queue.push(buf);
      queuedBytes += buf.length;
      pump();
    },
    end() {
      if (dead || ending) return;
      ending = true;
      finish();
    },
    get dead() {
      return dead;
    }
  };
}

module.exports = { createWaiterSink, WAITER_QUEUE_CAP_BYTES: MAX_QUEUED_BYTES };
