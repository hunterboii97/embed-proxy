// Opt-in player telemetry. Dormant unless the server injects
// `telemetry.enabled` (ADMIN_TELEMETRY=1). Sends a tiny boot beacon, one
// heartbeat every 30 s while watching, and player events. Every send is
// fire-and-forget: playback never waits on it.

const HEARTBEAT_MS = 30000;

function makeSid() {
  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return `s${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`;
  }
}

function cleanOrigin(value) {
  try {
    const host = new URL(value).hostname.toLowerCase().replace(/^www\./, '');
    return /^[a-z0-9.-]+$/.test(host) ? host : '';
  } catch {
    return '';
  }
}

export function createTelemetry(config) {
  if (!config || !config.enabled || typeof window === 'undefined') return null;

  const endpoint = typeof config.endpoint === 'string' && config.endpoint.startsWith('/')
    ? config.endpoint
    : '/telemetry';
  const base = {
    sid: makeSid(),
    provider: String(config.provider || 'other'),
    tier: config.tier === 'partner' ? 'partner' : 'free',
    content: String(config.content || ''),
    episode: String(config.episode || '')
  };
  const origin = cleanOrigin(document.referrer);
  if (origin) base.origin = origin;

  let player = null;
  let hls = null;
  let timer = null;
  let playing = false;
  let playStartedAt = 0;
  let activeMs = 0;
  let lastStallAt = 0;
  let fatalSent = false;

  function post(payload, urgent = false) {
    const body = JSON.stringify({ ...base, ...payload });
    try {
      if (urgent || document.visibilityState === 'hidden') {
        if (navigator.sendBeacon) navigator.sendBeacon(endpoint, body);
        return;
      }
      fetch(endpoint, {
        method: 'POST',
        keepalive: true,
        headers: { 'Content-Type': 'application/json' },
        body
      }).catch(() => {});
    } catch { /* telemetry must never break playback */ }
  }

  function videoHeight() {
    try {
      return Math.round(player?.querySelector('video')?.videoHeight || 0);
    } catch {
      return 0;
    }
  }

  function position() {
    const t = Number(player?.currentTime);
    return Number.isFinite(t) && t > 0 ? Math.round(t * 10) / 10 : 0;
  }

  function accumulateActive(now) {
    if (playing && playStartedAt > 0) {
      activeMs += Math.max(0, now - playStartedAt);
      playStartedAt = now;
    }
  }

  function heartbeat(urgent = false) {
    const now = Date.now();
    accumulateActive(now);
    if (activeMs < 1000) return;
    const elapsedMs = Math.min(120000, activeMs);
    activeMs -= elapsedMs;
    const bitrate = Number(hls?.bandwidthEstimate) || 0;
    const bytes = bitrate > 0
      ? Math.min(200 * 1024 * 1024, Math.round((bitrate * elapsedMs) / 8000))
      : 0;
    post({ type: 'heartbeat', elapsedMs: Math.round(elapsedMs), bytes, height: videoHeight(), position: position() }, urgent);
  }

  function emit(name, extra = {}) {
    post({ type: 'event', name, position: position(), state: playing ? 'playing' : 'paused', ...extra });
  }

  function flush() {
    heartbeat(true);
  }

  function attach(el) {
    player = el;
    el.addEventListener('play', () => {
      playing = true;
      playStartedAt = Date.now();
      emit('play');
    });
    el.addEventListener('pause', () => {
      accumulateActive(Date.now());
      playing = false;
      playStartedAt = 0;
      emit('pause');
    });
    el.addEventListener('ended', () => {
      accumulateActive(Date.now());
      playing = false;
      playStartedAt = 0;
      heartbeat(true);
      emit('ended');
    });
    el.addEventListener('waiting', () => {
      const now = Date.now();
      if (now - lastStallAt < 10000) return;
      lastStallAt = now;
      emit('stall');
    });
    el.addEventListener('seeking', () => emit('seek'));
    el.addEventListener('error', () => emit('error', { message: 'media element error' }));
    window.addEventListener('pagehide', flush);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') flush();
    });
    timer = setInterval(heartbeat, HEARTBEAT_MS);
  }

  function setHls(instance) {
    hls = instance || null;
  }

  function fatal(message) {
    if (fatalSent) return;
    fatalSent = true;
    emit('fatal', { message: String(message || 'fatal stream error') });
  }

  post({ type: 'boot', meta: { content: base.content, episode: base.episode } });

  return { attach, setHls, emit, fatal, heartbeat, flush, sid: base.sid };
}
