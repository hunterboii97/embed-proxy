/* ============================================================================
 * strm-compatible player core
 * ----------------------------------------------------------------------------
 * A self-hosted drop-in replacement for the strm.cx embed.
 *   - identical query-parameter contract
 *   - identical `strmcx/v1` postMessage protocol
 * Built on Vidstack (MIT) + hls.js (Apache-2.0), both vendored locally.
 *
 * No ads. No third-party calls. Every byte is served from your own origin.
 * ==========================================================================*/

export const PROTOCOL = 'strmcx/v1';

/* -------------------------------------------------------------------------- *
 * 1. Query-parameter contract
 * -------------------------------------------------------------------------- */

export function parseParams(search = location.search) {
  const p = new URLSearchParams(search);
  const str = (k) => p.get(k) || '';
  const num = (k) => {
    const v = Number(p.get(k));
    return Number.isFinite(v) ? v : null;
  };

  let tracks = [];
  const rawTracks = str('tracks');
  if (rawTracks) {
    try {
      const parsed = JSON.parse(rawTracks);
      if (Array.isArray(parsed)) {
        // Same rule as the original: entries without `file` are dropped.
        tracks = parsed
          .filter((t) => t && t.file)
          .map((t) => ({
            src: t.file,
            label: t.label ?? t.lang ?? 'Subtitles',
            language: t.lang || '',
            kind: t.kind === 'captions' ? 'captions' : 'subtitles',
            default: !!t.default,
          }));
      }
    } catch {
      /* malformed JSON is ignored, matching upstream behaviour */
    }
  }

  // "start:end" in seconds; end must exceed start
  const range = (v) => {
    if (!v) return null;
    const [a, b] = v.split(':').map(Number);
    if (!Number.isFinite(a) || !Number.isFinite(b) || b <= a) return null;
    return { start: a, end: b };
  };

  return {
    src: str('src'),
    playlist: str('playlist'),
    embed: p.has('embed'),
    srcType: str('src-type'),
    poster: str('poster'),
    title: str('title'),
    screenshotName: str('screenshot-name') || str('title'),
    thumbnails: str('thumbnails'),
    tracks,
    intro: range(str('intro')),
    outro: range(str('outro')),
    start: num('start'),
    layout: str('layout') || 'default',
    aspect: str('aspect'),
    download: str('download'),
    autoplay: p.has('autoplay'),
    muted: p.has('muted'),
    autoskip: p.has('autoskip'),
    nextOverlay: p.has('next-overlay'),
    theater: p.has('theater'),
    hasPrev: p.has('prev'),
    hasNext: p.has('next'),
  };
}

/* -------------------------------------------------------------------------- *
 * 2. Settings persistence
 * -------------------------------------------------------------------------- */

const STORE_KEY = 'strmcx:settings';

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveSettings(patch) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ ...loadSettings(), ...patch }));
  } catch {
    /* private mode / quota — non-fatal */
  }
}

/* -------------------------------------------------------------------------- *
 * 3. Subtitle normalisation (SRT -> VTT)
 * -------------------------------------------------------------------------- */

function srtToVtt(srt) {
  return (
    'WEBVTT\n\n' +
    srt
      .replace(/\r+/g, '')
      .replace(/^\d+\s*$/gm, '')
      .replace(/(\d{2}:\d{2}:\d{2}),(\d{3})/g, '$1.$2')
      .replace(/\n{3,}/g, '\n\n')
      .trim()
  );
}

/**
 * Resolves a track source into something a <track> element can consume.
 * - data: URIs pass straight through
 * - .srt is fetched, converted to VTT, and re-exposed as a blob: URL
 * - anything else is used as-is
 */
async function resolveTrack(src) {
  if (src.startsWith('data:') || src.startsWith('blob:')) return { src, revoke: null };
  if (!/\.srt(\?|#|$)/i.test(src)) return { src, revoke: null };
  try {
    const res = await fetch(src);
    if (!res.ok) return { src, revoke: null };
    const vtt = srtToVtt(await res.text());
    const url = URL.createObjectURL(new Blob([vtt], { type: 'text/vtt' }));
    return { src: url, revoke: url };
  } catch {
    return { src, revoke: null };
  }
}

/* -------------------------------------------------------------------------- *
 * 4. Host protocol  (`strmcx/v1`)
 * -------------------------------------------------------------------------- */

/** Commands the host may send. Payload shapes are validated below. */
const COMMANDS = new Set([
  'play', 'pause', 'toggle-play', 'space-press', 'space-release',
  'toggle-muted', 'set-muted', 'seek', 'seek-relative', 'seek-percent',
  'smart-skip', 'playback-rate-relative', 'set-playback-rate',
  'volume-relative', 'set-volume', 'toggle-captions', 'toggle-pip',
  'toggle-fullscreen', 'set-external-fullscreen', 'previous-episode',
  'next-episode', 'download', 'screenshot', 'toggle-theater',
  'set-color-scheme', 'resolve-keydown', 'set-session',
]);

/** Events forwarded to the host. */
const EVENTS = {
  'strmcx-ready': 'strmcx-ready',
  'strmcx-state-change': 'strmcx-state-change',
  'strmcx-time': 'strmcx-time-update',
  'strmcx-duration': 'strmcx-duration-change',
  'strmcx-ended': 'strmcx-ended',
  'strmcx-error': 'strmcx-error',
  'strmcx-next': 'strmcx-next-request',
  'strmcx-prev': 'strmcx-previous-request',
  'strmcx-theater': 'strmcx-theater-request',
  'strmcx-fullscreen': 'strmcx-fullscreen-request',
  'strmcx-download': 'strmcx-download-request',
  'strmcx-screenshot-error': 'strmcx-screenshot-error',
  'strmcx-keydown': 'strmcx-keydown',
};

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

function validPayload(command, payload) {
  if (payload !== undefined && !isObj(payload)) return false;
  const p = payload ?? {};
  const need = (keys) => keys.every((k) => p[k] !== undefined);
  const between = (k, lo, hi) => isNum(p[k]) && p[k] >= lo && p[k] <= hi;

  switch (command) {
    case 'seek':                    return need(['time']) && between('time', 0, 2678400);
    case 'seek-relative':           return need(['delta']) && between('delta', -86400, 86400);
    case 'seek-percent':            return need(['percent']) && between('percent', 0, 100);
    case 'playback-rate-relative':  return need(['playbackRateDelta']) && between('playbackRateDelta', -4, 4);
    case 'set-playback-rate':       return need(['playbackRate']) && between('playbackRate', 0.25, 4);
    case 'volume-relative':         return need(['volumeDelta']) && between('volumeDelta', -1, 1);
    case 'set-volume':              return need(['volume']) && between('volume', 0, 1);
    case 'set-external-fullscreen': return need(['active']) && typeof p.active === 'boolean';
    case 'set-muted':               return need(['muted']) && typeof p.muted === 'boolean';
    case 'set-color-scheme':        return p.colorScheme === 'light' || p.colorScheme === 'dark';
    case 'resolve-keydown':         return need(['id', 'consumed'])
                                      && Number.isSafeInteger(p.id) && p.id > 0
                                      && typeof p.consumed === 'boolean';
    case 'set-session':             return need(['session']) && isObj(p.session);
    default:                        return need([]);
  }
}

class HostLink {
  constructor() {
    this.port = null;
    this.onCommand = null;
    this.onResolveKeydown = null;
    window.addEventListener('message', (e) => this.#onMessage(e));
  }

  get connected() { return !!this.port; }

  #onMessage(e) {
    const d = e.data;
    if (!isObj(d) || d.protocol !== PROTOCOL || d.type !== 'connect') return;
    // Only accept the direct parent, from a well-formed http(s) origin,
    // carrying exactly one transferred port.
    if (e.source !== window.parent || e.ports.length !== 1) return;
    let origin;
    try { origin = new URL(e.origin); } catch { return; }
    if ((origin.protocol !== 'http:' && origin.protocol !== 'https:') || origin.origin !== e.origin) return;

    this.port?.close();
    this.port = e.ports[0];
    this.port.onmessage = (ev) => {
      const m = ev.data;
      if (!isObj(m) || m.protocol !== PROTOCOL || m.type !== 'command') return;
      if (typeof m.command !== 'string' || !COMMANDS.has(m.command)) return;
      if (!validPayload(m.command, m.payload)) return;
      if (m.command === 'resolve-keydown') this.onResolveKeydown?.(m.payload);
      else this.onCommand?.(m.command, m.payload);
    };
    this.port.start();
  }

  send(event, payload = {}) {
    if (!this.port) return;
    const mapped = EVENTS[event];
    if (!mapped) return;
    this.port.postMessage({ protocol: PROTOCOL, type: 'event', event: mapped, payload });
  }
}

/* -------------------------------------------------------------------------- *
 * 5. Player construction
 * -------------------------------------------------------------------------- */

const NS_SVG = 'http://www.w3.org/2000/svg';

function icon(path) {
  const svg = document.createElementNS(NS_SVG, 'svg');
  svg.setAttribute('class', 'vds-icon');
  svg.setAttribute('viewBox', '0 0 32 32');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('aria-hidden', 'true');
  svg.innerHTML = path;
  return svg;
}

function makeButton(label, svgPath, placement = 'top') {
  const trigger = document.createElement('media-tooltip-trigger');
  const btn = document.createElement('button');
  btn.className = 'vds-button';
  btn.setAttribute('aria-label', label);
  btn.setAttribute('data-strmcx-chrome', '');
  btn.append(icon(svgPath));

  const tip = document.createElement('media-tooltip');
  tip.className = 'vds-tooltip';
  tip.setAttribute('data-strmcx-chrome', '');
  const content = document.createElement('media-tooltip-content');
  content.className = 'vds-tooltip-content';
  content.setAttribute('placement', placement);
  content.textContent = label;
  tip.append(trigger, content);
  trigger.append(btn);
  return { tooltip: tip, button: btn };
}

const ICON_DOWNLOAD = '<path d="M16 4v16m0 0 6-6m-6 6-6-6M5 26h22" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>';

export async function createPlayer(options = {}) {
  const cfg = { ...parseParams(), ...options };
  const settings = loadSettings();
  const host = new HostLink();

  // Creating <media-player> before Vidstack defines it leaves a plain own
  // `src` property that shadows the prototype accessor, and the element never
  // upgrades. Wait for the definition instead of relying on script order.
  await customElements.whenDefined('media-player');

  /* --- element tree ---------------------------------------------------- */
  const player = document.createElement('media-player');
  player.setAttribute('playsinline', '');
  player.setAttribute('crossorigin', 'anonymous');   // needed for CORS subtitles
  player.setAttribute('stream-type', 'on-demand');
  // Vidstack defaults to load="play" and defers attaching the <video> element
  // until the user presses play. "idle" loads immediately on src change.
  player.setAttribute('load', 'idle');
  if (cfg.autoplay) player.setAttribute('autoplay', '');
  if (cfg.muted) player.setAttribute('muted', '');

  const provider = document.createElement('media-provider');
  player.append(provider);

  const layout = document.createElement(
    cfg.layout === 'native' ? 'div' : 'media-video-layout'
  );
  if (cfg.layout !== 'native' && cfg.thumbnails) {
    layout.setAttribute('thumbnails', cfg.thumbnails);
  }
  if (cfg.layout !== 'native') layout.setAttribute('no-scrub-gesture', '');
  player.append(layout);

  const container = document.getElementById('app');
  container.replaceChildren(player);

  if (cfg.aspect) player.style.setProperty('--strmcx-aspect', cfg.aspect);
  if (cfg.theater || settings.theater) document.documentElement.dataset.theater = '';

  /* --- source ---------------------------------------------------------- */
  const source = cfg.src || cfg.playlist;
  if (!source) {
    player.setAttribute('title', cfg.title || 'No source');
    return { player, host, cfg };
  }
  if (cfg.srcType) player.setAttribute('type', cfg.srcType);
  player.src = source;
  if (cfg.poster) player.poster = cfg.poster;
  if (cfg.title) player.title = cfg.title;

  /* --- HLS.js performance optimizations --------------------------------- */
  if (source.includes('.m3u8') && typeof window.Hls !== 'undefined') {
    // Configure HLS.js for optimal performance
    window.Hls.defaultConfig = {
      // Buffer management
      maxBufferLength: 30,          // Max buffer size in seconds (default 30)
      maxMaxBufferLength: 60,       // Max buffer size during seeking (default 60)
      maxBufferSize: 60 * 1000 * 1000, // 60MB max buffer (reduced from default)
      // Network
      maxBufferHole: 0.5,          // Handle small gaps in timeline (default 0.5)
      // Performance
      enableWorker: true,           // Use web worker for parsing (default true)
      // Prefetch
      manifestLoadingTimeOut: 10000, // 10s timeout for manifest
      manifestLoadingMaxRetry: 3,   // Retry manifest loading 3 times
      levelLoadingTimeOut: 10000,   // 10s timeout for level playlists
      levelLoadingMaxRetry: 3,      // Retry level loading 3 times
      fragLoadingTimeOut: 20000,     // 20s timeout for fragments
      fragLoadingMaxRetry: 4,       // Retry fragment loading 4 times
      // Recovery
      enableStallDetection: true,   // Detect stalled playback
      stallThreshold: 0.5,          // Stall threshold in seconds
      // Cache
      enableWebVTT: true,           // Enable VTT parsing
      ...window.Hls.defaultConfig
    };
  }

  /* --- restored settings ---------------------------------------------- */
  player.addEventListener('can-play', () => {
    if (typeof settings.volume === 'number') player.volume = settings.volume;
    if (typeof settings.rate === 'number') player.playbackRate = settings.rate;
    if (Number.isFinite(cfg.start) && cfg.start > 0 && player.currentTime < 1) {
      player.currentTime = cfg.start;
    }
  }, { once: true });

  player.addEventListener('volume-change', () => saveSettings({ volume: player.volume }));
  player.addEventListener('rate-change', () => saveSettings({ rate: player.playbackRate }));

  /* --- subtitle tracks -------------------------------------------------- */
  const revocable = [];
  for (const t of cfg.tracks) {
    const { src, revoke } = await resolveTrack(t.src);
    if (revoke) revocable.push(revoke);
    const el = document.createElement('track');
    el.kind = t.kind;
    el.src = src;
    el.label = t.label;
    if (t.language) el.srclang = t.language;
    if (t.default) el.default = true;
    provider.append(el);
  }

  /* --- intro / outro ---------------------------------------------------- */
  const skip = document.createElement('div');
  skip.className = 'strmcx-skip';
  skip.hidden = true;

  function makeSkipButton(label, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'strmcx-skip__btn';
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  const introBtn = cfg.intro
    ? makeSkipButton('Skip Intro', () => { player.currentTime = cfg.intro.end; hideSkip(); })
    : null;
  const outroBtn = cfg.outro
    ? makeSkipButton('Skip Outro', () => {
        if (cfg.hasNext) { host.send('strmcx-next'); } else { player.currentTime = cfg.outro.end; }
        hideSkip();
      })
    : null;

  if (introBtn || outroBtn) {
    if (introBtn) skip.append(introBtn);
    if (outroBtn) skip.append(outroBtn);
    player.append(skip);
  }

  function hideSkip() { skip.hidden = true; }

  /* --- next-episode overlay -------------------------------------------- */
  let nextOverlay = null;
  if (cfg.hasNext || cfg.nextOverlay) {
    nextOverlay = document.createElement('div');
    nextOverlay.className = 'strmcx-next';
    nextOverlay.hidden = true;
    nextOverlay.innerHTML =
      '<button type="button" class="strmcx-next__btn">Next Episode</button>';
    nextOverlay.querySelector('button').addEventListener('click', () => host.send('strmcx-next'));
    player.append(nextOverlay);
  }

  /* --- extra control-bar buttons --------------------------------------- */
  // The layout re-renders its controls template as reactive state settles,
  // wiping any nodes we insert — re-attach the download button if dropped.
  if (cfg.layout !== 'native' && cfg.download) {
    const { tooltip, button } = makeButton('Download', ICON_DOWNLOAD);
    button.addEventListener('click', () => {
      host.send('strmcx-download', { url: cfg.download });
      const a = document.createElement('a');
      a.href = cfg.download;
      a.download = cfg.screenshotName || '';
      a.target = '_blank';
      a.rel = 'noopener';
      document.body.append(a);
      a.click();
      a.remove();
    });
    const ensureAttached = () => {
      if (tooltip.isConnected) return;
      const groups = layout.querySelectorAll('.vds-controls-group');
      const g = groups.length ? groups[groups.length - 1] : null;
      if (g) g.insertBefore(tooltip, g.lastElementChild);
    };
    new MutationObserver(ensureAttached).observe(layout, { childList: true, subtree: true });
    ensureAttached();
  }

  /* --- screenshot ------------------------------------------------------- */
  function takeScreenshot() {
    try {
      const video = player.querySelector('video');
      if (!video) throw new Error('no video element');
      const c = document.createElement('canvas');
      c.width = video.videoWidth;
      c.height = video.videoHeight;
      c.getContext('2d').drawImage(video, 0, 0);
      const url = c.toDataURL('image/png');
      const name = (cfg.screenshotName || 'screenshot')
        .replace(/[^\w\- ]+/g, '')
        .trim()
        .replace(/\s+/g, '-');
      const stamp = Math.floor(player.currentTime);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${name}-${stamp}s.png`;
      document.body.append(a);
      a.click();
      a.remove();
    } catch {
      // Almost always a tainted canvas: the media origin did not send CORS headers.
      host.send('strmcx-screenshot-error', {
        reason: 'Canvas was tainted. Your media origin must send Access-Control-Allow-Origin.',
      });
    }
  }

  /* --- theatre ---------------------------------------------------------- */
  function toggleTheater() {
    const on = document.documentElement.hasAttribute('data-theater');
    document.documentElement.toggleAttribute('data-theater', !on);
    saveSettings({ theater: !on });
    host.send('strmcx-theater', { active: !on });
  }

  /* --- smart skip ------------------------------------------------------- */
  function smartSkip() {
    const t = player.currentTime;
    if (cfg.intro && t >= cfg.intro.start && t < cfg.intro.end) {
      player.currentTime = cfg.intro.end;
      return;
    }
    if (cfg.outro && t >= cfg.outro.start) {
      if (cfg.hasNext) host.send('strmcx-next');
      else player.currentTime = cfg.outro.end;
    }
  }

  /* --- timeline: skip ranges + overlays + autoskip ---------------------- */
  player.addEventListener('time-update', () => {
    const t = player.currentTime;
    const d = player.duration || Infinity;

    if (introBtn || outroBtn) {
      const inIntro = cfg.intro && t >= cfg.intro.start && t < cfg.intro.end;
      const inOutro = cfg.outro && t >= cfg.outro.start && t < cfg.outro.end;
      if (introBtn) introBtn.hidden = !inIntro;
      if (outroBtn) outroBtn.hidden = !inOutro;
      skip.hidden = !(inIntro || inOutro);
    }

    if (nextOverlay) {
      nextOverlay.hidden = !(d > 0 && d - t <= 30 && d - t > 0);
    }

    if (cfg.autoskip) {
      if (cfg.intro && t >= cfg.intro.start && t < cfg.intro.end - 0.4) {
        player.currentTime = cfg.intro.end;
      } else if (cfg.outro && t >= cfg.outro.start && t < cfg.outro.end - 0.4) {
        if (cfg.hasNext) host.send('strmcx-next');
        else player.currentTime = cfg.outro.end;
      }
    }
  });

  /* --- keyboard shortcuts (extend Vidstack's defaults) ------------------ */
  const PENDING = 100; // ms to wait for a host `resolve-keydown` verdict
  const pendingKeys = new Map();
  let keySeq = 0;

  function localShortcut(e) {
    if (e.altKey || e.ctrlKey || e.metaKey) return null;
    if (e.key === ' ') return e.repeat ? null : { command: 'space-press' };
    const k = e.key.length === 1 ? e.key.toLowerCase() : e.key;

    if (/^[0-9]$/.test(k)) return { command: 'seek-percent', payload: { percent: Number(k) / 10 } };
    if (e.shiftKey) {
      if (k === 'Enter') return { command: 'smart-skip' };
      if (k === 'p') return { command: 'previous-episode' };
      if (k === 'n') return { command: 'next-episode' };
      return null;
    }
    switch (k) {
      case 't': return { command: 'toggle-theater' };
      case 'j': return { command: 'seek-relative', payload: { delta: -10 } };
      case 'l': return { command: 'seek-relative', payload: { delta: 10 } };
      default: return null; // k / m / f / arrows / 0-9 handled by Vidstack
    }
  }

  function flushKey(id, consumed) {
    const entry = pendingKeys.get(id);
    if (!entry) return;
    clearTimeout(entry.timeout);
    pendingKeys.delete(id);
    if (!consumed) entry.run();
  }

  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented) return;
    const t = e.target;
    if (t instanceof HTMLElement &&
        t.closest('input, textarea, select, [contenteditable="true"], [role="textbox"]')) return;

    const action = localShortcut(e);
    const run = () => {
      if (!action) return;
      e.preventDefault();
      e.stopPropagation();
      runCommand(action.command, { ...action.payload, keyboard: true });
    };

    if (!host.connected) { run(); return; }

    // Ask the host first; it may own the key.
    const id = keySeq = keySeq === Number.MAX_SAFE_INTEGER ? 1 : keySeq + 1;
    const timeout = setTimeout(() => flushKey(id, false), PENDING);
    pendingKeys.set(id, { run, timeout });
    host.send('strmcx-keydown', {
      id, key: e.key, code: e.code,
      shiftKey: e.shiftKey, altKey: e.altKey, ctrlKey: e.ctrlKey, metaKey: e.metaKey,
      repeat: e.repeat,
    });
  }, true);

  /* --- command dispatch -------------------------------------------------- */
  function runCommand(command, payload = {}) {
    switch (command) {
      case 'play':              return player.play();
      case 'pause':             return player.pause();
      case 'toggle-play':       return player.paused ? player.play() : player.pause();
      case 'space-press':       return player.play();
      case 'space-release':     return undefined;
      case 'toggle-muted':      player.muted = !player.muted; return undefined;
      case 'set-muted':         player.muted = !!payload.muted; return undefined;
      case 'seek':              player.currentTime = Math.min(Math.max(0, payload.time), player.duration || Infinity); return undefined;
      case 'seek-relative':     player.currentTime = Math.min(Math.max(0, player.currentTime + payload.delta), player.duration || Infinity); return undefined;
      case 'seek-percent':      player.currentTime = (player.duration || 0) * (payload.percent / 100); return undefined;
      case 'smart-skip':        return smartSkip();
      case 'set-playback-rate': player.playbackRate = payload.playbackRate; return undefined;
      case 'playback-rate-relative':
        player.playbackRate = Math.min(4, Math.max(0.25, player.playbackRate + payload.playbackRateDelta));
        return undefined;
      case 'set-volume':        player.muted = false; player.volume = payload.volume; return undefined;
      case 'volume-relative':   player.muted = false; player.volume = Math.min(1, Math.max(0, player.volume + payload.volumeDelta)); return undefined;
      case 'toggle-captions': {
        // Vidstack's TextTracksList is iterable but not an Array.
        const tracks = Array.from(player.textTracks || []).filter((x) => x.kind === 'subtitles' || x.kind === 'captions');
        const active = tracks.find((x) => x.mode !== 'disabled');
        for (const x of tracks) x.mode = 'disabled';
        if (!active && tracks.length) tracks[0].mode = 'showing';
        return undefined;
      }
      case 'toggle-pip': {
        const v = player.querySelector('video');
        if (!v) return undefined;
        return document.pictureInPictureElement ? document.exitPictureInPicture() : v.requestPictureInPicture();
      }
      case 'toggle-fullscreen': return player.fullscreen ? player.exitFullscreen() : player.enterFullscreen();
      case 'set-external-fullscreen': document.documentElement.toggleAttribute('data-ext-fullscreen', !!payload.active);
      case 'toggle-theater':    return toggleTheater();
      case 'set-color-scheme':  document.documentElement.dataset.colorScheme = payload.colorScheme; return undefined;
      case 'screenshot':        return takeScreenshot();
      case 'download': {
        if (!cfg.download) return undefined;
        const a = document.createElement('a');
        a.href = cfg.download; a.target = '_blank'; a.rel = 'noopener';
        document.body.append(a); a.click(); a.remove();
        return undefined;
      }
      case 'next-episode':      return host.send('strmcx-next');
      case 'previous-episode':  return host.send('strmcx-prev');
      case 'set-session':       return undefined; // host owns persistence; ack only
      default:                  return undefined;
    }
  }

  host.onCommand = runCommand;
  host.onResolveKeydown = (p) => flushKey(p.id, p.consumed);

  /* --- event forwarding -------------------------------------------------- */
  const throttled = (() => {
    let last = 0;
    return (fn, ms = 1000) => (...args) => {
      const now = performance.now();
      if (now - last >= ms) { last = now; fn(...args); }
    };
  })();

  const emitTime = throttled(() => host.send('strmcx-time', {
    currentTime: player.currentTime || 0,
    duration: player.duration || 0,
  }));

  player.addEventListener('time-update', emitTime);
  player.addEventListener('play',  () => host.send('strmcx-state-change', { state: 'play' }));
  player.addEventListener('pause', () => host.send('strmcx-state-change', { state: 'pause' }));
  player.addEventListener('ended', () => host.send('strmcx-ended'));
  player.addEventListener('duration-change', () => host.send('strmcx-duration', { duration: player.duration }));
  player.addEventListener('error', () => host.send('strmcx-error', { message: String(player.error?.message ?? 'unknown') }));
  player.addEventListener('enter-fullscreen', () => host.send('strmcx-fullscreen', { active: true }));
  player.addEventListener('exit-fullscreen',  () => host.send('strmcx-fullscreen', { active: false }));

  // Loading splash, matching the original's behaviour
  const splash = document.querySelector('.strmcx-splash');
  const hideSplash = () => {
    if (!splash) return;
    splash.hidden = true;
    setTimeout(() => splash.remove(), 260);
  };
  for (const ev of ['can-play', 'loaded-metadata', 'playing']) {
    player.addEventListener(ev, hideSplash, { once: true });
  }

  player.addEventListener('can-play', () => host.send('strmcx-ready'), { once: true });
  // If the host connects before media is ready, still announce readiness.
  const announceReady = () => host.send('strmcx-ready');
  const readyTimer = setInterval(() => {
    if (host.connected) { announceReady(); clearInterval(readyTimer); }
  }, 250);
  setTimeout(() => clearInterval(readyTimer), 30000);

  return { player, host, cfg, runCommand, takeScreenshot, toggleTheater };
}
