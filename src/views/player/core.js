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

import { createTelemetry } from './telemetry.js';

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
            default: false,
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

// media-icons@1.1.5 seek-backward-10 / seek-forward-10
const ICON_SEEK_BACK = '<path d="M16.6667 10.3452C16.6667 10.8924 16.0439 11.2066 15.6038 10.8814L11.0766 7.5364C10.7159 7.26993 10.7159 6.73054 11.0766 6.46405L15.6038 3.11873C16.0439 2.79356 16.6667 3.10773 16.6667 3.6549V5.22682C16.6667 5.29746 16.7223 5.35579 16.7927 5.36066C22.6821 5.76757 27.3333 10.674 27.3333 16.6667C27.3333 22.9259 22.2592 28 16 28C9.96483 28 5.03145 23.2827 4.68601 17.3341C4.66466 16.9665 4.96518 16.6673 5.33339 16.6673H7.3334C7.70157 16.6673 7.99714 16.9668 8.02743 17.3337C8.36638 21.4399 11.8064 24.6667 16 24.6667C20.4183 24.6667 24 21.085 24 16.6667C24 12.5225 20.8483 9.11428 16.8113 8.70739C16.7337 8.69957 16.6667 8.76096 16.6667 8.83893V10.3452Z" fill="currentColor"/> <path fill-rule="evenodd" clip-rule="evenodd" d="M17.0879 19.679C17.4553 19.9195 17.8928 20.0398 18.4004 20.0398C18.9099 20.0398 19.3474 19.9205 19.7129 19.6818C20.0803 19.4413 20.3635 19.0938 20.5623 18.6392C20.7612 18.1847 20.8606 17.6373 20.8606 16.9972C20.8625 16.3608 20.764 15.8192 20.5652 15.3722C20.3663 14.9252 20.0822 14.5853 19.7129 14.3523C19.3455 14.1175 18.908 14 18.4004 14C17.8928 14 17.4553 14.1175 17.0879 14.3523C16.7224 14.5853 16.4402 14.9252 16.2413 15.3722C16.0443 15.8173 15.9449 16.3589 15.943 16.9972C15.9411 17.6354 16.0396 18.1818 16.2385 18.6364C16.4373 19.089 16.7205 19.4366 17.0879 19.679ZM19.1362 18.4262C18.9487 18.7349 18.7034 18.8892 18.4004 18.8892C18.1996 18.8892 18.0226 18.8211 17.8691 18.6847C17.7157 18.5464 17.5964 18.3372 17.5112 18.0568C17.4279 17.7765 17.3871 17.4233 17.389 16.9972C17.3909 16.3684 17.4847 15.9025 17.6703 15.5995C17.8559 15.2945 18.0993 15.1421 18.4004 15.1421C18.603 15.1421 18.7801 15.2093 18.9316 15.3438C19.0832 15.4782 19.2015 15.6828 19.2868 15.9574C19.372 16.2301 19.4146 16.5767 19.4146 16.9972C19.4165 17.6392 19.3237 18.1156 19.1362 18.4262Z" fill="currentColor"/> <path d="M13.7746 19.8978C13.8482 19.8978 13.9079 19.8381 13.9079 19.7644V14.2129C13.9079 14.1393 13.8482 14.0796 13.7746 14.0796H12.642C12.6171 14.0796 12.5927 14.0865 12.5716 14.0997L11.2322 14.9325C11.1931 14.9568 11.1693 14.9996 11.1693 15.0457V15.9497C11.1693 16.0539 11.2833 16.1178 11.3722 16.0635L12.464 15.396C12.4682 15.3934 12.473 15.3921 12.4779 15.3921C12.4926 15.3921 12.5045 15.404 12.5045 15.4187V19.7644C12.5045 19.8381 12.5642 19.8978 12.6378 19.8978H13.7746Z" fill="currentColor"/>';

const ICON_SEEK_FWD = '<path d="M15.3333 10.3452C15.3333 10.8924 15.9561 11.2066 16.3962 10.8814L20.9234 7.5364C21.2841 7.26993 21.2841 6.73054 20.9235 6.46405L16.3962 3.11873C15.9561 2.79356 15.3333 3.10773 15.3333 3.6549V5.22682C15.3333 5.29746 15.2778 5.35579 15.2073 5.36066C9.31791 5.76757 4.66667 10.674 4.66667 16.6667C4.66667 22.9259 9.74078 28 16 28C22.0352 28 26.9686 23.2827 27.314 17.3341C27.3354 16.9665 27.0348 16.6673 26.6666 16.6673H24.6666C24.2984 16.6673 24.0029 16.9668 23.9726 17.3337C23.6336 21.4399 20.1937 24.6667 16 24.6667C11.5817 24.6667 8 21.085 8 16.6667C8 12.5225 11.1517 9.11428 15.1887 8.70739C15.2663 8.69957 15.3333 8.76096 15.3333 8.83893V10.3452Z" fill="currentColor"/> <path fill-rule="evenodd" clip-rule="evenodd" d="M17.0879 19.679C17.4553 19.9195 17.8928 20.0398 18.4004 20.0398C18.9099 20.0398 19.3474 19.9205 19.7129 19.6818C20.0803 19.4413 20.3635 19.0938 20.5623 18.6392C20.7612 18.1847 20.8606 17.6373 20.8606 16.9972C20.8625 16.3608 20.764 15.8192 20.5652 15.3722C20.3663 14.9252 20.0822 14.5853 19.7129 14.3523C19.3455 14.1175 18.908 14 18.4004 14C17.8928 14 17.4553 14.1175 17.0879 14.3523C16.7224 14.5853 16.4402 14.9252 16.2413 15.3722C16.0443 15.8173 15.9449 16.3589 15.943 16.9972C15.9411 17.6354 16.0396 18.1818 16.2385 18.6364C16.4373 19.089 16.7205 19.4366 17.0879 19.679ZM19.1362 18.4262C18.9487 18.7349 18.7034 18.8892 18.4004 18.8892C18.1996 18.8892 18.0225 18.8211 17.8691 18.6847C17.7157 18.5464 17.5964 18.3372 17.5112 18.0568C17.4278 17.7765 17.3871 17.4233 17.389 16.9972C17.3909 16.3684 17.4847 15.9025 17.6703 15.5995C17.8559 15.2945 18.0992 15.1421 18.4004 15.1421C18.603 15.1421 18.7801 15.2093 18.9316 15.3438C19.0831 15.4782 19.2015 15.6828 19.2867 15.9574C19.372 16.2301 19.4146 16.5767 19.4146 16.9972C19.4165 17.6392 19.3237 18.1156 19.1362 18.4262Z" fill="currentColor"/> <path d="M13.7746 19.8978C13.8482 19.8978 13.9079 19.8381 13.9079 19.7644V14.2129C13.9079 14.1393 13.8482 14.0796 13.7746 14.0796H12.642C12.6171 14.0796 12.5927 14.0865 12.5716 14.0997L11.2322 14.9325C11.1931 14.9568 11.1693 14.9996 11.1693 15.0457V15.9497C11.1693 16.0539 11.2833 16.1178 11.3722 16.0635L12.464 15.396C12.4682 15.3934 12.473 15.3921 12.4779 15.3921C12.4926 15.3921 12.5045 15.404 12.5045 15.4187V19.7644C12.5045 19.8381 12.5642 19.8978 12.6378 19.8978H13.7746Z" fill="currentColor"/>';

// ±10s buttons use the built-in <media-seek-button> element (click seeks
// through the player core, same clamping as the j/l keyboard shortcuts).
function makeSeekButton(backward) {
  const tooltipText = backward ? 'Rewind 10s' : 'Forward 10s';
  const trigger = document.createElement('media-tooltip-trigger');
  const btn = document.createElement('media-seek-button');
  btn.className = 'vds-seek-button vds-button';
  btn.setAttribute('seconds', backward ? '-10' : '10');
  btn.setAttribute('aria-label', backward ? 'Rewind 10 seconds' : 'Forward 10 seconds');
  btn.setAttribute('data-strmcx-chrome', '');
  btn.append(icon(backward ? ICON_SEEK_BACK : ICON_SEEK_FWD));

  const tip = document.createElement('media-tooltip');
  tip.className = 'vds-tooltip';
  tip.setAttribute('data-strmcx-chrome', '');
  tip.setAttribute('data-strmcx-seek', '');
  const content = document.createElement('media-tooltip-content');
  content.className = 'vds-tooltip-content';
  content.setAttribute('placement', 'top');
  content.textContent = tooltipText;
  tip.append(trigger, content);
  trigger.append(btn);
  return { tooltip: tip, button: btn };
}

// Same 720p-first ordering as the server variant picker: exact 720, else the
// highest level below it, else the lowest level above.
function pickStartLevel(levels) {
  let below = -1;
  let above = -1;
  for (let i = 0; i < levels.length; i++) {
    const h = levels[i].height || 0;
    if (h === 720) return i;
    if (h > 0 && h < 720) {
      if (below < 0 || h > levels[below].height) below = i;
    } else if (h > 720 && (above < 0 || h < levels[above].height)) {
      above = i;
    }
  }
  return below >= 0 ? below : above;
}

const AD_CAP_KEY = 'strmcx:ad-last';
const AD_CAP_MS = 6 * 60 * 60 * 1000;
const AD_INTERSTITIAL_SECONDS = 5;

function maybeFireAd(ads, player) {
  if (!ads || !player) return;
  const redirects = Array.isArray(ads.redirects) ? ads.redirects.filter(Boolean) : [];
  if (!redirects.length) return;

  try {
    const last = Number(localStorage.getItem(AD_CAP_KEY) || 0);
    if (Number.isFinite(last) && Date.now() - last < AD_CAP_MS) return;
  } catch { /* storage unavailable: in-session guard still applies */ }
  try { localStorage.setItem(AD_CAP_KEY, String(Date.now())); } catch { /* private mode */ }

  const url = redirects[Math.floor(Math.random() * redirects.length)];
  let win = null;
  try { win = window.open(url, '_blank'); } catch { /* blocked */ }
  if (win) {
    try { win.opener = null; } catch { /* cross-origin */ }
    return;
  }
  if (ads.interstitial) showAdInterstitial(player, ads.interstitial);
}

// Popup-blocked fallback: a 5 s skippable panel over the (already playing)
// video. The iframe is sandboxed without top-navigation, so the ad cannot
// redirect or disturb the player page.
function showAdInterstitial(player, url) {
  const overlay = document.createElement('div');
  overlay.className = 'strmcx-ad';
  overlay.innerHTML =
    '<div class="strmcx-ad__panel">' +
    '<iframe class="strmcx-ad__frame" sandbox="allow-scripts allow-same-origin allow-popups allow-forms" referrerpolicy="no-referrer"></iframe>' +
    '<div class="strmcx-ad__bar">' +
    '<span class="strmcx-ad__note">Ad · closes in <span class="strmcx-ad__secs">' + AD_INTERSTITIAL_SECONDS + '</span>s</span>' +
    '<button type="button" class="strmcx-ad__skip">Skip ad</button>' +
    '</div></div>';
  player.append(overlay);

  setTimeout(() => {
    try { overlay.querySelector('iframe').src = url; } catch { /* ignore */ }
  }, 0);

  let left = AD_INTERSTITIAL_SECONDS;
  const secs = overlay.querySelector('.strmcx-ad__secs');
  const close = () => { clearInterval(timer); overlay.remove(); };
  const timer = setInterval(() => {
    left -= 1;
    if (left <= 0) close();
    else secs.textContent = String(left);
  }, 1000);
  overlay.querySelector('.strmcx-ad__skip').addEventListener('click', close);
}

export async function createPlayer(options = {}) {
  // Injected nulls must not erase query-string values (?intro/?outro).
  const overrides = {};
  for (const [key, value] of Object.entries(options)) {
    if (value !== undefined && value !== null) overrides[key] = value;
  }
  const cfg = { ...parseParams(), ...overrides };
  const settings = loadSettings();
  const host = new HostLink();
  const telemetry = createTelemetry({
    ...(cfg.telemetry && typeof cfg.telemetry === 'object' ? cfg.telemetry : {}),
    tier: cfg.tier
  });

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
  // until the user presses play. "idle" loads immediately on src change — the
  // stream (duration, subtitles, first segments) keeps loading in the
  // background while the click-to-play start screen is shown.
  player.setAttribute('load', 'idle');
  // Playback always begins from the start screen's play button; the autoplay
  // query param is deliberately not honoured.
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
  if (telemetry) telemetry.attach(player);

  if (cfg.aspect) player.style.setProperty('--strmcx-aspect', cfg.aspect);
  if (cfg.theater || settings.theater) document.documentElement.dataset.theater = '';

  /* --- 720p-first start level + stream hardening ------------------------ */
  // Vidstack's HLS provider hands over the hls.js instance before attaching
  // media, so this runs while the manifest is still loading. startLevel only
  // seeds the first fragment — ABR and the quality menu work normally after.

  /* --- error classification and recovery --------------------------------- */
  const MAX_FATAL_ERRORS = 3;
  let fatalErrorCount = 0;
  let lastFatalErrorTime = 0;
  let lastFatalErrorType = null;
  let lastSeekTime = 0;
  let hlsManifestParsed = false;

  const RECOVERABLE_ERRORS = new Set([
    'networkError',
    'keyLoadError'
  ]);

  player.addEventListener('hls-instance', (event) => {
    const hls = event.detail;
    const Hls = window.Hls;
    if (!hls || !Hls?.Events?.MANIFEST_PARSED) return;
    if (telemetry) telemetry.setHls(hls);

    try {
      Object.assign(hls.config, {
        enableWorker: true,
        maxBufferLength: 60,
        maxMaxBufferLength: 180,
        backBufferLength: 30,
        abrEwmaDefaultEstimate: 2000000,
        // Finite, explicit retry budgets: a dead provider turns fatal in
        // ~10 s instead of hanging on hls.js's 20 s / 120 s defaults.
        manifestLoadPolicy: {
          default: {
            maxTimeToFirstByteMs: 5000,
            maxLoadTimeMs: 15000,
            timeoutRetry: { maxNumRetry: 1, retryDelayMs: 0, maxRetryDelayMs: 0 },
            errorRetry: { maxNumRetry: 2, retryDelayMs: 1000, maxRetryDelayMs: 8000 },
          },
        },
        playlistLoadPolicy: {
          default: {
            maxTimeToFirstByteMs: 5000,
            maxLoadTimeMs: 15000,
            timeoutRetry: { maxNumRetry: 1, retryDelayMs: 0, maxRetryDelayMs: 0 },
            errorRetry: { maxNumRetry: 2, retryDelayMs: 1000, maxRetryDelayMs: 8000 },
          },
        },
        fragLoadPolicy: {
          default: {
            maxTimeToFirstByteMs: 10000,
            maxLoadTimeMs: 120000,
            timeoutRetry: { maxNumRetry: 4, retryDelayMs: 0, maxRetryDelayMs: 0 },
            // Two quick retries: a provider outage reaches fatal in seconds,
            // so the failover chain can take over well inside 15 s.
            errorRetry: { maxNumRetry: 2, retryDelayMs: 500, maxRetryDelayMs: 2000 },
          },
        },
      });
    } catch { /* config tweaks are best-effort; playback must not break */ }

    // Priority lane: every playlist/segment request carries this header, which
    // the proxy reads before scheduling prefetch. Free embeds send nothing.
    // hls.js invokes xhrSetup before xhr.open(), where setRequestHeader throws;
    // opening it here makes openAndSendXhr skip its own open, so the header sticks.
    if (cfg.tier === 'partner') {
      hls.config.xhrSetup = (xhr, url) => {
        if (xhr.readyState === 0) xhr.open('GET', url, true);
        xhr.setRequestHeader('X-Embed-Tier', 'partner');
      };
    }

    hls.on(Hls.Events.MANIFEST_PARSED, () => {
      hlsManifestParsed = true;
      const idx = pickStartLevel(hls.levels || []);
      if (idx >= 0) hls.startLevel = idx;
    });

    hls.on(Hls.Events.ERROR, (_evt, data) => {
      if (!data?.fatal) return;

      const errorType = data.type;
      const now = Date.now();

      // Reset counter if different error type or enough time passed
      if (errorType !== lastFatalErrorType || now - lastFatalErrorTime > 10000) {
        fatalErrorCount = 0;
      }

      lastFatalErrorType = errorType;
      lastFatalErrorTime = now;
      fatalErrorCount++;

      // Check if error occurred shortly after seek (buffer underrun)
      const timeSinceSeek = now - lastSeekTime;
      if (timeSinceSeek < 3000) {
        console.warn('Error shortly after seek, allowing HLS recovery');
        return;
      }

      // Check if error is recoverable
      if (RECOVERABLE_ERRORS.has(errorType)) {
        // Allow HLS.js retries to handle it
        console.warn(`Recoverable HLS error (${errorType}), allowing retries...`);
        return;
      }

      // Only failover if same fatal error occurs multiple times
      if (fatalErrorCount >= MAX_FATAL_ERRORS) {
        if (telemetry) telemetry.fatal(data.details || 'fatal stream error');
        handleFatalError();
      }
    });
  });

  // Track seek operations for error handling
  player.addEventListener('seeking', () => {
    lastSeekTime = Date.now();
  });

  /* --- source failover -------------------------------------------------- */
  // The server embeds the remaining provider chain in cfg.fallbacks; only the
  // first entry is used so every provider gets exactly one attempt. The new
  // page resumes at the failure timestamp via ?start=<seconds>.
  const failbackList = (Array.isArray(cfg.fallbacks) ? cfg.fallbacks : [])
    .filter((u) => typeof u === 'string' && u.startsWith('/embed/') && !u.startsWith('//'));

  let failoverStarted = false;
  let fatalOverlay = null;

  function showFatalOverlay(title, canRetry) {
    if (fatalOverlay) return;
    fatalOverlay = document.createElement('div');
    fatalOverlay.className = 'strmcx-fatal';
    fatalOverlay.innerHTML =
      '<div class="strmcx-fatal__panel">' +
      '<p class="strmcx-fatal__title"></p>' +
      (canRetry ? '<button type="button" class="strmcx-fatal__retry">Retry</button>' : '') +
      '</div>';
    fatalOverlay.querySelector('.strmcx-fatal__title').textContent = title;
    fatalOverlay.querySelector('.strmcx-fatal__retry')?.addEventListener('click', () => location.reload());
    player.append(fatalOverlay);
  }

  // Carry the real embedding site across failover navigations: this page's
  // own URL would otherwise become the next page's document.referrer.
  function failbackURL(next, resumeAt) {
    const params = new URLSearchParams({ start: String(Math.max(0, Math.floor(resumeAt || 0))) });
    const embedRef = window.__YUME_EMBED_REF__;
    if (embedRef) params.set('embedref', embedRef);
    // Partner status rides in a signed token; the next shell reuses it instead
    // of re-deriving tier from a same-origin Referer.
    if (cfg.tierToken) params.set('tier', cfg.tierToken);
    return next + (next.includes('?') ? '&' : '?') + params.toString();
  }

  function getCurrentProvider() {
    const urlMatch = location.pathname.match(/\/embed\/(\w+)\//);
    return urlMatch ? urlMatch[1] : null;
  }

  function goToFallback(next, resumeAt, delay = 600) {
    const currentProvider = getCurrentProvider();
    const nextProvider = next.match(/\/embed\/(\w+)\//)?.[1];

    // Don't reload if fallback is same provider
    if (currentProvider && nextProvider && currentProvider === nextProvider) {
      showFatalOverlay('Playback failed. Please try refreshing.', true);
      return;
    }

    if (telemetry) telemetry.emit('fallback', { message: 'switching to backup source' });
    showFatalOverlay('Stream error — switching to a backup source…', false);
    // Let the overlay paint before the document is replaced.
    setTimeout(() => location.replace(failbackURL(next, resumeAt)), delay);
  }

  function handleFatalError() {
    if (failoverStarted) return;
    failoverStarted = true;

    const resumeAt = Math.max(0, Math.floor(player.currentTime || 0));
    const next = failbackList[0];
    if (!next) {
      showFatalOverlay('Playback failed. Please try again.', true);
      return;
    }
    goToFallback(next, resumeAt);
  }

  /* --- slow-start watchdog ---------------------------------------------- */
  // Playback failures normally surface as an hls.js fatal error. This covers
  // the remaining case: no fatal, no can-play — a silent black screen. It does
  // not cancel loading; if the stream recovers, the panel disappears.
  let slowOverlay = null;
  let slowTimer = null;

  function clearSlowWatchdog() {
    clearTimeout(slowTimer);
    slowOverlay?.remove();
    slowOverlay = null;
  }

  function showSlowOverlay() {
    if (slowOverlay || fatalOverlay) return;
    slowOverlay = document.createElement('div');
    slowOverlay.className = 'strmcx-fatal';
    slowOverlay.innerHTML =
      '<div class="strmcx-fatal__panel">' +
      '<p class="strmcx-fatal__title">Still loading — this source is slow.</p>' +
      '<div class="strmcx-fatal__actions">' +
      '<button type="button" class="strmcx-fatal__retry" data-act="retry">Retry</button>' +
      (failbackList[0] ? '<button type="button" class="strmcx-fatal__retry" data-act="backup">Use backup</button>' : '') +
      '</div></div>';

    // Retry button: attempt HLS recovery first, then reload
    slowOverlay.querySelector('[data-act="retry"]').addEventListener('click', () => {
      // Check if HLS instance exists and try to recover
      const hlsInstance = player.querySelector('video')?.hls;
      if (hlsInstance) {
        try {
          hlsInstance.startLoad();
          clearSlowWatchdog();
          return;
        } catch (e) {
          console.warn('HLS recovery failed, reloading page');
        }
      }
      location.reload();
    });

    slowOverlay.querySelector('[data-act="backup"]')?.addEventListener('click', () => {
      goToFallback(failbackList[0], Math.max(0, Math.floor(player.currentTime || 0)), 150);
    });
    player.append(slowOverlay);
  }

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

  slowTimer = setTimeout(() => {
    // Check multiple loading states before showing slow overlay
    const isSeekingRecent = (Date.now() - lastSeekTime) < 20000;
    const isHlsLoading = hlsManifestParsed === false;
    const isPlayerLoading = player.state.waiting || player.state.buffering || player.state.loading;

    // Only show if not in loading state and not in seek grace period
    if (!player.state.canPlay && !fatalOverlay && !isPlayerLoading && !isSeekingRecent && hlsManifestParsed) {
      showSlowOverlay();
    }
  }, 60000); // Increased from 30s to 60s to reduce false positives
  player.addEventListener('can-play', clearSlowWatchdog, { once: true });
  player.addEventListener('playing', clearSlowWatchdog, { once: true });

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

  /* --- intro / outro ranges on the seek bar ----------------------------- */
  // Yellow segments matching MegaPlay's marker colour, drawn inside the
  // slider box. The layout re-renders its controls, so they are re-added
  // whenever the cached key no longer matches the DOM.
  let markerKey = '';

  function renderSkipMarkers(force = false) {
    if (!(cfg.intro || cfg.outro)) return;
    const slider = player.querySelector('.vds-time-slider');
    if (!slider) return;
    const duration = Number(player.duration) || 0;
    const rangeKey = (r) => (r ? `${r.start}:${r.end}` : '');
    const key = `${duration}|${rangeKey(cfg.intro)}|${rangeKey(cfg.outro)}`;
    if (!force && key === markerKey && slider.querySelector('.strmcx-skip-range')) return;
    markerKey = key;
    slider.querySelectorAll('.strmcx-skip-range').forEach((n) => n.remove());
    if (!(duration > 0)) return;

    const add = (range, modifier) => {
      if (!range) return;
      const start = Math.max(0, Math.min(range.start, duration));
      const end = Math.max(0, Math.min(range.end, duration));
      if (!(end > start)) return;
      const mark = document.createElement('div');
      mark.className = `strmcx-skip-range ${modifier}`;
      mark.style.left = `${(start / duration) * 100}%`;
      mark.style.width = `${((end - start) / duration) * 100}%`;
      slider.appendChild(mark);
    };
    add(cfg.intro, 'strmcx-skip-range--intro');
    add(cfg.outro, 'strmcx-skip-range--outro');
  }

  renderSkipMarkers(true);

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

  /* --- click-to-play start screen --------------------------------------- */
  // Appears once the media is ready and stays until playback begins: a black
  // screen with a centered white circular play button. Loading already
  // happened in the background (load="idle"), so clicking starts instantly.
  const startScreen = document.createElement('div');
  startScreen.className = 'strmcx-start';
  startScreen.hidden = true;
  startScreen.innerHTML =
    '<button type="button" class="strmcx-start__btn" aria-label="Play">' +
    '<svg viewBox="22 16 19 27" aria-hidden="true">' +
    '<path d="M22 16 L40 29 L22 42 Z"/>' +
    '</svg></button>';
  startScreen.querySelector('button').addEventListener('click', () => player.play());
  player.append(startScreen);

  const showStartScreen = () => { startScreen.hidden = false; };
  const hideStartScreen = () => { startScreen.hidden = true; };
  player.addEventListener('can-play', showStartScreen, { once: true });
  player.addEventListener('play', hideStartScreen);
  if (player.state.canPlay) showStartScreen();

  /* --- redirect ad (free mode) ------------------------------------------ */
  // One direct-link ad on the very first play, capped at 1 per 6 h in
  // localStorage. Playback has already started when this runs and nothing
  // here is awaited; the ad loads in a separate tab/iframe, so it can never
  // delay or interrupt the stream. Only the first play is eligible — never
  // seek/pause/resume.
  let adAttempted = false;
  player.addEventListener('play', () => {
    if (adAttempted) return;
    adAttempted = true;
    try { maybeFireAd(cfg.ads, player); } catch { /* ads never break playback */ }
  });

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

  /* --- ±10s seek buttons ------------------------------------------------ */
  // Same re-attach mechanism as the download button, but guarded: seek
  // buttons are cosmetic, so any failure here must never abort player
  // construction (that would leave a black player with dead controls).
  if (cfg.layout !== 'native') {
    try {
      const back = makeSeekButton(true);
      const fwd = makeSeekButton(false);
      let seekQueued = false;

      const attachSeekButtons = () => {
        if (back.tooltip.isConnected && fwd.tooltip.isConnected) return;
        const groups = layout.querySelectorAll('.vds-controls-group');
        const g = groups.length ? groups[groups.length - 1] : null;
        if (!g) return;
        const anchor = g.querySelector('.vds-play-tooltip');
        if (anchor) anchor.after(back.tooltip, fwd.tooltip);
        else g.insertBefore(back.tooltip, g.firstElementChild);
      };

      const safeAttach = () => {
        try { attachSeekButtons(); } catch { /* never break the player */ }
      };

      // Coalesce observer bursts to one check per frame so a reactive
      // re-render can never spin our re-insertion into a hot loop.
      const scheduleAttach = () => {
        if (seekQueued) return;
        seekQueued = true;
        requestAnimationFrame(() => { seekQueued = false; safeAttach(); });
      };

      new MutationObserver(scheduleAttach).observe(layout, { childList: true, subtree: true });
      safeAttach();
    } catch { /* never break the player */ }
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
  let lastSkipUiAt = 0;
  player.addEventListener('time-update', () => {
    const t = player.currentTime;
    const d = player.duration || Infinity;
    const now = performance.now();

    // time-update fires once per animation frame (~144 Hz); skip chrome is
    // cheap but not free, so refresh it at MegaPlay's 4 Hz time cadence.
    if (now - lastSkipUiAt >= 250) {
      lastSkipUiAt = now;

      if (introBtn || outroBtn) {
        const inIntro = cfg.intro && t >= cfg.intro.start && t < cfg.intro.end;
        const inOutro = cfg.outro && t >= cfg.outro.start && t < cfg.outro.end;
        if (introBtn) introBtn.hidden = !inIntro;
        if (outroBtn) outroBtn.hidden = !inOutro;
        skip.hidden = !(inIntro || inOutro);
      }

      renderSkipMarkers();
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
  player.addEventListener('duration-change', () => {
    host.send('strmcx-duration', { duration: player.duration });
    renderSkipMarkers(true);
  });
  player.addEventListener('error', () => {
    host.send('strmcx-error', { message: String(player.error?.message ?? 'unknown') });
    handleFatalError();
  });
  player.addEventListener('enter-fullscreen', () => host.send('strmcx-fullscreen', { active: true }));
  player.addEventListener('exit-fullscreen',  () => host.send('strmcx-fullscreen', { active: false }));

  player.addEventListener('can-play', () => host.send('strmcx-ready'), { once: true });
  // If the host connects before media is ready, still announce readiness.
  const announceReady = () => host.send('strmcx-ready');
  const readyTimer = setInterval(() => {
    if (host.connected) { announceReady(); clearInterval(readyTimer); }
  }, 250);
  setTimeout(() => clearInterval(readyTimer), 30000);

  return { player, host, cfg, runCommand, takeScreenshot, toggleTheater };
}
