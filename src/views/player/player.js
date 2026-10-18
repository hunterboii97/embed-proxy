import { createPlayer } from './core.js';

// Shell-first boot: the HTML paints a skeleton, then this file asks the same
// embed route (?resolve=1) for the stream, tokens, tier and ads. Every failure
// path ends in a visible Retry panel — never an endless spinner.
const app = document.getElementById('app');
const INITIAL = window.__YUME_PLAYER_CONFIG__ || {};
const RESOLVE_TIMEOUT_MS = 9000;
const BOOT_TIMEOUT_MS = 15000;

function embedRef() {
  const fromQuery = new URLSearchParams(location.search).get('embedref');
  return fromQuery || document.referrer || '';
}

// Failover navigations carry this forward so the next page keeps the real
// embedding site (and therefore the partner tier) instead of reporting us.
window.__YUME_EMBED_REF__ = embedRef();

function normalizeTracks(tracks) {
  if (!Array.isArray(tracks)) return [];
  return tracks
    .filter((t) => t && t.file)
    .map((t) => ({
      src: t.file,
      label: t.label ?? t.lang ?? 'Subtitles',
      language: t.lang || '',
      kind: t.kind === 'captions' ? 'captions' : 'subtitles',
      default: false
    }));
}

function showBootError(message) {
  if (!app) return;
  const box = document.createElement('div');
  box.className = 'strmcx-boot strmcx-boot--error';

  const title = document.createElement('p');
  title.className = 'strmcx-boot__label';
  title.textContent = 'Stream unavailable';

  const detail = document.createElement('p');
  detail.className = 'strmcx-boot__detail';
  detail.textContent = message || 'Please try again.';

  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'strmcx-boot__retry';
  retry.textContent = 'Retry';
  retry.addEventListener('click', () => {
    box.remove();
    boot();
  });

  box.append(title, detail, retry);
  app.replaceChildren(box);
}

async function resolveConfig(cfg) {
  if (!cfg.resolve) return cfg;

  const url = new URL(cfg.resolve, location.href);
  const ref = window.__YUME_EMBED_REF__;
  if (ref) url.searchParams.set('ref', ref);

  const res = await fetch(url.pathname + url.search, {
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS)
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || data.error || !data.src) {
    throw new Error(data?.error || `Resolve failed (HTTP ${res.status})`);
  }
  return { ...cfg, ...data, resolve: null };
}

async function boot() {
  try {
    const cfg = await resolveConfig(INITIAL);
    cfg.tracks = normalizeTracks(cfg.tracks);

    const api = await Promise.race([
      createPlayer(cfg),
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Player took too long to start')), BOOT_TIMEOUT_MS);
      })
    ]);
    // Console handle for debugging: player.api.player
    window.player = { api };
  } catch (err) {
    console.error('[player] failed to initialise', err);
    showBootError(err?.message);
  }
}

boot();
