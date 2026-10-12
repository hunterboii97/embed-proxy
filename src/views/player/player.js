import { createPlayer } from './core.js';

// Config is injected by the server template (see player.html). The tracks
// arrive in the strm.cx contract shape ({file,label,lang,kind}) and are
// normalised here exactly like parseParams() does for query-string input.
const injected = window.__YUME_PLAYER_CONFIG__ || {};
if (Array.isArray(injected.tracks)) {
  injected.tracks = injected.tracks
    .filter((t) => t && t.file)
    .map((t) => ({
      src: t.file,
      label: t.label ?? t.lang ?? 'Subtitles',
      language: t.lang || '',
      kind: t.kind === 'captions' ? 'captions' : 'subtitles',
      default: !!t.default
    }));
}

createPlayer(injected)
  .then((api) => {
    // Console handle for debugging: player.api.player
    window.player = { api };
  })
  .catch((err) => {
    console.error('[player] failed to initialise', err);
    const msg = document.createElement('div');
    msg.className = 'strmcx-error';
    msg.textContent = 'Failed to load player';
    document.getElementById('app')?.append(msg);
  });
