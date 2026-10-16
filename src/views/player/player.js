import { createPlayer } from './core.js';

// Config is injected by the server template (see player.html). The tracks
// arrive in the strm.cx contract shape ({file,label,lang,kind}) and are
// normalised here exactly like parseParams() does for query-string input.
const injected = window.__YUME_PLAYER_CONFIG__ || {};
if (Array.isArray(injected.tracks)) {
  const processed = injected.tracks
    .filter((t) => t && t.file)
    .map((t) => ({
      src: t.file,
      label: t.label ?? t.lang ?? 'Subtitles',
      language: t.lang || '',
      kind: t.kind === 'captions' ? 'captions' : 'subtitles',
      default: false
    }));

  // Find English track and set as default (comprehensive language detection)
  const englishTrack = processed.find(t => {
    const lang = (t.language || t.label || '').toLowerCase();
    return lang.includes('en') || lang.includes('eng') || lang.includes('english');
  });

  if (englishTrack) {
    englishTrack.default = true;
    // Move English track to the front
    const index = processed.indexOf(englishTrack);
    if (index > 0) {
      processed.splice(index, 1);
      processed.unshift(englishTrack);
    }
  }

  injected.tracks = processed;
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
