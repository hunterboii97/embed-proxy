import { createPlayer } from './core.js';

createPlayer()
  .then((api) => {
    // Console handle for debugging: player.api.player
    window.player = { api };
  })
  .catch((err) => {
    console.error('[player] failed to initialise', err);
    const splash = document.querySelector('.strmcx-splash__brand');
    if (splash) splash.textContent = 'Failed to load player';
  });
