const fs = require('node:fs');
const path = require('node:path');

const playerTemplatePath = path.join(__dirname, 'player.html');
let playerHtmlTemplate = '';

try {
  playerHtmlTemplate = fs.readFileSync(playerTemplatePath, 'utf8');
} catch (e) {
  console.error('Failed reading player.html:', e);
}

function renderCleanArtplayer(streamURL, subtitleTracks = [], preferredLang = 'sub', episodeKey = '', audioOptions = []) {
  if (!preferredLang) preferredLang = 'sub';
  const tracksJSON = JSON.stringify(subtitleTracks || []);
  const audsJSON = JSON.stringify(audioOptions || []);

  return playerHtmlTemplate
    .replace('{{STREAM_URL}}', streamURL)
    .replace('{{RAW_TRACKS}}', tracksJSON)
    .replace('{{PREFERRED_LANG}}', preferredLang)
    .replace('{{EPISODE_KEY}}', episodeKey)
    .replace('{{RAW_AUDIO_OPTIONS}}', audsJSON);
}

function renderCustomProxy404(requestPath = '', message = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body {
            width: 100%;
            height: 100%;
            background-color: #000000;
            color: #ffffff;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            text-align: center;
            padding: 24px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.98); }
            to { opacity: 1; transform: scale(1); }
        }
        .code {
            font-size: clamp(72px, 15vw, 120px);
            font-weight: 800;
            letter-spacing: -0.05em;
            line-height: 1;
            color: #ffffff;
            user-select: none;
        }
        .desc {
            margin-top: 12px;
            font-size: 13px;
            font-weight: 500;
            color: #71717a;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            user-select: none;
        }
        .btn-reload {
            margin-top: 28px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 9px 18px;
            background: #18181b;
            color: #a1a1aa;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .btn-reload:hover {
            background: #27272a;
            color: #ffffff;
            border-color: rgba(255, 255, 255, 0.15);
            transform: translateY(-1px);
        }
        .btn-reload svg {
            transition: transform 0.3s ease;
        }
        .btn-reload:hover svg {
            transform: rotate(180deg);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="code">404</div>
        <div class="desc">${message || 'Stream Not Available'}</div>
        <button class="btn-reload" onclick="location.reload()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.3"/>
            </svg>
            Retry
        </button>
    </div>
</body>
</html>`;
}

module.exports = {
  renderCleanArtplayer,
  renderCustomProxy404
};
