const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const playerTemplatePath = path.join(__dirname, 'player', 'player.html');
let playerHtmlTemplate = '';

// Content version of every player asset (name+size+mtime hash, computed once
// at startup). Appended as ?v= to each /player-assets URL so browsers fetch
// the current bundle even if they hold long-lived cache entries from before
// the no-cache policy existed — a stale cached bundle can otherwise persist
// for a year and keep serving old player code.
function computeAssetVersion() {
  const h = crypto.createHash('sha1');
  (function walk(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else {
        const st = fs.statSync(full);
        h.update(e.name);
        h.update(String(st.size));
        h.update(String(Math.floor(st.mtimeMs)));
      }
    }
  })(path.join(__dirname, 'player'));
  return h.digest('hex').slice(0, 10);
}

try {
  playerHtmlTemplate = fs.readFileSync(playerTemplatePath, 'utf8');
  const assetVersion = computeAssetVersion();
  playerHtmlTemplate = playerHtmlTemplate.replace(
    /\/player-assets\/[^"'\s)]+/g,
    (m) => `${m}?v=${assetVersion}`
  );
} catch (e) {
  console.error('Failed reading player.html:', e);
}

function scriptSafeJSON(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

// The embed HTML is a static shell: it paints immediately, contains no
// viewer-specific data, and asks the resolve endpoint for the stream after
// boot. Everything the server used to inject is decided at resolve time.
function renderPlayerShell(resolveURL) {
  return playerHtmlTemplate
    .replace('{{RESOLVE_JSON}}', scriptSafeJSON(resolveURL || ''))
    .replace('{{STREAM_URL}}', '')
    .replace('{{RAW_TRACKS}}', '[]')
    .replace('{{ADS_CONFIG}}', 'null')
    .replace('{{FALLBACKS}}', '[]')
    .replace('{{EMBED_TIER}}', '"free"')
    .replace('{{TELEMETRY_JSON}}', 'null')
    .replace('{{INTRO_JSON}}', 'null')
    .replace('{{OUTRO_JSON}}', 'null');
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

// Whitelist map of every file under src/views/player/ (template excluded),
// built once at startup — path-traversal safe, no fs access per request.
const ASSET_MIME = {
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.map': 'application/json; charset=utf-8'
};

function buildPlayerAssetMap() {
  const root = path.join(__dirname, 'player');
  const map = new Map();
  (function walk(dir, prefix) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'player.html') continue;
      const full = path.join(dir, entry.name);
      const rel = prefix + entry.name;
      if (entry.isDirectory()) {
        walk(full, rel + '/');
      } else {
        map.set('/' + rel, full);
      }
    }
  })(root, '');
  return map;
}

function registerPlayerAssetRoutes(fastify) {
  const assets = buildPlayerAssetMap();

  fastify.get('/player-assets/*', async (req, reply) => {
    const rel = '/' + (req.params['*'] || '');
    const file = assets.get(rel);
    if (!file) {
      reply.header('Content-Type', 'text/html; charset=utf-8');
      return reply.code(404).send(renderCustomProxy404(req.url, 'Asset Not Found'));
    }
    reply.header('Content-Type', ASSET_MIME[path.extname(file).toLowerCase()] || 'application/octet-stream');
    // no-cache + weak ETag: browsers revalidate every load (cheap 304 when
    // unchanged) so player patches reach users immediately — previously
    // vendor/* was served immutable for a year and patched bundles never
    // reached browsers that had cached them.
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      reply.header('Content-Type', 'text/html; charset=utf-8');
      return reply.code(404).send(renderCustomProxy404(req.url, 'Asset Not Found'));
    }
    const etag = `W/"${stat.size.toString(36)}-${Math.floor(stat.mtimeMs).toString(36)}"`;
    reply.header('Cache-Control', 'no-cache');
    reply.header('ETag', etag);
    if (req.headers['if-none-match'] === etag) {
      return reply.code(304).send();
    }
    return reply.send(fs.createReadStream(file));
  });
}

module.exports = {
  renderPlayerShell,
  renderCustomProxy404,
  registerPlayerAssetRoutes
};
