// Dynamic thread pool scaling based on CPU cores for better hardware utilization
const os = require('node:os');
const cpuCount = os.cpus().length;
process.env.UV_THREADPOOL_SIZE = String(Math.max(16, cpuCount * 4)); // 4x CPU cores, min 16

const fs = require('node:fs');
const path = require('node:path');
const Fastify = require('fastify');
const cors = require('@fastify/cors');
const compression = require('@fastify/compress');
const { PORT } = require('./config');
const { renderDocs } = require('./src/views/docs');
const { renderCustomProxy404 } = require('./src/views/player');
const { registerProxyRoutes } = require('./src/routes/proxy');
const { registerEmbedRoutes } = require('./src/routes/embeds');
const { registerApiRoutes } = require('./src/routes/api');
const { registerDownloadRoutes } = require('./src/routes/download');

// Self-hosted hls.js bundle (served from memory — no CDN round-trip / JS-delay)
let hlsBundle = null;
try {
  hlsBundle = fs.readFileSync(path.join(__dirname, 'src', 'views', 'hls.min.js'));
} catch {}

const app = Fastify({
  logger: false,           // Disabled for max throughput (zero console I/O overhead)
  trustProxy: true,        // Trust X-Forwarded-For from Cloudflare & LiteSpeed
  connectionTimeout: 0,    // Let OS manage idle connections (LiteSpeed handles this)
  keepAliveTimeout: 65000, // 65s for better CDN keep-alive (was 5s)
  bodyLimit: 1048576,      // 1MB max body (proxy only streams, never buffers large bodies)
  http2: false,            // Disable HTTP/2 (cPanel/Passenger compatibility issue)
  routerOptions: {
    maxParamLength: 4096
  }
});

// Enable Permissive High-Performance CORS
app.register(cors, {
  origin: true,
  methods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
  allowedHeaders: ['Range', 'Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Content-Type', 'Accept-Ranges']
});

// Enable response compression for M3U8 playlists and text responses
app.register(compression, {
  encodings: ['gzip', 'deflate'],
  threshold: 1024, // Compress responses > 1KB
  compressibleTypes: ['application/vnd.apple.mpegurl', 'text/plain', 'text/html']
});

// Enable TCP_NODELAY on all sockets for immediate packet transmission
app.addHook('onRequest', async (req, reply) => {
  req.raw.socket?.setNoDelay(true);
});

// Register Sub-routers
app.register(registerProxyRoutes);
app.register(registerEmbedRoutes);
app.register(registerApiRoutes);
app.register(registerDownloadRoutes);

// Self-hosted hls.js (long-cacheable, same-origin = no external DNS/TLS)
app.get('/hls.min.js', async (req, reply) => {
  if (!hlsBundle) {
    return reply.code(404).send({ error: 'hls.min.js not bundled' });
  }
  reply.header('Content-Type', 'application/javascript; charset=utf-8');
  reply.header('Cache-Control', 'public, max-age=31536000, immutable');
  return reply.send(hlsBundle);
});

// Interactive Sandbox Documentation & Live Embed Generator
const docsHandler = async (req, reply) => {
  const host = req.headers['host'] || `localhost:${PORT}`;
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const baseURL = `${proto}://${host}`;

  reply.header('Content-Type', 'text/html; charset=utf-8');
  return renderDocs(baseURL);
};

// Redirect / to /docs
app.get('/', async (req, reply) => {
  return reply.redirect('/docs');
});
app.get('/docs', docsHandler);
app.get('/api', docsHandler);

// Custom 404 Handler matching original OLED design
app.setNotFoundHandler(async (req, reply) => {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  return reply.code(404).send(renderCustomProxy404(req.url, 'Resource Not Found'));
});

// Global Error Handler
app.setErrorHandler(async (error, req, reply) => {
  console.error('[Error]', req.url, error.message);
  reply.header('Content-Type', 'application/json; charset=utf-8');
  return reply.code(error.statusCode || 500).send({
    error: error.message || 'Internal Server Error'
  });
});

// Compatibility wrapper for LiteSpeed lsnode.js and Passenger
const origListen = app.listen.bind(app);
app.listen = function (opt, ...args) {
  if (typeof opt === 'number' || (typeof opt === 'string' && !isNaN(opt))) {
    const listenOpts = { port: Number(opt) };
    let cb = undefined;
    if (typeof args[0] === 'string') {
      listenOpts.host = args[0];
      cb = typeof args[1] === 'function' ? args[1] : undefined;
    } else if (typeof args[0] === 'function') {
      cb = args[0];
    }
    return origListen(listenOpts, cb);
  }
  return origListen(opt, ...args);
};

// CDN prewarming: establish connections to common CDNs on startup
async function prewarmCDNConnections() {
  const { fetchStream } = require('./src/utils/http');
  const commonCDNs = [
    'https://megacloud.club',
    'https://vidsrc.me',
    'https://mega.nz',
    'https://zoro.to',
    'https://animixplay.to'
  ];

  console.log('🔥 Prewarming CDN connections...');
  for (const cdn of commonCDNs) {
    try {
      await fetchStream(cdn, { method: 'HEAD' });
    } catch {}
  }
  console.log('✅ CDN connections prewarmed');
}

// Start Server in standalone mode
if (require.main === module) {
  (async () => {
    try {
      const address = await app.listen({ port: PORT, host: '0.0.0.0' });
      console.log(`🚀 KaidoAPI running at: ${address}`);
      // Prewarm CDN connections in background
      prewarmCDNConnections();
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  })();
}

// Export for LiteSpeed / Phusion Passenger
module.exports = app;
