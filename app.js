// libuv pool for dns.lookup / crypto offload — must be set before any async
// work starts. os.cpus() on shared cPanel boxes reports host cores, so cap it.
const os = require('node:os');
const cpuCount = os.cpus().length;
process.env.UV_THREADPOOL_SIZE = String(Math.min(32, Math.max(16, cpuCount * 2)));

const fs = require('node:fs');
const path = require('node:path');
const Fastify = require('fastify');
const cors = require('@fastify/cors');
const compression = require('@fastify/compress');
const { PORT, LISTEN_HOST } = require('./config');
const { renderDocs } = require('./src/views/docs');
const { renderCustomProxy404, registerPlayerAssetRoutes } = require('./src/views/player');
const { registerProxyRoutes } = require('./src/routes/proxy');
const { registerEmbedRoutes } = require('./src/routes/embeds');
const { registerApiRoutes } = require('./src/routes/api');
const { registerFlixDownloadRoutes } = require('./src/routes/download-flix');

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

// Admin telemetry is opt-in and entirely outside the request hot path: a
// flag-gated hook counts requests and posts a loopback snapshot every 30 s.
if (/^(1|true|yes|on)$/i.test(String(process.env.ADMIN_METRICS || '').trim())) {
  require('./src/admin/worker-metrics').attach(app);
}

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
  // @fastify/compress reads `customTypes` (not compressibleTypes). The default
  // list covers html/css/js/json; HLS playlists need to be added explicitly
  // because mime-db marks their type non-compressible.
  customTypes: /text\/(?!event-stream)|(?:\+|\/)json(?:;|$)|(?:\+|\/)text(?:;|$)|(?:\+|\/)xml(?:;|$)|octet-stream(?:;|$)|application\/vnd\.apple\.mpegurl(?:;|$)/i
});

// Register Sub-routers
app.register(registerProxyRoutes);
app.register(registerEmbedRoutes);
app.register(registerApiRoutes);
app.register(registerFlixDownloadRoutes);
registerPlayerAssetRoutes(app);

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
  // Host is attacker-controlled on direct connections; only a plain
  // hostname/IPv4[:port] or [IPv6][:port] may become the embed base URL.
  const rawHost = String(req.headers['host'] || '');
  const hostValid =
    rawHost.length <= 255 &&
    (/^[A-Za-z0-9.-]+(:\d{1,5})?$/.test(rawHost) || /^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/.test(rawHost));
  const host = hostValid ? rawHost : `localhost:${PORT}`;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const proto = forwardedProto === 'https' || req.socket.encrypted ? 'https' : 'http';
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

// Start Server in standalone mode
if (require.main === module) {
  (async () => {
    try {
      const address = await app.listen({ port: PORT, host: LISTEN_HOST });
      console.log(`🚀 MikazaAPI running at: ${address}`);
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  })();
}

// Export for LiteSpeed / Phusion Passenger
module.exports = app;
