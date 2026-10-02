const Fastify = require('fastify');
const cors = require('@fastify/cors');
const { PORT } = require('./config');
const { renderDocs } = require('./src/views/docs');
const { renderCustomProxy404 } = require('./src/views/player');
const { registerProxyRoutes } = require('./src/routes/proxy');
const { registerEmbedRoutes } = require('./src/routes/embeds');
const { registerApiRoutes } = require('./src/routes/api');
const { registerDownloadRoutes } = require('./src/routes/download');

const app = Fastify({
  logger: false,           // Disabled for max throughput (zero console I/O overhead)
  trustProxy: true,        // Trust X-Forwarded-For from Cloudflare & LiteSpeed
  connectionTimeout: 0,    // Let OS manage idle connections (LiteSpeed handles this)
  keepAliveTimeout: 5000,  // Match Cloudflare's default keep-alive timeout (5s)
  bodyLimit: 1048576,      // 1MB max body (proxy only streams, never buffers large bodies)
  http2: false,            // Explicitly disable HTTP/2 (Passenger is HTTP/1.1 only)
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

// Register Sub-routers
app.register(registerProxyRoutes);
app.register(registerEmbedRoutes);
app.register(registerApiRoutes);
app.register(registerDownloadRoutes);

// Interactive Sandbox Documentation & Live Embed Generator
const docsHandler = async (req, reply) => {
  const host = req.headers['host'] || `localhost:${PORT}`;
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const baseURL = `${proto}://${host}`;

  reply.header('Content-Type', 'text/html; charset=utf-8');
  return renderDocs(baseURL);
};

app.get('/', docsHandler);
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
      const address = await app.listen({ port: PORT, host: '0.0.0.0' });
      console.log(`🚀 YumeZone Ultra Stream & Clean Embed Proxy running at: ${address}`);
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  })();
}

// Export for LiteSpeed / Phusion Passenger
module.exports = app;
