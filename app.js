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
  logger: false, // Disabled for extreme throughput and zero console I/O blocking
  connectionTimeout: 120000,
  keepAliveTimeout: 120000,
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

// Start Server (supports both Standalone and Phusion Passenger)
(async () => {
  try {
    if (typeof PhusionPassenger !== 'undefined') {
      await app.listen({ path: 'passenger' });
    } else if (require.main === module || process.env.PORT) {
      const address = await app.listen({ port: PORT, host: '0.0.0.0' });
      console.log(`🚀 YumeZone Ultra Stream & Clean Embed Proxy running at: ${address}`);
    }
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

// Export for cPanel Phusion Passenger
module.exports = app;
