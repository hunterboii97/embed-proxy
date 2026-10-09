const { request, Agent, setGlobalDispatcher } = require('undici');

// Ultra high-performance Global Agent
// - pipelining:10 sends multiple requests per TCP connection (HTTP/1.1)
// - connections:128 per origin (cPanel shared hosting is single-server, no need for 10k)
// - keepAliveTimeout/MaxTimeout: keep sockets alive between requests
// - DNS cache TTL 30s: avoid repeated DNS lookups for the same CDN origins
const globalAgent = new Agent({
  keepAliveTimeout: 60000,
  keepAliveMaxTimeout: 300000,
  connections: 128,
  pipelining: 10,
  maxResponseSize: -1,
  headersTimeout: 10000,
  bodyTimeout: 0,
  connect: {
    timeout: 6000,
    keepAlive: true,
    keepAliveInitialDelay: 0,
    noDelay: true,
    rejectUnauthorized: false
  }
});

setGlobalDispatcher(globalAgent);

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

async function fetchText(url, options = {}) {
  const headers = {
    'user-agent': DEFAULT_UA,
    ...(options.headers || {})
  };
  const res = await request(url, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    dispatcher: globalAgent
  });
  const text = await res.body.text();
  return {
    statusCode: res.statusCode,
    headers: res.headers,
    body: text
  };
}

async function fetchJSON(url, options = {}) {
  const headers = {
    'user-agent': DEFAULT_UA,
    accept: 'application/json',
    ...(options.headers || {})
  };
  const res = await request(url, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    dispatcher: globalAgent
  });
  const json = await res.body.json();
  return {
    statusCode: res.statusCode,
    headers: res.headers,
    data: json
  };
}

async function fetchStream(url, options = {}) {
  const headers = {
    'user-agent': DEFAULT_UA,
    ...(options.headers || {})
  };
  const res = await request(url, {
    method: options.method || 'GET',
    headers,
    dispatcher: globalAgent
  });
  return res;
}

module.exports = {
  globalAgent,
  DEFAULT_UA,
  request,
  fetchText,
  fetchJSON,
  fetchStream
};
