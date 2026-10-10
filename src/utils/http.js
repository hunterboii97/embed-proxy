const dns = require('node:dns');
const { LRUCache } = require('lru-cache');
const { request, Agent, setGlobalDispatcher } = require('undici');

// DNS cache: undici has NO built-in DNS cache, every new connection re-resolves
// via getaddrinfo (threadpool + ~20-80ms). Cache lookups for 10 minutes per hostname.
const dnsCache = new LRUCache({ max: 5000, ttl: 600000 });
const dnsInflight = new Map();

function cachedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  const wantAll = options && options.all;
  const cached = dnsCache.get(hostname);
  if (cached) {
    if (wantAll) return process.nextTick(callback, null, cached.all);
    return process.nextTick(callback, null, cached.address, cached.family);
  }

  let pending = dnsInflight.get(hostname);
  if (!pending) {
    pending = new Promise((resolve, reject) => {
      dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
        if (err || !addrs || addrs.length === 0) return reject(err || new Error('DNS empty'));
        resolve(addrs);
      });
    });
    dnsInflight.set(hostname, pending);
    pending.finally(() => dnsInflight.delete(hostname));
  }

  pending.then(
    (addrs) => {
      const entry = { address: addrs[0].address, family: addrs[0].family, all: addrs };
      dnsCache.set(hostname, entry);
      if (wantAll) return callback(null, addrs);
      callback(null, addrs[0].address, addrs[0].family);
    },
    (err) => callback(err)
  );
}

// Ultra high-performance Global Agent tuned for 4 vCPU cores - ULTRA MODE
// - pipelining:30 sends multiple requests per TCP connection (HTTP/1.1)
// - connections:1024 per origin (doubled for 4 cores)
// - keepAliveTimeout/MaxTimeout: long-lived sockets so CDNs stay hot
// - cachedLookup: 10min DNS memo (see above)
const globalAgent = new Agent({
  keepAliveTimeout: 300000,
  keepAliveMaxTimeout: 900000,
  connections: 1024,
  pipelining: 30,
  maxResponseSize: -1,
  headersTimeout: 3000,
  bodyTimeout: 0,
  connect: {
    timeout: 1000,
    keepAlive: true,
    keepAliveInitialDelay: 0,
    noDelay: true,
    rejectUnauthorized: false,
    lookup: cachedLookup
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
    dispatcher: globalAgent,
    signal: options.signal // Allow AbortSignal for timeout
  });
  return res;
}

module.exports = {
  globalAgent,
  DEFAULT_UA,
  fetchText,
  fetchJSON,
  fetchStream
};
