const { request, Agent, setGlobalDispatcher } = require('undici');

// Ultra high-performance Global Agent with 10,000 pooled keep-alive connections
const globalAgent = new Agent({
  keepAliveTimeout: 120000,
  keepAliveMaxTimeout: 300000,
  connections: 10000,
  pipelining: 1,
  connect: {
    timeout: 8000
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
  fetchText,
  fetchJSON,
  fetchStream
};
