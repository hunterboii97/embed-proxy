const { request } = require('undici');
const { isPrivateHost } = require('../../config');
const { fetchJSON, globalAgent, DEFAULT_UA } = require('../utils/http');

const FLIXCLOUD_ORIGIN = 'https://flixcloud.cc';
const MAX_REDIRECTS = 6;
const ID_RE = /^[A-Za-z0-9_-]{6,64}$/;

class FlixcloudError extends Error {}

// SvelteKit serves route data as devalue-flattened values: every container
// entry is an integer index into the value table (negatives are primitives).
function devalueUnflatten(values) {
  const sentinels = new Map([
    [-1, undefined],
    [-2, undefined],
    [-3, NaN],
    [-4, Infinity],
    [-5, -Infinity],
    [-6, -0]
  ]);
  const cache = new Map();

  const hydrate = (ref) => {
    if (typeof ref !== 'number' || !Number.isInteger(ref)) return ref;
    if (ref < 0) return sentinels.get(ref);
    if (cache.has(ref)) return cache.get(ref);
    if (ref >= values.length) throw new FlixcloudError(`devalue reference ${ref} out of range`);

    const v = values[ref];
    if (Array.isArray(v) && typeof v[0] === 'string') {
      const tag = v[0];
      if (tag === 'Date') {
        cache.set(ref, v[1]);
        return v[1];
      }
      if (tag === 'BigInt') {
        const n = Number(v[1]);
        cache.set(ref, n);
        return n;
      }
      if (tag === 'RegExp') {
        const out = { pattern: v[1], flags: v[2] };
        cache.set(ref, out);
        return out;
      }
      if (tag === 'Map' || tag === 'Set') {
        const items = v.slice(2).map(hydrate);
        const out = tag === 'Set'
          ? items
          : items.reduce((acc, item, i) => {
            if (i % 2 === 0) acc[item] = items[i + 1];
            return acc;
          }, {});
        cache.set(ref, out);
        return out;
      }
      const out = v.slice(1).map(hydrate);
      cache.set(ref, out);
      return out;
    }
    if (Array.isArray(v)) {
      const out = [];
      cache.set(ref, out);
      for (const item of v) out.push(hydrate(item));
      return out;
    }
    if (v && typeof v === 'object') {
      const out = {};
      cache.set(ref, out);
      for (const [key, item] of Object.entries(v)) out[key] = hydrate(item);
      return out;
    }
    cache.set(ref, v);
    return v;
  };

  return hydrate(0);
}

// Any URL we fetch comes from upstream JSON, so forbid schemes and hosts that
// could turn the extractor into an SSRF primitive.
function assertFetchable(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new FlixcloudError('invalid upstream URL');
  }
  if (u.protocol !== 'https:') {
    throw new FlixcloudError(`refusing non-https upstream URL: ${u.protocol}`);
  }
  if (isPrivateHost(u.hostname)) {
    throw new FlixcloudError(`refusing private upstream host: ${u.hostname}`);
  }
  return u;
}

async function fetchFlixMetadata(fileId, { signal } = {}) {
  if (!ID_RE.test(String(fileId || ''))) {
    throw new FlixcloudError('invalid flixcloud file id');
  }
  assertFetchable(`${FLIXCLOUD_ORIGIN}/d/${fileId}/__data.json`);
  const timeout = AbortSignal.timeout(10000);
  const res = await fetchJSON(`${FLIXCLOUD_ORIGIN}/d/${fileId}/__data.json`, {
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    headers: { referer: `${FLIXCLOUD_ORIGIN}/` }
  });
  if (res.statusCode !== 200) {
    throw new FlixcloudError(`metadata HTTP ${res.statusCode}`);
  }
  const nodes = res.data?.nodes;
  if (!Array.isArray(nodes)) {
    throw new FlixcloudError('unexpected metadata shape (no nodes)');
  }

  for (const node of nodes) {
    if (!node || typeof node !== 'object') continue;
    if (node.type === 'error') {
      const err = node.error;
      const msg = err && typeof err === 'object' ? err.message : err;
      throw new FlixcloudError(msg || 'file not found');
    }
    if (!Array.isArray(node.data)) continue;
    const data = devalueUnflatten(node.data);
    if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
    const video = data.video && typeof data.video === 'object' ? data.video : data;
    if (data.download && (video.fileId || data.fileId)) {
      return { video, download: data.download };
    }
  }
  throw new FlixcloudError('file data not found (removed or private)');
}

function buildDownloadUrl(meta) {
  const base = String(meta.download?.base || '').replace(/\/+$/, '');
  const token = String(meta.download?.token || '');
  const fileId = String(meta.video?.fileId || '');
  if (!base || !token || !fileId) {
    throw new FlixcloudError('metadata missing download base/token/fileId');
  }
  const url = `${base}/download/${encodeURIComponent(fileId)}?token=${encodeURIComponent(token)}`;
  assertFetchable(url);
  return url;
}

// Follows the 302 chain and returns the live response for the final CDN URL.
// The signed link is IP-bound to this server and expires in ~15 min, so it is
// never cached or handed to clients.
async function requestFlixDownload(fileId, { method = 'GET', range = '', signal } = {}) {
  const meta = await fetchFlixMetadata(fileId, { signal });
  let url = buildDownloadUrl(meta);

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const target = assertFetchable(url);
    const headers = {
      'user-agent': DEFAULT_UA,
      accept: '*/*'
    };
    if (/^(.+\.)?flixcloud\.[a-z]+$/i.test(target.hostname)) {
      headers.referer = `${FLIXCLOUD_ORIGIN}/`;
    }
    if (method !== 'HEAD' && range) {
      headers.range = range;
    }

    const res = await request(url, {
      method,
      headers,
      dispatcher: globalAgent,
      signal
    });

    if (res.statusCode >= 300 && res.statusCode < 400) {
      const loc = res.headers.location;
      try { await res.body.dump(); } catch {}
      if (!loc) throw new FlixcloudError(`upstream HTTP ${res.statusCode} without Location`);
      url = new URL(loc, url).toString();
      continue;
    }

    if (res.statusCode >= 400 && res.statusCode !== 416) {
      let detail = '';
      try {
        detail = (await res.body.text()).slice(0, 200).replace(/\s+/g, ' ').trim();
      } catch {}
      const err = new FlixcloudError(`upstream HTTP ${res.statusCode}${detail ? `: ${detail}` : ''}`);
      err.upstreamStatus = res.statusCode;
      throw err;
    }

    return { res, url, video: meta.video || {} };
  }

  throw new FlixcloudError('too many redirects resolving download link');
}

async function openFlixDownload(fileId, options = {}) {
  return requestFlixDownload(fileId, options);
}

// Resolves the chain to just the signed CDN URL, for callers that need to feed
// it to another process (FFmpeg) instead of proxying the body themselves.
async function resolveFlixDownloadUrl(fileId, { signal } = {}) {
  const { res, url, video } = await requestFlixDownload(fileId, {
    method: 'GET',
    range: 'bytes=0-0',
    signal
  });
  try { await res.body.dump(); } catch {}
  return { url, video };
}

module.exports = {
  FlixcloudError,
  devalueUnflatten,
  fetchFlixMetadata,
  buildDownloadUrl,
  openFlixDownload,
  resolveFlixDownloadUrl
};
