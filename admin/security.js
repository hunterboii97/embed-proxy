'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

/* -------------------------------------------------------------------------- *
 * IP parsing / CIDR matching (IPv4 + IPv6, no dependencies)
 * -------------------------------------------------------------------------- */

function normalizeIP(value) {
  let ip = String(value || '').trim();
  if (!ip) return '';
  if (ip.startsWith('[')) {
    const end = ip.indexOf(']');
    if (end !== -1) ip = ip.slice(1, end);
  }
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  const lowered = ip.toLowerCase();
  if (lowered.startsWith('::ffff:')) {
    const v4 = ip.slice(7);
    if (net.isIPv4(v4)) return v4;
  }
  return ip;
}

function ipv4Bytes(ip) {
  if (!net.isIPv4(ip)) return null;
  const parts = ip.split('.').map(Number);
  return Uint8Array.from(parts);
}

function ipv6Bytes(ip) {
  if (!net.isIPv6(ip)) return null;
  let str = ip;
  const lastColon = str.lastIndexOf(':');
  const tail = str.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4Bytes(tail);
    if (!v4) return null;
    str = str.slice(0, lastColon + 1) +
      (((v4[0] << 8) | v4[1]).toString(16)) + ':' + (((v4[2] << 8) | v4[3]).toString(16));
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tailGroups = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tailGroups.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...tailGroups];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    const part = Number.parseInt(groups[i], 16);
    bytes[i * 2] = part >> 8;
    bytes[i * 2 + 1] = part & 0xff;
  }
  return bytes;
}

function parseIP(value) {
  const ip = normalizeIP(value);
  const v4 = ipv4Bytes(ip);
  if (v4) return { family: 4, bytes: v4 };
  const v6 = ipv6Bytes(ip);
  if (v6) return { family: 6, bytes: v6 };
  return null;
}

function parseRule(entry) {
  const raw = String(entry || '').trim();
  if (!raw) return null;
  const slash = raw.indexOf('/');
  const address = slash === -1 ? raw : raw.slice(0, slash);
  const parsed = parseIP(address);
  if (!parsed) return null;
  const bits = parsed.family === 4 ? 32 : 128;
  let prefix = bits;
  if (slash !== -1) {
    const n = Number.parseInt(raw.slice(slash + 1), 10);
    if (!Number.isFinite(n) || n < 0 || n > bits) return null;
    prefix = n;
  }
  return { family: parsed.family, bytes: parsed.bytes, prefix };
}

function matchesRule(parsed, rule) {
  if (!parsed || parsed.family !== rule.family) return false;
  const fullBytes = rule.prefix >> 3;
  const remainder = rule.prefix & 7;
  for (let i = 0; i < fullBytes; i++) {
    if (parsed.bytes[i] !== rule.bytes[i]) return false;
  }
  if (remainder) {
    const mask = 0xff << (8 - remainder);
    if ((parsed.bytes[fullBytes] & mask) !== (rule.bytes[fullBytes] & mask)) return false;
  }
  return true;
}

function compileAllowlist(entries) {
  const rules = [];
  const invalid = [];
  for (const entry of entries || []) {
    const rule = parseRule(entry);
    if (rule) rules.push(rule);
    else invalid.push(entry);
  }
  return { rules, invalid };
}

function isLoopback(value) {
  const ip = normalizeIP(value);
  if (ip === '::1') return true;
  if (net.isIPv4(ip) && ip.startsWith('127.')) return true;
  return false;
}

function isAllowed(value, compiled) {
  const ip = normalizeIP(value);
  if (!ip) return false;
  if (compiled.rules.length === 0) return isLoopback(ip);
  const parsed = parseIP(ip);
  if (!parsed) return false;
  return compiled.rules.some((rule) => matchesRule(parsed, rule));
}

/**
 * nginx is always the public entry point and overwrites X-Real-IP with the
 * real viewer address (Cloudflare ranges resolved via set_real_ip_from).
 * The collector trusts that header only when the socket itself is loopback;
 * a direct request to the public origin cannot forge it.
 */
function resolveClientIP(req) {
  const socketIP = normalizeIP(req.socket && req.socket.remoteAddress);
  if (!isLoopback(socketIP)) return socketIP;
  const header = req.headers['x-real-ip'];
  if (header) {
    const first = normalizeIP(String(header).split(',')[0]);
    if (parseIP(first)) return first;
  }
  return socketIP;
}

/* -------------------------------------------------------------------------- *
 * Response helpers
 * -------------------------------------------------------------------------- */

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a == null ? '' : a)).digest();
  const hb = crypto.createHash('sha256').update(String(b == null ? '' : b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function sendNotFound(res) {
  const body = 'Not Found';
  if (res.headersSent) return res.end();
  res.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  return res.end(body);
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
}

module.exports = {
  normalizeIP,
  parseIP,
  compileAllowlist,
  isAllowed,
  isLoopback,
  resolveClientIP,
  safeEqual,
  sendNotFound,
  applySecurityHeaders
};
