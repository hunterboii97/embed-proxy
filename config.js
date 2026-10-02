const path = require('node:path');
const crypto = require('node:crypto');
require('dotenv').config();

const PORT = parseInt(process.env.PORT || '5001', 10);
const rawSecret = process.env.PROXY_SECRET || 'e8b2f9a9416b9b32c69d82e1c9db8c56fa769f373cfd715dfc6b45a0d33b4991';
const proxySecretKey = crypto.createHash('sha256').update(rawSecret).digest();

const originsStr = process.env.ALLOWED_ORIGINS || 'yumezone.live,localhost,127.0.0.1';
const allowedOrigins = originsStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

let embedStr = process.env.ALLOWED_EMBED_DOMAINS || process.env.ALLOWED_ORIGINS || 'yumezone.live,*.yumezone.live,localhost,127.0.0.1';
const allowedEmbedDomains = embedStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// CDN Rules with specific Referer / Origin header spoofing
const cdnRules = [
  {
    matches: (h) => h.endsWith('.aniwatchtv.uk') || h === 'aniwatchtv.uk' || h.endsWith('.zokoanime.video') || h === 'zokoanime.video',
    referer: 'https://aniwatchtv.uk/',
    origin: 'https://aniwatchtv.uk',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.includes('abyssplayer.com') || h.includes('sssrr.org') || h.includes('abyss'),
    referer: 'https://abyssplayer.com/',
    origin: 'https://abyssplayer.com',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.includes('animesalt.cx') || h.includes('animesalt'),
    referer: 'https://animesalt.cx/',
    origin: 'https://animesalt.cx',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.includes('megaplay.buzz') || h.includes('anikoto.cz') || h.includes('megaplay'),
    referer: 'https://anikoto.cz/',
    origin: 'https://anikoto.cz',
    secSite: 'cross-site'
  }
];

function isPrivateHost(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase().trim();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;

  // Check IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
  const ipv4Match = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const b0 = parseInt(ipv4Match[1], 10);
    const b1 = parseInt(ipv4Match[2], 10);
    if (b0 === 10) return true;
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    if (b0 === 192 && b1 === 168) return true;
    if (b0 === 169 && b1 === 254) return true;
    if (b0 === 127) return true;
  }
  return false;
}

function matchDomainPattern(domain, pattern) {
  domain = domain.toLowerCase();
  pattern = pattern.toLowerCase();
  if (pattern === '*' || domain === pattern) return true;
  if (pattern.startsWith('*.')) {
    const root = pattern.slice(2);
    return domain === root || domain.endsWith('.' + root);
  }
  return false;
}

function isDomainAllowed(hostOrURL, proxyHost) {
  let host = hostOrURL.toLowerCase().trim();
  if (host.includes('://')) {
    try {
      const u = new URL(host);
      host = u.hostname.toLowerCase();
    } catch {
      return false;
    }
  }
  if (host.includes(':')) {
    host = host.split(':')[0];
  }
  if (proxyHost && host === proxyHost.split(':')[0].toLowerCase()) {
    return true;
  }
  for (const pattern of allowedEmbedDomains) {
    if (matchDomainPattern(host, pattern)) return true;
  }
  return false;
}

function isEmbedAllowed(req) {
  const secFetchDest = (req.headers['sec-fetch-dest'] || '').toLowerCase();
  const secFetchSite = (req.headers['sec-fetch-site'] || '').toLowerCase();
  const referer = req.headers['referer'] || '';
  const origin = req.headers['origin'] || '';
  const host = req.headers['host'] || '';

  // Direct tab visits always permitted
  if (secFetchDest === 'document' && (secFetchSite === 'none' || secFetchSite === 'same-origin' || !secFetchSite) && !referer) {
    return true;
  }

  // Cross-site iframe requests
  if (secFetchDest === 'iframe' || secFetchSite === 'cross-site' || (referer && referer.includes('://'))) {
    if (referer) {
      if (isDomainAllowed(referer, host)) return true;
    }
    if (origin) {
      if (isDomainAllowed(origin, host)) return true;
    }
    // Block unauthorized iframes
    if (secFetchDest === 'iframe') {
      return false;
    }
  }

  // Permissive fallback for standard browser requests
  return true;
}

function buildFrameAncestorsCSP(proxyHost) {
  const ancestors = ["'self'"];
  if (proxyHost) {
    const cleanHost = proxyHost.split(':')[0];
    ancestors.push(`https://${cleanHost}`);
    ancestors.push(`http://${cleanHost}`);
  }
  for (const d of allowedEmbedDomains) {
    if (d === '*') return 'frame-ancestors *';
    ancestors.push(`https://${d}`);
    ancestors.push(`http://${d}`);
  }
  return `frame-ancestors ${ancestors.join(' ')}`;
}

module.exports = {
  PORT,
  proxySecretKey,
  allowedOrigins,
  allowedEmbedDomains,
  cdnRules,
  isPrivateHost,
  isDomainAllowed,
  isEmbedAllowed,
  buildFrameAncestorsCSP
};
