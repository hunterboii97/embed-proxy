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

// Comprehensive CDN Rules matching main.go with exact Referer / Origin header spoofing
const cdnRules = [
  {
    matches: (h) => h.endsWith('.aniwatchtv.uk') || h === 'aniwatchtv.uk' ||
      h.endsWith('.zokoanime.video') || h === 'zokoanime.video' ||
      h.endsWith('.dramahot.top') || h === 'dramahot.top' ||
      h.endsWith('.otaku-stream.site') || h === 'otaku-stream.site',
    referer: 'https://zokoanime.video/',
    origin: 'https://zokoanime.video',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.shiora.site') || h === 'shiora.site' ||
      h.endsWith('.shiora.top') || h === 'shiora.top' ||
      h.endsWith('.imgnex.top') || h === 'imgnex.top' ||
      h.endsWith('.nexabloom.top') || h === 'nexabloom.top' ||
      h.endsWith('.quavex.top') || h === 'quavex.top' ||
      h.endsWith('.qeltrix.top') || h === 'qeltrix.top' ||
      h.endsWith('.tiktokcdn.com') || h === 'tiktokcdn.com' ||
      h.endsWith('.ipstatp.com') || h === 'ipstatp.com' ||
      h.endsWith('.streamzone1.site') || h === 'streamzone1.site' ||
      h.endsWith('.cinewave2.site') || h === 'cinewave2.site' ||
      h.endsWith('.watching.onl') || h === 'watching.onl' ||
      h.endsWith('.mewstream.buzz') || h === 'mewstream.buzz' ||
      h.endsWith('.lostproject.club') || h === 'lostproject.club' ||
      h.endsWith('.nekostream.site') || h === 'nekostream.site' ||
      h.endsWith('.megaplay.buzz') || h === 'megaplay.buzz' ||
      h.endsWith('.twilightharbor.space') || h === 'twilightharbor.space',
    referer: 'https://megaplay.buzz/',
    origin: 'https://megaplay.buzz',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.otakuu.se') || h === 'otakuu.se' ||
      h.endsWith('.fast4speed.rsvp') || h === 'fast4speed.rsvp' ||
      h.endsWith('.24stream.xyz') || h === '24stream.xyz',
    referer: 'https://animex.one/',
    origin: 'https://animex.one',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.vibeplayer.site') || h === 'vibeplayer.site',
    referer: 'https://vibeplayer.site/',
    origin: 'https://vibeplayer.site',
    secSite: 'same-origin'
  },
  {
    matches: (h) => h.endsWith('.mofl.pro') || h === 'mofl.pro' ||
      h.endsWith('.vidhosters.com') || h === 'vidhosters.com',
    referer: 'https://kem.clvd.xyz/',
    origin: 'https://kem.clvd.xyz',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.zencloudz.cc') || h === 'zencloudz.cc',
    referer: 'https://aniwave.at/',
    origin: 'https://aniwave.at',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.ibyteimg.com') || h === 'ibyteimg.com' ||
      h.endsWith('.byteimg.com') || h === 'byteimg.com' ||
      h.endsWith('.byteoversea.com') || h === 'byteoversea.com' ||
      h.endsWith('.vivibebe.site') || h === 'vivibebe.site',
    referer: 'https://vivibebe.site/',
    origin: 'https://vivibebe.site',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.krussdomi.com') || h === 'krussdomi.com',
    referer: 'https://krussdomi.com/',
    origin: 'https://krussdomi.com',
    secSite: 'same-origin'
  },
  {
    matches: (h) => h.endsWith('.owocdn.top') || h === 'owocdn.top' ||
      h.endsWith('.kwik.cx') || h === 'kwik.cx' ||
      h.endsWith('.uwucdn.top') || h === 'uwucdn.top',
    referer: 'https://kwik.cx/',
    origin: 'https://kwik.cx',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.anime-dunya.com') || h === 'anime-dunya.com',
    referer: 'https://anime-dunya.com/',
    origin: 'https://anime-dunya.com',
    secSite: 'same-origin'
  },
  {
    matches: (h) => h.startsWith('rrr.') || h === 'megaup.nl' || h.endsWith('.megaup.nl') ||
      h === 'hub26link.site' || h.endsWith('.hub26link.site'),
    referer: 'https://megaup.nl/',
    origin: 'https://megaup.nl',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.as-cdn26.top') || h === 'as-cdn26.top' ||
      h.endsWith('.as-cdn28.top') || h === 'as-cdn28.top' ||
      h.endsWith('.as-cdn31.top') || h === 'as-cdn31.top' ||
      h.endsWith('.as-cdn.top') || h === 'as-cdn.top' ||
      h.includes('as-cdn') ||
      h.endsWith('.vexal.top') || h === 'vexal.top' ||
      h.endsWith('.animesalt.cx') || h === 'animesalt.cx',
    referer: 'https://animesalt.cx/',
    origin: 'https://animesalt.cx',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.sssrr.org') || h === 'sssrr.org' ||
      h.endsWith('.abyssplayer.com') || h === 'abyssplayer.com',
    referer: 'https://abyssplayer.com/',
    origin: 'https://abyssplayer.com',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.allanime.uns.bio') || h === 'allanime.uns.bio' ||
      h.endsWith('.allanime.day') || h === 'allanime.day' ||
      h.endsWith('.ecotechshop.cfd') || h === 'ecotechshop.cfd',
    referer: 'https://allanime.day/',
    origin: 'https://allanime.day',
    secSite: 'cross-site'
  },
  {
    matches: (h) => h.endsWith('.slopnet.site') || h === 'slopnet.site' ||
      h.endsWith('.flixcloud.cc') || h === 'flixcloud.cc',
    referer: 'https://flixcloud.cc/',
    origin: 'https://flixcloud.cc',
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
