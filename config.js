const path = require('node:path');
const crypto = require('node:crypto');
require('dotenv').config();

const PORT = parseInt(process.env.PORT || '5001', 10);

// Standalone-mode bind address. Default 0.0.0.0 for Railway/cPanel; set
// LISTEN_HOST=127.0.0.1 on VPS setups so the raw port is never publicly
// reachable (nginx/Cloudflare front it; cf-connecting-ip trust depends on it).
const LISTEN_HOST = process.env.LISTEN_HOST || '0.0.0.0';
const rawSecret = process.env.PROXY_SECRET || 'e8b2f9a9416b9b32c69d82e1c9db8c56fa769f373cfd715dfc6b45a0d33b4991';

// The built-in default and the shipped .env.example placeholder are public
// values — anyone could forge tokens with them. Refuse to boot unless a real
// secret is configured (ALLOW_INSECURE_DEFAULT_SECRET=1 bypasses for local dev).
const INSECURE_SECRETS = new Set([
  'e8b2f9a9416b9b32c69d82e1c9db8c56fa769f373cfd715dfc6b45a0d33b4991',
  'your_32_byte_hex_or_secret_string'
]);
if (
  (!process.env.PROXY_SECRET || INSECURE_SECRETS.has(String(process.env.PROXY_SECRET).trim())) &&
  process.env.ALLOW_INSECURE_DEFAULT_SECRET !== '1'
) {
  console.error(
    '[config] PROXY_SECRET is missing or is a public placeholder. Set a strong random ' +
    'PROXY_SECRET in .env (ALLOW_INSECURE_DEFAULT_SECRET=1 bypasses for local development only).'
  );
  process.exit(1);
}

const proxySecretKey = crypto.createHash('sha256').update(rawSecret).digest();

const originsStr = process.env.ALLOWED_ORIGINS || 'yumezone.live,localhost,127.0.0.1';
const allowedOrigins = originsStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

let embedStr = process.env.ALLOWED_EMBED_DOMAINS || process.env.ALLOWED_ORIGINS || 'yumezone.live,*.yumezone.live,localhost,127.0.0.1';
const allowedEmbedDomains = embedStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// Hard deny list: any embedding page whose Referer/Origin matches is refused
// even in free mode. Empty (default) disables the check entirely.
const blockedEmbedDomains = String(process.env.BLOCKED_EMBED_DOMAINS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// Free embed mode: any non-blocked site may frame the player (CSP
// frame-ancestors *). Domains in ALLOWED_EMBED_DOMAINS become the partner
// tier: no ads and a reserved prefetch lane. Every other site is the free
// tier: allowed, but sees ads and yields background work first. Off by
// default — allowlisted domains keep working and are all partner-tier.
const freeEmbedMode = String(process.env.EMBED_MODE || '').trim().toLowerCase() === 'free';

// Redirect-ad URLs for free mode. One direct link (Adsterra + Monetag, comma
// separated) opens on the first play click; the interstitial is the
// popup-blocked fallback rendered in a sandboxed iframe. Empty = no ads.
const adDirectUrls = String(process.env.AD_DIRECT_URLS || '')
  .split(',')
  .map((s) => s.trim())
  .filter((s) => /^https?:\/\//i.test(s));
const adInterstitialUrl = String(process.env.AD_INTERSTITIAL_URL || '').trim();

// Shared token model: viewer-independent URLs are required for any shared
// cache (nginx disk cache) to work. Off by default — IP-bound tokens remain
// the legacy behavior and stay valid until they expire after a flip.
// Expiry is rounded to a fixed bucket (+ grace) so every viewer minted in the
// same window gets the same token, and a cached embed page never carries an
// already-expired token across the bucket boundary.
const sharedSegmentTokens = /^(1|true|yes|on)$/i.test(String(process.env.SHARED_SEGMENT_TOKENS || '').trim());
const tokenBucketSeconds = parseInt(process.env.TOKEN_BUCKET_SECONDS || '86400', 10) || 86400;
const tokenGraceSeconds = parseInt(process.env.TOKEN_GRACE_SECONDS || '3600', 10);
if (tokenGraceSeconds < 0) {
  throw new Error('TOKEN_GRACE_SECONDS must be >= 0');
}

// Master switch: RATE_LIMIT_ENABLED=false turns off ALL per-IP rate limits
// (embed pages, /p stream tokens, downloads). Allowed domains then send
// unlimited requests; the embed gate and IP-bound tokens still apply.
const rateLimitEnabled = !/^(false|0|off|no)$/i.test(String(process.env.RATE_LIMIT_ENABLED || 'true').trim());

// Per-client-IP request budgets (requests per minute; 0 disables a limit).
// Embed/proxy defaults are set high so authorized sites' viewers never feel
// them (even via shared NAT/carrier IPs); they exist as flood protection only.
const embedRateLimitPerMin = parseInt(process.env.EMBED_RATE_LIMIT_PER_MIN || '3000', 10);
const proxyRateLimitPerMin = parseInt(process.env.PROXY_RATE_LIMIT_PER_MIN || '30000', 10);
const downloadRateLimitPerMin = parseInt(process.env.DOWNLOAD_RATE_LIMIT_PER_MIN || '30', 10);
// Flixcloud downloads stream multi-GB files straight through the worker, so
// they get a much tighter budget than the legacy HLS remux downloads. The
// quota is shared across all workers via data/download-quota.
const flixDownloadRateLimitPerMin = parseInt(process.env.FLIX_DOWNLOAD_RATE_LIMIT_PER_MIN || '1', 10);
const flixDownloadDailyLimit = parseInt(process.env.FLIX_DOWNLOAD_DAILY_LIMIT || '5', 10);
const flixDownloadQuotaDir = process.env.FLIX_DOWNLOAD_QUOTA_DIR || path.join(__dirname, 'data', 'download-quota');

// Player beacons for the admin dashboard. Off by default; the collector must
// agree (both services read the same .env). Injected per embed page only when
// true, so the player's telemetry module is dormant otherwise.
const adminTelemetryEnabled = /^(1|true|yes|on)$/i.test(String(process.env.ADMIN_TELEMETRY || '').trim());

// Shell-first embeds: the HTML paints immediately and a JSON resolve call does
// the upstream extraction. The whole resolve is capped (0 disables the cap)
// and a fallback provider is hedged in after the stagger delay when the
// primary has not answered yet.
const embedResolveTimeoutMs = parseInt(process.env.EMBED_RESOLVE_TIMEOUT_MS || '4000', 10) || 4000;
const embedHedgeStaggerMs = parseInt(process.env.EMBED_HEDGE_STAGGER_MS || '1500', 10);

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
      h.endsWith('.broforgotsave.online') || h === 'broforgotsave.online' ||
      h.endsWith('.megaplay.buzz') || h === 'megaplay.buzz',
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

// Trusted-proxy order: Cloudflare overwrites cf-connecting-ip, nginx/LiteSpeed
// overwrite x-real-ip. For raw X-Forwarded-For the LAST entry is the one our
// own proxy appended (client-forged values sit to the left), so take that.
function getClientIP(req) {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf).trim();
  const real = req.headers['x-real-ip'];
  if (real) return String(real).trim();
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const parts = String(forwarded).split(',');
    const last = parts[parts.length - 1].trim();
    if (last) return last;
  }
  return req.socket?.remoteAddress || '127.0.0.1';
}

function hostnameOf(hostOrURL) {
  if (!hostOrURL) return '';
  const value = String(hostOrURL).toLowerCase().trim();
  if (value.includes('://')) {
    try { return new URL(value).hostname.toLowerCase(); } catch { return ''; }
  }
  return value.includes(':') ? value.split(':')[0] : value;
}

function matchesDomainList(hostOrURL, patterns) {
  const host = hostnameOf(hostOrURL);
  if (!host) return false;
  for (const pattern of patterns) {
    if (matchDomainPattern(host, pattern)) return true;
  }
  return false;
}

function isEmbedBlocked(req) {
  if (!blockedEmbedDomains.length) return false;
  return matchesDomainList(req.headers['referer'] || '', blockedEmbedDomains) ||
    matchesDomainList(req.headers['origin'] || '', blockedEmbedDomains);
}

// Same deny list, applied to a raw URL string (the resolve call reports the
// embedding page's URL in its `ref` query parameter, because the browser
// sends our own origin as Referer for same-origin fetches).
function isBlockedEmbedSource(value) {
  if (!blockedEmbedDomains.length) return false;
  return matchesDomainList(value || '', blockedEmbedDomains);
}

// Tier is decided once per embed-page request from the embedding site's
// Referer/Origin. Direct visits have no parent site and default to free.
// Legacy allowlist mode (free mode off) has no ads, so every allowed page is
// treated as partner for the priority lane.
function getEmbedTier(req) {
  if (!freeEmbedMode) return 'partner';
  const host = req.headers['host'] || '';
  const referer = req.headers['referer'] || '';
  const origin = req.headers['origin'] || '';
  if (referer && isDomainAllowed(referer, host)) return 'partner';
  if (origin && isDomainAllowed(origin, host)) return 'partner';
  return 'free';
}

function isEmbedAllowed(req) {
  const secFetchDest = (req.headers['sec-fetch-dest'] || '').toLowerCase();
  const referer = req.headers['referer'] || '';
  const origin = req.headers['origin'] || '';
  const host = req.headers['host'] || '';

  // Top-level navigation (typed URL, bookmark, shared link) is a direct visit,
  // not an embed — allowed. Tokens minted for it are IP-bound and rate-limited,
  // so scraped direct-visit tokens are useless for re-hosting elsewhere.
  if (secFetchDest === 'document') return true;

  // Hard-deny list applies in every mode, before the allowlist/free checks.
  if (isEmbedBlocked(req)) return false;

  // Everything else — iframes, objects, and header-less HTTP clients — must
  // present a Referer/Origin from the allowlist. Fail closed: no signals at
  // all means a script, not a browser embed.
  if (freeEmbedMode) {
    if (isWebOrigin(referer) || isWebOrigin(origin)) return true;
    return false;
  }
  if (referer && isDomainAllowed(referer, host)) return true;
  if (origin && isDomainAllowed(origin, host)) return true;
  return false;
}

function isWebOrigin(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function buildFrameAncestorsCSP(proxyHost) {
  if (freeEmbedMode) return 'frame-ancestors *';
  const ancestors = ["'self'"];
  if (proxyHost) {
    const cleanHost = proxyHost.split(':')[0];
    ancestors.push(`https://${cleanHost}`);
    ancestors.push(`http://${cleanHost}`);
  }
  for (const d of allowedEmbedDomains) {
    if (d === '*') return 'frame-ancestors *';
    // A CSP host-source without a port only matches the scheme's default port,
    // so "localhost" alone would still block dev servers on :3000/:5173/etc.
    if (d === 'localhost' || d === '127.0.0.1') {
      ancestors.push(`http://${d}:*`, `https://${d}:*`);
      continue;
    }
    ancestors.push(`https://${d}`);
    ancestors.push(`http://${d}`);
  }
  return `frame-ancestors ${ancestors.join(' ')}`;
}

module.exports = {
  PORT,
  LISTEN_HOST,
  proxySecretKey,
  allowedOrigins,
  allowedEmbedDomains,
  blockedEmbedDomains,
  embedRateLimitPerMin,
  proxyRateLimitPerMin,
  downloadRateLimitPerMin,
  flixDownloadRateLimitPerMin,
  flixDownloadDailyLimit,
  flixDownloadQuotaDir,
  rateLimitEnabled,
  sharedSegmentTokens,
  tokenBucketSeconds,
  tokenGraceSeconds,
  freeEmbedMode,
  adDirectUrls,
  adInterstitialUrl,
  adminTelemetryEnabled,
  embedResolveTimeoutMs,
  embedHedgeStaggerMs,
  cdnRules,
  isPrivateHost,
  isDomainAllowed,
  isEmbedAllowed,
  isEmbedBlocked,
  isBlockedEmbedSource,
  getEmbedTier,
  getClientIP,
  buildFrameAncestorsCSP
};
