const crypto = require('node:crypto');
const { proxySecretKey, sharedSegmentTokens, tokenBucketSeconds, tokenGraceSeconds } = require('../../config');

const megaplayAESKey = Buffer.alloc(32);
Buffer.from('i?LMTAx0Q6,:}50U', 'utf8').copy(megaplayAESKey);
const megaplayIV = Buffer.from("W0;27ToaUpl_P%'c", 'utf8');
const megaplayHMACKey = Buffer.from('MpCdnT0k3n!9f2K#xQ7vL5mR8wN1pY4s', 'utf8');
const pathKeyRegex = /\/([a-f0-9]{32})\/([a-f0-9]{32})\//i;
const zokoObfKey = Buffer.from('otaku-embed-v1', 'utf8');

/**
 * Token cache: same URL + same expiry = same token, no need to re-encrypt.
 * Shared mode reuses a token until it expires — re-minting with a fresh IV
 * would change the URL and miss the shared cache on every eviction.
 * Key: JSON.stringify(payload), Value: {token, cachedAt, tokenExp}
 */
const tokenCache = new Map();
const TOKEN_CACHE_MAX = parseInt(process.env.TOKEN_CACHE_MAX || '50000', 10) || 50000;
let tokenCacheLastPurge = Date.now();

function purgeTokenCache() {
  const now = Date.now();
  if (now - tokenCacheLastPurge < 60000) return;
  tokenCacheLastPurge = now;
  for (const [k, v] of tokenCache) {
    const stale = sharedSegmentTokens
      ? v.tokenExp < now
      : v.cachedAt + 900000 < now;
    if (stale) tokenCache.delete(k);
  }
}

/**
 * Under SHARED_SEGMENT_TOKENS every token for the same target must be
 * byte-identical for every viewer — that is what lets a shared cache store
 * one copy. Drop the per-viewer IP claim and round expiry to a fixed bucket
 * plus grace. Flag-off returns the payload untouched (legacy behavior).
 */
function sharedTokenClaims(payload) {
  if (!sharedSegmentTokens) return payload;
  const { ip, ...claims } = payload;
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = (Math.floor(nowSec / tokenBucketSeconds) + 1) * tokenBucketSeconds + tokenGraceSeconds;
  return { ...claims, exp };
}

/**
 * Encrypts token payload using AES-256-GCM (12-byte IV + ciphertext + 16-byte AuthTag)
 * Uses an in-memory cache to avoid re-encrypting the same URL within 5 minutes.
 */
function encryptToken(payload, key = proxySecretKey) {
  const claims = sharedTokenClaims(payload);

  // Only cache when a stable expiry is present (prevents unbounded growth)
  if (claims.exp) {
    const cacheKey = JSON.stringify(claims);
    const cached = tokenCache.get(cacheKey);
    if (cached) return cached.token;

    const plaintext = Buffer.from(cacheKey, 'utf8');
    const iv = makeIV(plaintext, key);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const token = Buffer.concat([iv, ciphertext, tag]).toString('base64url');

    if (tokenCache.size >= TOKEN_CACHE_MAX) {
      // FIFO evict instead of clear(): wiping the map re-mints every live URL
      // with a new IV, which would orphan warm shared-cache entries.
      const overflow = tokenCache.size - TOKEN_CACHE_MAX + 1;
      let removed = 0;
      for (const k of tokenCache.keys()) {
        tokenCache.delete(k);
        if (++removed >= overflow) break;
      }
    }
    tokenCache.set(cacheKey, { token, cachedAt: Date.now(), tokenExp: claims.exp * 1000 });
    purgeTokenCache();
    return token;
  }

  const plaintext = Buffer.from(JSON.stringify(claims), 'utf8');
  const iv = makeIV(plaintext, key);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, ciphertext, tag]);
  return combined.toString('base64url');
}

/**
 * Shared mode must mint byte-identical tokens on every worker: derive the IV
 * deterministically from the plaintext and the secret. Distinct plaintexts
 * still get distinct IVs; identical plaintexts intentionally share one token
 * so a shared cache (nginx disk cache) sees one URL per segment.
 * Legacy mode keeps a random IV per mint.
 */
function makeIV(plaintext, key) {
  if (!sharedSegmentTokens) return crypto.randomBytes(12);
  return crypto.createHmac('sha256', key).update(plaintext).digest().subarray(0, 12);
}

/**
 * Decrypts AES-256-GCM token from base64url string
 */
function decryptToken(tokenStr, key = proxySecretKey) {
  if (!tokenStr) throw new Error('Empty token string');
  let rawB64 = tokenStr.trim();
  // Handle any potential slash extensions like /p/{token}/video.mp4
  if (rawB64.includes('/')) {
    rawB64 = rawB64.split('/')[0];
  }
  const combined = Buffer.from(rawB64, 'base64url');
  if (combined.length < 28) {
    throw new Error('Token payload too short (minimum 28 bytes for IV + Tag)');
  }

  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(12, combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

/**
 * Tier tokens: a small HMAC-signed bearer credential minted at the shell
 * request from the embedding site (Referer/Origin) and validated on resolve
 * and on failover navigations. Kept separate from encryptToken because shared
 * segment tokens deliberately drop per-viewer claims; the tier claim must
 * survive that transformation untouched.
 */
const TIER_TOKEN_TTL_S = 6 * 60 * 60;
const tierTokenRegex = /^t1\.(partner|free)\.(\d{1,12})\.([A-Za-z0-9_-]{43})$/;

function signTierToken(tier, ttlSeconds = TIER_TOKEN_TTL_S) {
  const tierName = tier === 'partner' ? 'partner' : 'free';
  const exp = Math.floor(Date.now() / 1000) + Math.max(60, ttlSeconds | 0);
  const payload = `t1.${tierName}.${exp}`;
  const sig = crypto.createHmac('sha256', proxySecretKey).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyTierToken(token) {
  if (typeof token !== 'string' || token.length > 200) return null;
  const m = token.match(tierTokenRegex);
  if (!m) return null;
  const tier = m[1];
  const exp = parseInt(m[2], 10);
  if (!Number.isFinite(exp) || exp * 1000 <= Date.now()) return null;
  const expected = crypto.createHmac('sha256', proxySecretKey).update(`t1.${tier}.${exp}`).digest();
  let given;
  try {
    given = Buffer.from(m[3], 'base64url');
  } catch {
    return null;
  }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  return tier;
}

/**
 * Encrypts rewritten M3U8 playlist with client hex key using AES-256-GCM
 */
function encryptPlaylistResponse(text, hexKey) {  const keyBytes = Buffer.from(hexKey, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(text, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString('base64url');
}

/**
 * Decrypts MegaPlay encrypted payload (AES-256-CBC + PKCS7 unpad)
 */
function decryptMegaplayEnc(enc) {
  let b64 = enc.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  const cipherBytes = Buffer.from(b64, 'base64');
  if (cipherBytes.length === 0 || cipherBytes.length % 16 !== 0) {
    throw new Error(`Invalid ciphertext size for MegaPlay: ${cipherBytes.length}`);
  }

  const decipher = crypto.createDecipheriv('aes-256-cbc', megaplayAESKey, megaplayIV);
  decipher.setAutoPadding(true);
  const plain = Buffer.concat([decipher.update(cipherBytes), decipher.final()]);
  const decRes = JSON.parse(plain.toString('utf8'));

  let fileURL = decRes.file;
  if (!fileURL) {
    throw new Error('Empty file URL in MegaPlay decrypted payload');
  }

  // Attach CDN token if path key matches and not already present
  if (!fileURL.includes('token=')) {
    const matches = fileURL.match(pathKeyRegex);
    if (matches && matches.length >= 3) {
      const pathKey = `${matches[1].toLowerCase()}/${matches[2].toLowerCase()}`;
      const exp = Math.floor(Date.now() / 1000) + 86400;
      const msg = `${exp}|${pathKey}`;
      const sig = crypto.createHmac('sha256', megaplayHMACKey).update(msg).digest();
      const token = `${Buffer.from(msg).toString('base64url')}.${sig.toString('base64url')}`;
      const sep = fileURL.includes('?') ? '&' : '?';
      fileURL = `${fileURL}${sep}token=${encodeURIComponent(token)}`;
    }
  }

  return fileURL;
}

/**
 * Deobfuscates Zoko (zokoanime.video) stream payload
 */
function deobfuscateZokoPayload(blob) {
  const raw = Buffer.from(blob, 'base64');
  for (let i = 0; i < raw.length; i++) {
    raw[i] ^= zokoObfKey[i % zokoObfKey.length];
  }
  const unescaped = decodeURIComponent(raw.toString('utf8'));
  return JSON.parse(unescaped);
}

/**
 * Decrypts AnimeSalt AbyssPlayer "const datas" payload
 */
function decryptAbyssDatas(datasB64) {
  let cleanB64 = datasB64.replace(/-/g, '+').replace(/_/g, '/');
  while (cleanB64.length % 4 !== 0) {
    cleanB64 += '=';
  }
  const datasRaw = Buffer.from(cleanB64, 'base64');
  const datas = JSON.parse(datasRaw.toString('latin1'));

  const keyStr = `${datas.user_id}:${datas.slug}:${datas.md5_id}`;
  const hexKey = crypto.createHash('md5').update(keyStr).digest('hex');
  const keyBytes = Buffer.from(hexKey, 'utf8'); // 32 ASCII bytes for AES-256-CTR
  const ivBytes = keyBytes.subarray(0, 16);     // first 16 bytes as IV

  const cipherMedia = Buffer.alloc(datas.media.length);
  for (let i = 0; i < datas.media.length; i++) {
    cipherMedia[i] = datas.media.charCodeAt(i) & 0xFF;
  }

  const decipher = crypto.createDecipheriv('aes-256-ctr', keyBytes, ivBytes);
  const decryptedMedia = Buffer.concat([decipher.update(cipherMedia), decipher.final()]);
  const media = JSON.parse(decryptedMedia.toString('utf8'));

  return { datas, media };
}

/**
 * Generates Sora token for Abyss chunked proxying
 */
function genSoraToken(filePath, size) {
  const sizeStr = String(size);
  const quirkBytes = Buffer.alloc(sizeStr.length);
  for (let i = 0; i < sizeStr.length; i++) {
    quirkBytes[i] = sizeStr.charCodeAt(i) - 48;
  }
  const hexKey = crypto.createHash('md5').update(quirkBytes).digest('hex');
  const keyBytes = Buffer.from(hexKey, 'utf8');
  const ivBytes = keyBytes.subarray(0, 16);

  const cipher = crypto.createCipheriv('aes-256-ctr', keyBytes, ivBytes);
  const enc = Buffer.concat([cipher.update(Buffer.from(filePath, 'utf8')), cipher.final()]);

  const b1 = enc.toString('base64').replace(/=+$/, '');
  const b2 = Buffer.from(b1, 'utf8').toString('base64').replace(/=+$/, '');
  return b2;
}

module.exports = {
  encryptToken,
  decryptToken,
  signTierToken,
  verifyTierToken,
  encryptPlaylistResponse,
  decryptMegaplayEnc,
  deobfuscateZokoPayload,
  decryptAbyssDatas,
  genSoraToken
};
