const crypto = require('node:crypto');
const { proxySecretKey } = require('../../config');

const megaplayAESKey = Buffer.alloc(32);
Buffer.from('i?LMTAx0Q6,:}50U', 'utf8').copy(megaplayAESKey);
const megaplayIV = Buffer.from("W0;27ToaUpl_P%'c", 'utf8');
const megaplayHMACKey = Buffer.from('MpCdnT0k3n!9f2K#xQ7vL5mR8wN1pY4s', 'utf8');
const pathKeyRegex = /\/([a-f0-9]{32})\/([a-f0-9]{32})\//i;
const zokoObfKey = Buffer.from('otaku-embed-v1', 'utf8');

/**
 * Token cache: same URL + same expiry = same token, no need to re-encrypt
 * Key: JSON.stringify(payload), Value: {token, exp}
 */
const tokenCache = new Map();
const TOKEN_CACHE_MAX = 5000;
let tokenCacheLastPurge = Date.now();

function purgeTokenCache() {
  const now = Date.now();
  if (now - tokenCacheLastPurge < 60000) return;
  tokenCacheLastPurge = now;
  for (const [k, v] of tokenCache) {
    if (v.cachedAt + 300000 < now) tokenCache.delete(k);
  }
}

/**
 * Encrypts token payload using AES-256-GCM (12-byte IV + ciphertext + 16-byte AuthTag)
 * Uses an in-memory cache to avoid re-encrypting the same URL within 5 minutes.
 */
function encryptToken(payload, key = proxySecretKey) {
  // Only cache when a stable expiry is present (prevents unbounded growth)
  if (payload.exp) {
    const cacheKey = JSON.stringify(payload);
    const cached = tokenCache.get(cacheKey);
    if (cached) return cached.token;

    const plaintext = Buffer.from(cacheKey, 'utf8');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const token = Buffer.concat([iv, ciphertext, tag]).toString('base64url');

    if (tokenCache.size >= TOKEN_CACHE_MAX) tokenCache.clear();
    tokenCache.set(cacheKey, { token, cachedAt: Date.now() });
    purgeTokenCache();
    return token;
  }

  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, ciphertext, tag]);
  return combined.toString('base64url');
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
 * Encrypts rewritten M3U8 playlist with client hex key using AES-256-GCM
 */
function encryptPlaylistResponse(text, hexKey) {
  const keyBytes = Buffer.from(hexKey, 'hex');
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
  encryptPlaylistResponse,
  decryptMegaplayEnc,
  deobfuscateZokoPayload,
  decryptAbyssDatas,
  genSoraToken
};
