const { encryptToken } = require('./crypto');
const { fetchText, DEFAULT_UA } = require('./http');
const { cdnRules } = require('../../config');

const uriRegex = /URI="([^"]+)"/g;

function resolveAbsoluteURL(rel, base) {
  try {
    const abs = new URL(rel, base);
    // Carry over master/media playlist query (e.g. ?token=) when relative URL has none
    try {
      const baseURL = new URL(base);
      if (!abs.search && baseURL.search) {
        abs.search = baseURL.search;
      }
    } catch {}
    return abs.href;
  } catch {
    return rel;
  }
}

/**
 * Build upstream headers using CDN spoofing rules (same as /p proxy).
 */
function buildCdnHeaders(targetURL, fallbackReferer = '') {
  const headers = {
    'user-agent': DEFAULT_UA,
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors'
  };

  let host = '';
  try {
    host = new URL(targetURL).hostname.toLowerCase();
  } catch {}

  let matched = false;
  for (const rule of cdnRules) {
    if (host && rule.matches(host)) {
      headers['referer'] = rule.referer;
      headers['origin'] = rule.origin;
      headers['sec-fetch-site'] = rule.secSite || 'cross-site';
      matched = true;
      break;
    }
  }

  if (!matched) {
    const ref = fallbackReferer || (host ? `https://${host}/` : '');
    if (ref) {
      headers['referer'] = ref;
      try {
        const u = new URL(ref);
        headers['origin'] = `${u.protocol}//${u.host}`;
      } catch {
        headers['origin'] = ref.replace(/\/$/, '');
      }
    }
    headers['sec-fetch-site'] = 'cross-site';
  }

  return headers;
}

function rewriteM3U8(text, targetURL, referer, clientIP, expires, playlistKey, pkParam, isEncrypted) {
  const lines = text.split(/\r?\n/);
  const outLines = [];
  const pkQuery = pkParam ? `?pk=${encodeURIComponent(pkParam)}` : '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('#') && trimmed.includes('URI="')) {
      const newLine = line.replace(uriRegex, (match, uri) => {
        const abs = resolveAbsoluteURL(uri, targetURL);
        const cleanPath = abs.split('?')[0].toLowerCase();
        const isManifest = cleanPath.includes('.m3u8') && !cleanPath.endsWith('.ts') && !cleanPath.endsWith('.key');

        const tokPayload = {
          url: abs,
          ref: referer,
          exp: expires,
          ip: clientIP
        };
        if (playlistKey && isManifest) {
          tokPayload.key = playlistKey;
        }
        const tok = encryptToken(tokPayload);
        let encParam = '';
        if (isManifest && isEncrypted) {
          encParam = pkQuery ? '&enc=1' : '?enc=1';
        }
        return `URI="/p/${tok}${pkQuery}${encParam}"`;
      });
      outLines.push(newLine);
    } else if (trimmed && !trimmed.startsWith('#')) {
      const abs = resolveAbsoluteURL(trimmed, targetURL);
      const cleanPath = abs.split('?')[0].toLowerCase();
      const isManifest = cleanPath.includes('.m3u8') && !cleanPath.endsWith('.ts') && !cleanPath.endsWith('.key');

      const tokPayload = {
        url: abs,
        ref: referer,
        exp: expires,
        ip: clientIP
      };
      if (playlistKey && isManifest) {
        tokPayload.key = playlistKey;
      }
      const tok = encryptToken(tokPayload);
      let encParam = '';
      if (isManifest && isEncrypted) {
        encParam = pkQuery ? '&enc=1' : '?enc=1';
      }
      outLines.push(`/p/${tok}${pkQuery}${encParam}`);
    } else {
      outLines.push(line);
    }
  }

  return outLines.join('\n');
}

function parseM3U8Variants(masterText, baseURL) {
  const variants = [];
  const lines = masterText.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('#EXT-X-STREAM-INF:')) {
      let resolution = '';
      let height = 0;
      let bandwidth = 0;

      const resMatch = line.match(/RESOLUTION=(\d+x\d+)/i);
      if (resMatch) {
        resolution = resMatch[1];
        const hMatch = resolution.match(/x(\d+)/i);
        if (hMatch) {
          height = parseInt(hMatch[1], 10);
        }
      }

      const bwMatch = line.match(/BANDWIDTH=(\d+)/i);
      if (bwMatch) {
        bandwidth = parseInt(bwMatch[1], 10);
      }

      // Find next non-empty, non-comment line for the variant URL
      for (let j = i + 1; j < lines.length; j++) {
        const nextLine = lines[j].trim();
        if (nextLine && !nextLine.startsWith('#')) {
          const fullURL = resolveAbsoluteURL(nextLine, baseURL);
          variants.push({
            url: fullURL,
            resolution,
            height,
            bandwidth
          });
          i = j;
          break;
        }
      }
    }
  }

  return variants;
}

async function resolveM3U8Quality(masterM3U8URL, referer, requestedQuality = 'best') {
  const headers = buildCdnHeaders(masterM3U8URL, referer);
  const effectiveReferer = headers['referer'] || referer || '';

  const { body: masterText, statusCode } = await fetchText(masterM3U8URL, { headers });
  if (statusCode !== 200 || !masterText || !masterText.includes('#EXTM3U')) {
    return { selectedURL: masterM3U8URL, referer: effectiveReferer, statusCode };
  }

  const variants = parseM3U8Variants(masterText, masterM3U8URL);
  if (variants.length === 0) {
    return { selectedURL: masterM3U8URL, referer: effectiveReferer, statusCode };
  }

  const cleanQ = requestedQuality.toLowerCase().trim();
  let targetHeight = 0;
  if (cleanQ.includes('1080')) targetHeight = 1080;
  else if (cleanQ.includes('720')) targetHeight = 720;
  else if (cleanQ.includes('480')) targetHeight = 480;
  else if (cleanQ.includes('360')) targetHeight = 360;

  if (targetHeight > 0) {
    const exact = variants.find(v => v.height === targetHeight);
    if (exact) return { selectedURL: exact.url, referer: effectiveReferer, statusCode };

    let closest = variants[0];
    let minDiff = Math.abs(variants[0].height - targetHeight);
    for (const v of variants) {
      const diff = Math.abs(v.height - targetHeight);
      if (diff < minDiff) {
        minDiff = diff;
        closest = v;
      }
    }
    return { selectedURL: closest.url, referer: effectiveReferer, statusCode };
  }

  variants.sort((a, b) => (b.height || 0) - (a.height || 0) || (b.bandwidth || 0) - (a.bandwidth || 0));
  return { selectedURL: variants[0].url, referer: effectiveReferer, statusCode };
}

module.exports = {
  resolveAbsoluteURL,
  rewriteM3U8,
  parseM3U8Variants,
  resolveM3U8Quality,
  buildCdnHeaders
};
