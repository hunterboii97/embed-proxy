const { encryptToken } = require('./crypto');

const uriRegex = /URI="([^"]+)"/g;

function resolveAbsoluteURL(rel, base) {
  try {
    return new URL(rel, base).href;
  } catch {
    return rel;
  }
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

module.exports = {
  resolveAbsoluteURL,
  rewriteM3U8
};
