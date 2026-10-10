const { fetchText } = require('../utils/http');
const { encryptToken, decryptAbyssDatas } = require('../utils/crypto');
const { resolveAnimeTitle } = require('./resolver');
const { singleflight } = require('../utils/singleflight');
const {
  animeSaltStreamCache,
  animeSaltAudioLinksCache,
  animeSaltSlugCache,
  stats
} = require('../utils/cache');

const reData = /(?:plyr\/player|player|multi-lang-plyr)\.php\?data=([a-zA-Z0-9%_\-\+=]+)/;
const reDataFallback = /[?&]data=([a-zA-Z0-9%_\-\+=]{20,})/;
const reAbyssDirect = /https?:\/\/(?:player\.)?abyssplayer\.com\/([a-zA-Z0-9_-]+)/g;
const reDatasConst = /const datas = "([^"]+)"/;
const slugRegex = /https?:\/\/animesalt\.cx\/series\/([a-zA-Z0-9\-]+)\/?/g;

async function resolveAnimeSaltSlug(anilistID, malID, manualSlug) {
  if (manualSlug) return manualSlug;
  const cacheKey = `ani:${anilistID}_mal:${malID}`;
  if (animeSaltSlugCache.has(cacheKey)) {
    return animeSaltSlugCache.get(cacheKey);
  }

  const title = await resolveAnimeTitle(anilistID, malID);
  if (!title) {
    throw new Error(`Could not resolve anime title for ani:${anilistID} mal:${malID}`);
  }

  // Clean title for search
  const t = title.replace(/['’`´]/g, '');
  const cleanTitle = t.replace(/[^a-zA-Z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
  const targetSlug = cleanTitle.toLowerCase().replace(/\s+/g, '-');

  const queries = [cleanTitle];
  if (title.includes(':')) {
    const p = title.split(':')[0].trim();
    if (p && p !== cleanTitle) queries.push(p);
  }
  if (title.includes('-')) {
    const p = title.split('-')[0].trim();
    if (p && p !== cleanTitle) queries.push(p);
  }

  // FAST DIRECT PROBE: Check if targetSlug exists directly on animesalt.cx/series/{slug}/
  const directProbe = fetchText(`https://animesalt.cx/series/${targetSlug}/`, {
    headers: { referer: 'https://animesalt.cx/' }
  }).then(res => {
    if (res.statusCode === 200) {
      return targetSlug;
    }
    return null;
  }).catch(() => null);

  // Search queries in parallel
  const searchPromises = queries.map(q => {
    const searchURL = `https://animesalt.cx/?s=${encodeURIComponent(q)}`;
    return fetchText(searchURL, { headers: { referer: 'https://animesalt.cx/' } })
      .then(res => {
        if (res.statusCode === 200 && res.body) {
          const matches = [...res.body.matchAll(slugRegex)];
          if (matches.length > 0) {
            // Check for exact targetSlug match
            const exact = matches.find(m => m[1] === targetSlug);
            if (exact) return exact[1];
            return matches[0][1];
          }
        }
        return null;
      })
      .catch(() => null);
  });

  const results = await Promise.all([directProbe, ...searchPromises]);
  const foundSlug = results.find(s => Boolean(s)) || targetSlug;

  if (foundSlug) {
    animeSaltSlugCache.set(cacheKey, foundSlug);
    return foundSlug;
  }

  throw new Error(`No matching series found on AnimeSalt for: ${title}`);
}

async function extractAnimeSaltStream(slug, season = 1, ep = 1, hashDirect = '', requestedLang = 'hin') {
  requestedLang = (requestedLang || 'hin').toLowerCase().trim();
  if (season <= 0) season = 1;
  if (ep <= 0) ep = 1;
  const flightKey = `salt|${slug}:${season}:${ep}:${hashDirect}:${requestedLang}`;
  return singleflight(flightKey, () => extractAnimeSaltStreamUncached(slug, season, ep, hashDirect, requestedLang));
}

async function extractAnimeSaltStreamUncached(slug, season = 1, ep = 1, hashDirect = '', requestedLang = 'hin') {
  requestedLang = (requestedLang || 'hin').toLowerCase().trim();
  if (season <= 0) season = 1;
  if (ep <= 0) ep = 1;

  const cacheKey = `stream:${slug}:${season}:${ep}:${hashDirect}:${requestedLang}`;
  if (animeSaltStreamCache.has(cacheKey)) {
    stats.animeSaltHits++;
    const cached = animeSaltStreamCache.get(cacheKey);
    return {
      proxiedURL: cached.proxiedURL,
      tracks: cached.tracks,
      audioOptions: cached.audioOptions,
      resolvedSlug: cached.resolvedSlug
    };
  }
  stats.animeSaltMisses++;

  let selectedLink = '';
  const audioOptions = [];

  if (slug) {
    const audioLinksKey = `${slug}:${season}:${ep}`;
    let audioLinks = animeSaltAudioLinksCache.get(audioLinksKey) || [];

    if (audioLinks.length === 0) {
      const episodeReferer = `https://animesalt.cx/episode/${slug}-${season}x${ep}/`;
      const epRes = await fetchText(episodeReferer, {
        headers: {
          referer: `https://animesalt.cx/series/${slug}/`
        }
      });

      if (epRes.statusCode === 200 && epRes.body) {
        const html = epRes.body;
        let m = html.match(reData);
        if (!m) m = html.match(reDataFallback);

        if (m && m[1]) {
          try {
            const unescapedData = decodeURIComponent(m[1]);
            let cleanB64 = unescapedData.replace(/-/g, '+').replace(/_/g, '/');
            while (cleanB64.length % 4 !== 0) cleanB64 += '=';
            const b64Dec = Buffer.from(cleanB64, 'base64').toString('utf8');
            const parsed = JSON.parse(b64Dec);
            if (Array.isArray(parsed) && parsed.length > 0) {
              audioLinks = parsed;
              animeSaltAudioLinksCache.set(audioLinksKey, audioLinks);
            }
          } catch {}
        }

        // Direct Abyss player regex fallback
        if (audioLinks.length === 0) {
          const directMatches = [...html.matchAll(reAbyssDirect)];
          if (directMatches.length > 0) {
            audioLinks = directMatches.map(dm => ({
              Language: 'Default',
              Link: dm[0]
            }));
          }
        }
      }
    }

    if (audioLinks.length > 0) {
      for (const a of audioLinks) {
        const aLang = a.language || a.Language || '';
        const aLink = a.link || a.Link || '';
        const lLower = aLang.toLowerCase();
        let lCode = 'sub';
        let lLabel = aLang || 'Default';

        if (lLower.includes('hindi')) {
          lCode = 'hin';
          lLabel = 'Hindi (Default Dub)';
        } else if (lLower.includes('japan')) {
          lCode = 'sub';
          lLabel = 'Japanese (Sub)';
        } else if (lLower.includes('english')) {
          lCode = 'dub';
          lLabel = 'English (Dub)';
        } else if (lLower.includes('tamil')) {
          lCode = 'tam';
          lLabel = 'Tamil';
        } else if (lLower.includes('telugu')) {
          lCode = 'tel';
          lLabel = 'Telugu';
        } else if (lLower.includes('kannada')) {
          lCode = 'kan';
          lLabel = 'Kannada';
        }

        audioOptions.push({
          label: lLabel,
          language: aLang,
          langCode: lCode
        });

        if (!selectedLink) {
          if (
            (requestedLang === 'hin' && lLower.includes('hindi')) ||
            ((requestedLang === 'sub' || requestedLang === 'jpn') && lLower.includes('japan')) ||
            ((requestedLang === 'dub' || requestedLang === 'eng') && lLower.includes('english')) ||
            (requestedLang === 'tam' && lLower.includes('tamil')) ||
            (requestedLang === 'tel' && lLower.includes('telugu')) ||
            (requestedLang === 'kan' && lLower.includes('kannada'))
          ) {
            selectedLink = aLink;
          }
        }
      }

      if (!selectedLink && audioLinks.length > 0) {
        selectedLink = audioLinks[0].link || audioLinks[0].Link || '';
      }
    }
  }

  if (!selectedLink && hashDirect) {
    if (hashDirect.startsWith('http')) {
      selectedLink = hashDirect;
    } else {
      selectedLink = `https://abyssplayer.com/${hashDirect}`;
    }
  }

  if (!selectedLink) {
    throw new Error('Could not locate Server 1 AbyssPlayer link on episode page');
  }

  // Check if selectedLink is cached
  if (animeSaltStreamCache.has(selectedLink)) {
    const cached = animeSaltStreamCache.get(selectedLink);
    return {
      proxiedURL: cached.proxiedURL,
      tracks: cached.tracks,
      audioOptions,
      resolvedSlug: cached.resolvedSlug
    };
  }

  const abyssRes = await fetchText(selectedLink, {
    headers: { referer: 'https://animesalt.cx/' }
  });

  if (abyssRes.statusCode !== 200 || !abyssRes.body) {
    throw new Error(`AbyssPlayer returned ${abyssRes.statusCode}`);
  }

  const mDatas = abyssRes.body.match(reDatasConst);
  if (!mDatas || !mDatas[1]) {
    throw new Error('const datas payload not found in AbyssPlayer page');
  }

  const { datas, media } = decryptAbyssDatas(mDatas[1]);

  // Type A: Direct MP4 Source (prefer h264)
  let bestSource = null;
  const sources = media?.mp4?.sources || [];
  for (const s of sources) {
    if (!s.status || !s.path || !s.url) continue;
    if (s.codec === 'h264') {
      if (!bestSource || bestSource.codec !== 'h264' || s.res_id > bestSource.res_id) {
        bestSource = s;
      }
    } else if (!bestSource || (bestSource.codec !== 'h264' && s.res_id > bestSource.res_id)) {
      bestSource = s;
    }
  }

  if (bestSource) {
    const parts = bestSource.path.split('/');
    const filename = parts[parts.length - 1];
    const streamToken = encryptToken({
      url: `${bestSource.url}/${bestSource.path}`,
      ref: 'https://abyssplayer.com/',
      key: filename,
      cipher: 'abyss-ctr',
      exp: Math.floor(Date.now() / 1000) + (6 * 3600)
    });
    const proxiedURL = `/p/${streamToken}/video.mp4`;
    const resEntry = {
      proxiedURL,
      tracks: null,
      audioOptions,
      resolvedSlug: datas.slug || slug
    };
    animeSaltStreamCache.set(cacheKey, resEntry);
    animeSaltStreamCache.set(selectedLink, resEntry);
    return resEntry;
  }

  // Type B: Chunked FristData (prefer h264)
  let bestFD = null;
  const fristDatas = media?.mp4?.fristDatas || [];
  for (const fd of fristDatas) {
    if (!fd.url) continue;
    if (fd.codec === 'h264') {
      if (!bestFD || bestFD.codec !== 'h264' || fd.res_id > bestFD.res_id) {
        bestFD = fd;
      }
    } else if (!bestFD || (bestFD.codec !== 'h264' && fd.res_id > bestFD.res_id)) {
      bestFD = fd;
    }
  }

  if (bestFD) {
    let domain = '';
    for (const s of sources) {
      if (s.res_id === bestFD.res_id && s.sub) {
        if (s.codec === bestFD.codec || !domain) {
          domain = `${s.sub}.sssrr.org`;
        }
        if (s.codec === bestFD.codec) break;
      }
    }
    if (!domain && media?.mp4?.domains?.length > 0) {
      domain = media.mp4.domains[0];
    }
    if (domain && !domain.includes('.')) {
      domain = `${domain}.sssrr.org`;
    }

    const parts = bestFD.url.split('/');
    const filename = parts[parts.length - 1];
    const streamToken = encryptToken({
      url: bestFD.url,
      ref: 'https://abyssplayer.com/',
      key: filename,
      cipher: 'abyss-chunked',
      ts: bestFD.size,
      ps: bestFD.partSize,
      cs: 5242880,
      mid: datas.md5_id,
      rid: bestFD.res_id,
      dom: domain,
      exp: Math.floor(Date.now() / 1000) + (6 * 3600)
    });
    const proxiedURL = `/p/${streamToken}/video.mp4`;
    const resEntry = {
      proxiedURL,
      tracks: null,
      audioOptions,
      resolvedSlug: datas.slug || slug
    };
    animeSaltStreamCache.set(cacheKey, resEntry);
    animeSaltStreamCache.set(selectedLink, resEntry);
    return resEntry;
  }

  throw new Error('No valid H.264 stream found in Abyss response');
}

module.exports = {
  resolveAnimeSaltSlug,
  extractAnimeSaltStream
};
