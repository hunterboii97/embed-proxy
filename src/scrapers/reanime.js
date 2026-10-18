const { fetchJSON } = require('../utils/http');
const { singleflight } = require('../utils/singleflight');

const REANIME_API = 'https://reanime.to/api/flix';
const FLIXCLOUD_LINK_RE = /^https?:\/\/(?:[a-z0-9-]+\.)?flixcloud\.[a-z]+\/(?:d|e|embed|watch|file|v)\/([A-Za-z0-9_-]+)/i;

function normalizeLang(value) {
  const s = String(value || '').toLowerCase();
  if (s.includes('dub')) return 'dub';
  if (s.includes('sub')) return 'sub';
  return s;
}

// Reanime returns flixcloud player links (/e/<id>?v=N). The download API for
// the same file lives at /d/<id>; only the file id is needed to resolve it.
function parseFlixcloudId(link) {
  const m = FLIXCLOUD_LINK_RE.exec(String(link || ''));
  return m ? m[1] : '';
}

async function fetchFlixServers(aniId, ep) {
  const url = `${REANIME_API}/${aniId}/${ep}`;
  const res = await fetchJSON(url, {
    signal: AbortSignal.timeout(10000),
    headers: { referer: 'https://reanime.to/' }
  });
  if (res.statusCode !== 200) {
    throw new Error(`reanime HTTP ${res.statusCode}`);
  }
  const servers = Array.isArray(res.data?.servers) ? res.data.servers : [];
  const out = [];
  for (const s of servers) {
    const fileId = parseFlixcloudId(s?.dataLink);
    if (!fileId) continue;
    const lang = normalizeLang(s.dataType);
    if (lang !== 'sub' && lang !== 'dub') continue;
    out.push({
      name: String(s.serverName || ''),
      lang,
      link: String(s.dataLink),
      fileId
    });
  }
  return out;
}

// serverNum is 1-based and counts only entries for the requested language.
// Exact duplicate links are collapsed so a mirrored entry does not burn a slot.
function pickFlixServer(servers, serverNum, lang) {
  const seen = new Set();
  const forLang = [];
  for (const s of servers) {
    if (s.lang !== lang) continue;
    if (seen.has(s.link)) continue;
    seen.add(s.link);
    forLang.push(s);
  }
  return forLang[serverNum - 1] || null;
}

function listFlixServers(aniId, ep) {
  return singleflight(`reanime|${aniId}|${ep}`, () => fetchFlixServers(aniId, ep));
}

module.exports = {
  listFlixServers,
  pickFlixServer
};
