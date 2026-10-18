const { fetchJSON } = require('../utils/http');
const { singleflight } = require('../utils/singleflight');

const REANIME_API = 'https://reanime.to/api/flix';
const FLIXCLOUD_LINK_RE = /^https?:\/\/(?:[a-z0-9-]+\.)?flixcloud\.[a-z]+\/(?:d|e|embed|watch|file|v)\/([A-Za-z0-9_-]+)/i;

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
    out.push({
      name: String(s.serverName || ''),
      link: String(s.dataLink),
      fileId
    });
  }
  return out;
}

// serverNum is 1-based over unique links. Sub and dub entries point at the
// same file, so exact duplicate links are collapsed before counting slots.
function pickFlixServer(servers, serverNum) {
  const seen = new Set();
  const unique = [];
  for (const s of servers) {
    if (seen.has(s.link)) continue;
    seen.add(s.link);
    unique.push(s);
  }
  return unique[serverNum - 1] || null;
}

function listFlixServers(aniId, ep) {
  return singleflight(`reanime|${aniId}|${ep}`, () => fetchFlixServers(aniId, ep));
}

module.exports = {
  listFlixServers,
  pickFlixServer
};
