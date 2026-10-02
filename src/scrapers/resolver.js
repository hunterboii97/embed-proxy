const { fetchText, fetchJSON } = require('../utils/http');
const { animeTitleCache, malIdCache } = require('../utils/cache');

async function resolveMalId(idNum) {
  if (!idNum || idNum <= 0) return 0;
  if (malIdCache.has(idNum)) return malIdCache.get(idNum);

  // Parallel race: Tier 1 AniZip API & Tier 2 AniList GraphQL
  const promises = [];

  // 1. AniZip API
  promises.push(
    fetchJSON(`https://api.ani.zip/mappings?anilist_id=${idNum}`)
      .then(res => {
        if (res.data?.mappings?.mal_id > 0) {
          return res.data.mappings.mal_id;
        }
        return 0;
      })
      .catch(() => 0)
  );

  // 2. AniList GraphQL
  const gqlQuery = `query ($id: Int) { Media (id: $id, type: ANIME) { idMal } }`;
  promises.push(
    fetchJSON('https://graphql.anilist.co', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: gqlQuery, variables: { id: idNum } })
    })
      .then(res => {
        if (res.data?.data?.Media?.idMal > 0) {
          return res.data.data.Media.idMal;
        }
        return 0;
      })
      .catch(() => 0)
  );

  const results = await Promise.all(promises);
  const found = results.find(id => id > 0) || 0;
  if (found > 0) {
    malIdCache.set(idNum, found);
  }
  return found;
}

async function resolveAnimeTitle(anilistID, malID) {
  if ((!anilistID || anilistID <= 0) && (!malID || malID <= 0)) return '';
  const cacheKey = `ani:${anilistID}_mal:${malID}`;
  if (animeTitleCache.has(cacheKey)) return animeTitleCache.get(cacheKey);

  const promises = [];

  // 1. AniZip API
  if (anilistID > 0 || malID > 0) {
    const url = anilistID > 0 
      ? `https://api.ani.zip/mappings?anilist_id=${anilistID}`
      : `https://api.ani.zip/mappings?mal_id=${malID}`;
    promises.push(
      fetchJSON(url)
        .then(res => {
          const t = res.data?.titles?.en || res.data?.titles?.canonical || res.data?.titles?.rj;
          return t || '';
        })
        .catch(() => '')
    );
  }

  // 2. AniList GraphQL
  if (anilistID > 0 || malID > 0) {
    let query, variables;
    if (anilistID > 0) {
      query = `query ($id: Int) { Media (id: $id, type: ANIME) { title { english userPreferred romaji } } }`;
      variables = { id: anilistID };
    } else {
      query = `query ($idMal: Int) { Media (idMal: $idMal, type: ANIME) { title { english userPreferred romaji } } }`;
      variables = { idMal: malID };
    }
    promises.push(
      fetchJSON('https://graphql.anilist.co', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query, variables })
      })
        .then(res => {
          const title = res.data?.data?.Media?.title;
          return title?.english || title?.userPreferred || title?.romaji || '';
        })
        .catch(() => '')
    );
  }

  // 3. Jikan / MAL API
  if (malID > 0) {
    promises.push(
      fetchJSON(`https://api.jikan.moe/v4/anime/${malID}`)
        .then(res => {
          const data = res.data?.data;
          return data?.title_english || data?.title || '';
        })
        .catch(() => '')
    );
  }

  // Fast resolution: return first non-empty title
  const results = await Promise.all(promises);
  const found = results.find(t => Boolean(t)) || '';
  if (found) {
    animeTitleCache.set(cacheKey, found);
  }
  return found;
}

module.exports = {
  resolveMalId,
  resolveAnimeTitle
};
