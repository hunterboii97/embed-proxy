# YumeZone Stream & Clean Embed Proxy API (MegaPlay, AnimeSalt & Zoko)

Dedicated high-performance Go reverse proxy, embed sanitizer, and multi-server video scraper for **MegaPlay** (`megaplay.buzz`), **AnimeSalt Server 1** (`as-cdn26.top` / `animesalt.cx`), and **Zoko** (`zokoanime.video`). Extracts clean HLS streams, proxies M3U8 video chunks with automatic CDN referer spoofing and permissive CORS, and renders a 100% ad-free OLED video player with automatic audio track selection, multi-audio switcher, subtitle management, and MyAnimeList/AniList catalog mapping.

## 🚀 Key Features

- **Zoko Server Scraper & Decryptor (`zokoanime.video`)**: Scrapes and deobfuscates HLS streams and VTT subtitles from Zoko, proxies video chunks with automatic CDN referer spoofing (`*.aniwatchtv.uk`), and renders them in our custom OLED video player. Supports both MyAnimeList ID and AniList ID with intro/outro skip metadata extraction.
- **AnimeSalt Server 1 (Hindi Dub Extractor)**: Scrapes `as-cdn26.top` Server 1 multi-audio HLS master playlists directly from AnimeSalt series slugs or AniList/MAL IDs, pre-selecting Hindi Dub by default while providing an in-player audio track switcher for Japanese, English, Tamil, and Telugu.
- **Allowed Site / Domain Embedding Security**: Enforces strict `ALLOWED_EMBED_DOMAINS` environment configuration. Only whitelisted sites can embed the player in an `<iframe>` (unauthorized domains get rejected at the HTTP/CSP level in advance without loading). Direct browser tab access remains unrestricted.
- **Ad & Popup Stripping**: Sanitizes upstream stream sources by bypassing ad scripts, popups, and anti-sandbox blockers.
- **MyAnimeList & AniList Catalog Resolution**: Embed directly via MAL ID or AniList ID with automated fallback resolution (AniZip -> AniList GraphQL -> Jikan).
- **Clean OLED Bespoke Video Player**: High-resolution streaming with 60fps scrub bar, 10s skip, landscape fullscreen, mobile touch volume, subtitle switching, and multi-track audio switching.
- **Bi-Directional `postMessage` Telemetry**: Emits `time`, `complete`, `watching-log`, and `YUME_SWITCH_SERVER` events to the parent website for progress tracking and auto-next episode triggers.
- **HLS / TS Stream Proxying**: High-throughput zero-copy M3U8 playlist rewriting and chunk streaming with AES-GCM token verification.
- **Upstream CDN Whitelists**: Injects required `Referer` headers (`as-cdn26.top`, `megaplay.buzz`, `zokoanime.video`, `aniwatchtv.uk`, etc.) and permissive CORS headers for all streaming CDNs.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` or `/docs` or `/api` | Interactive Web Documentation & Live Embed Sandbox |
| `GET` | `/embed/zoko/mal/{mal_id}/{ep}/{lang}` | Clean OLED embed player for Zoko (MyAnimeList ID) |
| `GET` | `/embed/zoko/ani/{anilist_id}/{ep}/{lang}` | Clean OLED embed player for Zoko (AniList ID) |
| `GET` | `/embed/zoko/{mal_id}/{ep}/{lang}` | Clean OLED embed player for Zoko (Direct MAL ID) |
| `GET` | `/player/zoko?mal={mal_id}&ep={ep}&lang={lang}` | Query-param format player for Zoko |
| `GET` | `/api/zoko/source?mal={mal}&ani={ani}&ep={ep}&lang={sub\|dub}` | Direct JSON stream extractor for Zoko with subtitles & skip timings |
| `GET` | `/embed/animesalt/{slug}-{season}x{ep}?lang={hin\|sub\|dub}` | Clean OLED embed player for AnimeSalt Server 1 (Hindi Dub default) |
| `GET` | `/embed/animesalt/ani/{anilist_id}/{ep}/{lang}` | AnimeSalt Server 1 embed by AniList ID |
| `GET` | `/embed/animesalt/mal/{mal_id}/{ep}/{lang}` | AnimeSalt Server 1 embed by MyAnimeList ID |
| `GET` | `/embed/as-cdn/{hash}?lang={hin\|sub\|dub}` | AnimeSalt Server 1 direct video hash embed |
| `GET` | `/player/salt?slug={slug}&ep={ep}&lang={lang}` | Query-param format player for AnimeSalt |
| `GET` | `/api/animesalt/source?slug={slug}&season={s}&ep={e}` | Direct JSON stream extractor for AnimeSalt Server 1 |
| `GET` | `/embed/megaplay/mal/{mal_id}/{ep_num}/{language}` | Clean OLED embed player for MegaPlay (MAL ID) |
| `GET` | `/embed/megaplay/ani/{anilist_id}/{ep_num}/{language}` | Clean OLED embed player for MegaPlay (AniList ID) |
| `GET` | `/embed/megaplay/s-2/{episode_id}/{language}` | Direct embed player for catalog episode ID |
| `GET` | `/p/{encrypted_token}` | Secure HLS playlist / TS video segment stream proxy |
| `GET` | `/stream/getSources` | Direct upstream JSON stream sources extractor for MegaPlay |
| `GET` | `/health` | Service healthcheck & timestamp information |

---

## 💻 Webmaster Quick Integration

### Zoko Server (Sub / Dub)
```html
<!-- Responsive 16:9 Video Embed Container -->
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe 
    src="https://yume-proxy-railway-production.up.railway.app/embed/zoko/mal/21/1/sub"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

### AnimeSalt Server 1 (Hindi Dub / Multi-Audio)
```html
<!-- Responsive 16:9 Video Embed Container -->
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe 
    src="https://yume-proxy-railway-production.up.railway.app/embed/animesalt/dan-da-dan-1x1?lang=hin"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

### MegaPlay (Sub / Dub)
```html
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe 
    src="https://yume-proxy-railway-production.up.railway.app/embed/megaplay/mal/5114/1/sub"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `5001` | Server listen port (automatically provided by Railway) |
| `PROXY_SECRET` | *(required)* | 32-character AES-256 key matching Render Backend |
| `ALLOWED_EMBED_DOMAINS` | `yumezone.live,*.yumezone.live,localhost,127.0.0.1` | Whitelisted domains permitted to embed the player in an `<iframe>` (blocks unauthorized embeds in advance) |
| `ALLOWED_ORIGINS` | `yumezone.live,localhost,127.0.0.1` | Whitelisted origins for general CORS requests |

---

## 🐳 Railway Deployment

1. Connect this repository (`yume-proxy-railway`) to **Railway**.
2. Railway will automatically build using the multi-stage `Dockerfile`.
3. Set the environment variables in Railway Dashboard:
   - `PROXY_SECRET`: (your shared secret key)
   - `ALLOWED_EMBED_DOMAINS`: `yumezone.live,*.yumezone.live,localhost,127.0.0.1`
   - `ALLOWED_ORIGINS`: `https://yumezone.live,https://www.yumezone.live`
4. Add your custom domain or use Railway's default domain.
