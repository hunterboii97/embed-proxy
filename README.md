# YumeZone Ultra Stream & Clean Embed Proxy API (MegaPlay, AnimeSalt & Zoko)

Dedicated ultra-high-performance Node.js & Fastify reverse proxy, embed sanitizer, and multi-server video scraper for **MegaPlay** (`megaplay.buzz`), **AnimeSalt Server 1** (`animesalt.cx` / `abyssplayer.com`), and **Zoko** (`zokoanime.video`). Engineered with C++ pooled keep-alive sockets (`undici`), zero-copy stream piping, and in-memory LRU caching. Compatible with both **cPanel Web Hosting** (CloudLinux Passenger) and **Docker / VPS / Railway**.

## 🚀 Key Features

- **Zoko Server Scraper & Decryptor (`zokoanime.video`)**: Scrapes and deobfuscates HLS streams and VTT subtitles from Zoko, proxies video chunks with automatic CDN referer spoofing (`*.aniwatchtv.uk`), and renders them in our custom OLED video player. Supports both MyAnimeList ID and AniList ID with intro/outro skip metadata extraction.
- **AnimeSalt Server 1 (Hindi Dub Extractor)**: Scrapes AnimeSalt Server 1 multi-audio streams directly from AnimeSalt series slugs or AniList/MAL IDs, pre-selecting Hindi Dub by default while providing an in-player audio track switcher for Japanese, English, Tamil, and Telugu.
- **Allowed Site / Domain Embedding Security**: Enforces strict `ALLOWED_EMBED_DOMAINS` environment configuration. Only whitelisted sites can embed the player in an `<iframe>` (unauthorized domains get rejected at the HTTP/CSP level in advance without loading). Direct browser tab access remains unrestricted.
- **Ad & Popup Stripping**: Sanitizes upstream stream sources by bypassing ad scripts, popups, and anti-sandbox blockers.
- **MyAnimeList & AniList Catalog Resolution**: Embed directly via MAL ID or AniList ID with automated fallback resolution (AniZip -> AniList GraphQL -> Jikan).
- **Clean OLED Bespoke Video Player**: High-resolution streaming with 60fps scrub bar, 10s skip, landscape fullscreen, mobile touch volume, subtitle switching, and multi-track audio switching.
- **Bi-Directional `postMessage` Telemetry**: Emits `time`, `complete`, `watching-log`, and `YUME_SWITCH_SERVER` events to the parent website for progress tracking and auto-next episode triggers.
- **HLS / TS Stream Proxying**: High-throughput zero-copy M3U8 playlist rewriting and chunk streaming with AES-GCM token verification.
- **Upstream CDN Whitelists**: Injects required `Referer` headers (`abyssplayer.com`, `megaplay.buzz`, `zokoanime.video`, `aniwatchtv.uk`, etc.) and permissive CORS headers for all streaming CDNs.

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
| `GET` | `/api/download` or `/download` | Real-time zero-transcode MP4 download endpoint with quality selector (`1080p`, `720p`, `480p`, `360p`, `best`) for Discord bots and direct downloaders |
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

## 🤖 Discord Bot Real-Time MP4 Download Integration

The `/api/download` endpoint streams episodes on-the-fly directly as **standard `.mp4` video files** using real-time zero-transcode remuxing (`-c copy`). Downloads begin in **~1 second** without saving files to server disk.

### Endpoint Syntax
```
GET /api/download?server={zoko|megaplay|salt}&mal={mal_id}&ep={ep}&q={1080p|720p|480p|360p|best}&lang={sub|dub|hin}
```

### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `server` | string | `zoko` | Video provider: `zoko`, `megaplay`, or `animesalt` (or `salt`) |
| `mal` | integer | - | MyAnimeList anime ID (e.g. `52991` for Solo Leveling, `21` for One Piece) |
| `ani` | integer | - | AniList anime ID |
| `slug` | string | - | AnimeSalt series slug (e.g. `dan-da-dan`) |
| `ep` | integer | `1` | Episode number |
| `q` | string | `best` | Preferred resolution: `1080p`, `720p`, `480p`, `360p`, or `best` |
| `lang` | string | `sub` | Audio/subtitle track: `sub`, `dub`, or `hin` (Hindi default for AnimeSalt) |
| `title` | string | *(auto)* | Custom title for output filename (e.g. `[YumeZone]_Solo_Leveling_EP01_SUB_1080p.mp4`) |

### Example Usage for Discord Bots (Python / Discord.js)
```python
# Discord Bot Python Example: Send Rich Embed with One-Click Download Buttons
download_1080p = f"https://your-railway-app.up.railway.app/api/download?server=zoko&mal={mal_id}&ep={ep}&q=1080p"
download_720p  = f"https://your-railway-app.up.railway.app/api/download?server=zoko&mal={mal_id}&ep={ep}&q=720p"

# Add buttons linking directly to the URLs for members to download instantly at line-rate speed!
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

---

## 🌐 cPanel Web Hosting Deployment (1-Click Setup)

This application is built to run 100% natively on cPanel via CloudLinux Phusion Passenger:

1. **Upload Files**:
   - Upload the project files (or `git clone`) into your cPanel home directory (e.g. `/home/username/yume-proxy`).
   - *(Do not upload `node_modules/`; cPanel will install dependencies cleanly).*
2. **Setup Node.js App**:
   - In cPanel, search for **Setup Node.js App** and click **Create Application**.
   - **Node.js version**: Choose **18.x, 20.x, or 22.x**.
   - **Application mode**: `Production`.
   - **Application root**: `yume-proxy` (path where files are located).
   - **Application URL**: Your domain or subdomain (e.g. `embed.yumezone.live` or `proxy.yourdomain.com`).
   - **Application startup file**: `app.js`.
3. **Configure Environment Variables**:
   - Under the Environment variables section in cPanel, add:
     - `PROXY_SECRET`: (your 32-byte secret key)
     - `ALLOWED_EMBED_DOMAINS`: `yumezone.live,*.yumezone.live,localhost,127.0.0.1`
     - `ALLOWED_ORIGINS`: `yumezone.live,localhost,127.0.0.1`
4. **Install Dependencies & Start**:
   - Click **Create**.
   - Click the **Run NPM Install** button.
   - Click **Restart Application**.
   - Your embed proxy is now live, blazing fast, and SSL-secured!

---

## 🐳 Docker / Railway / VPS Deployment

1. Connect this repository to **Railway**, **Render**, or your own **VPS**.
2. Deploy directly using the provided `Dockerfile`.
3. Set the environment variables in your dashboard (`PROXY_SECRET`, `ALLOWED_EMBED_DOMAINS`, etc.).
4. The service will boot in ~5 seconds and stream at maximum line-rate.
