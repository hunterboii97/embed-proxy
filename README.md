# MikazaAPI — Professional Anime Embed Streaming Service

Dedicated ultra-high-performance Node.js & Fastify reverse proxy, embed sanitizer, and multi-server video scraper for **Kira** (MegaPlay), **Haiku** (AnimeSalt), and **Naoka** (Zoko). Engineered with C++ pooled keep-alive sockets (`undici`), zero-copy stream piping, and in-memory LRU caching. Compatible with both **cPanel Web Hosting** (CloudLinux Passenger) and **Docker / VPS / Railway**.

## Server Architecture

Our service operates three streaming servers:

- **Kira Server**: Primary streaming server with extensive catalog coverage
- **Haiku Server**: Multi-audio server with Hindi dub support (Japanese, English, Tamil, Telugu)
- **Naoka Server**: Secure streaming with encrypted playback and skip timing detection

## 🚀 Key Features

- **Ad-Free OLED Player**: Clean video player with zero ads, popups, or trackers
- **Multi-Server Support**: Three streaming servers with automatic failover
- **postMessage API**: Real-time events for progress tracking and auto-next episode
- **Library Downloads**: `/download/kaiju/ani/...` proxies original multi-audio episodes with Mikaza-API naming
- **Multi-Audio Support**: Japanese, English, Hindi, Tamil, and Telugu audio tracks
- **ID Resolution**: Automatic MyAnimeList and AniList ID resolution
- **Encrypted Streaming**: AES-GCM encrypted stream tokens with CDN spoofing
- **Skip Timings**: Intro/outro skip detection with metadata extraction
- **Domain Whitelisting**: Strict ALLOWED_EMBED_DOMAINS security

---

## 📡 API Endpoints

### Embed Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/docs` | Interactive Documentation & Live Tester |
| `GET` | `/embed/kira/mal/{mal_id}/{ep}/{lang}` | Kira Server embed (MAL ID) |
| `GET` | `/embed/kira/ani/{anilist_id}/{ep}/{lang}` | Kira Server embed (AniList ID) |
| `GET` | `/embed/haiku/{slug}-{season}x{ep}?lang={hin\|sub\|dub}` | Haiku Server embed (Series Slug) |
| `GET` | `/embed/haiku/ani/{anilist_id}/{ep}/{lang}` | Haiku Server embed (AniList ID) |
| `GET` | `/embed/haiku/mal/{mal_id}/{ep}/{lang}` | Haiku Server embed (MAL ID) |
| `GET` | `/embed/naoka/mal/{mal_id}/{ep}/{lang}` | Naoka Server embed (MAL ID) |
| `GET` | `/embed/naoka/ani/{anilist_id}/{ep}/{lang}` | Naoka Server embed (AniList ID) |

### JSON Source API

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/kira/source?mal={mal}&ani={ani}&ep={ep}&lang={lang}` | Kira Server source JSON |
| `GET` | `/api/haiku/source?slug={slug}&season={s}&ep={e}` | Haiku Server source JSON |
| `GET` | `/api/naoka/source?mal={mal}&ani={ani}&ep={ep}&lang={sub\|dub}` | Naoka Server source JSON |

### System Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/download/kaiju/ani/{anilist_id}/{ep}` | Original episode file with all audio tracks and subtitles (Flixcloud; requires `DOWNLOAD_ENABLED`) |
| `GET` | `/p/{encrypted_token}` | Encrypted HLS/TS/VTT proxy |
| `GET` | `/health` | Service health check |

### Library Downloads

`/download/kaiju/ani/{anilist_id}/{ep}` resolves the Flixcloud file listed by
Reanime and proxies it as-is, named:

```
[Mikaza-API] - Mushoku Tensei III: Jobless Reincarnation (Ep 01).mkv
```

The source is the original multi-audio MKV with Japanese and English tracks
plus every subtitle, so the file plays either language depending on the
player's track selection. Range requests and `HEAD` are supported. `kaiju` is
the current library source; future sources plug into the same path shape. The
signed CDN URL is IP-bound and expires in ~15 minutes, so the proxy resolves it
per request. Disabled unless `DOWNLOAD_ENABLED=true`. Each IP gets **1 request
per minute** and **5 per 24 hours** for GETs (`HEAD` is free); the shared quota
lives under `data/download-quota` (gitignored).

---

## 💻 Quick Integration

### Kira Server (MAL ID)
```html
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe
    src="https://your-domain.com/embed/kira/mal/5114/1/sub"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

### Haiku Server (Hindi Dub)
```html
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe
    src="https://your-domain.com/embed/haiku/dan-da-dan-1x1?lang=hin"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

### Naoka Server (MAL ID)
```html
<div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;">
  <iframe
    src="https://your-domain.com/embed/naoka/mal/21/1/sub"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture">
  </iframe>
</div>
```

---

## 📡 postMessage API

The embedded player sends events via `window.postMessage`:

| Event | Payload | Description |
| :--- | :--- | :--- |
| `time` | `{ time, duration, percent }` | Playback progress |
| `complete` | `{ event: "complete" }` | Episode finished (auto-next) |
| `watching-log` | `{ currentTime, duration }` | Periodic watch-time logging |
| `YUME_SWITCH_SERVER` | `{ server: string }` | User switched server |

### JavaScript Example
```javascript
window.addEventListener("message", function (event) {
  let data = event.data;
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch (e) { return; }
  }
  if (!data) return;

  if (data.event === "time") {
    console.log("Progress:", data.percent + "%");
  }

  if (data.event === "complete") {
    console.log("Episode finished!");
    loadNextEpisode();
  }
});
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `5001` | Server listen port |
| `LISTEN_HOST` | `0.0.0.0` | Standalone bind address. Set `127.0.0.1` on VPS behind nginx (keeps the raw port private). |
| `PROXY_SECRET` | *(required)* | Strong random AES-256 key. The server refuses to boot with a missing/placeholder value (public defaults are rejected). |
| `ALLOWED_EMBED_DOMAINS` | `localhost,127.0.0.1` | Embed allowlist. Requests from any other origin get a bare `403` (no page). Also drives the `frame-ancestors` CSP. |
| `ALLOWED_ORIGINS` | `localhost,127.0.0.1` | CORS-allowed origins (no wildcard; foreign origins get no `Access-Control-Allow-Origin`). |
| `SOURCE_API_ENABLED` | *off* | Enables the JSON source API (`/api/*/source`). Off = `403`. Licensed deployments only. |
| `DOWNLOAD_ENABLED` | *off* | Enables `/download/kaiju/ani/...`. Off = `403`. |
| `RATE_LIMIT_ENABLED` | `true` | Master switch for all per-IP rate limits. `false` = unlimited requests (embed gate + IP-bound tokens still apply). |
| `EMBED_RATE_LIMIT_PER_MIN` | `3000` | Per-IP embed-page rate limit (`429` when exceeded). Defaults are generous so real viewers never trip them; `0` disables. |
| `PROXY_RATE_LIMIT_PER_MIN` | `30000` | Per-IP `/p/*` stream/token rate limit. `0` disables. |
| `FLIX_DOWNLOAD_RATE_LIMIT_PER_MIN` | `1` | Per-IP budget for `/download/kaiju/...` (shared across workers). `0` disables. |
| `FLIX_DOWNLOAD_DAILY_LIMIT` | `5` | Per-IP downloads per rolling 24 hours (shared across workers). `0` disables. |
| `FLIX_DOWNLOAD_QUOTA_DIR` | `./data/download-quota` | Shared quota store used by all workers. |
| `ALLOW_INSECURE_DEFAULT_SECRET` | *unset* | Local dev only: boot with a placeholder `PROXY_SECRET`. Never set in production. |

---

## 🌐 Deployment

### cPanel (CloudLinux Passenger)
1. Upload files to cPanel home directory
2. Create Node.js app in cPanel
3. Set environment variables
4. Run NPM install and restart

### Docker / Railway / VPS
1. Connect repository to Railway/Render/VPS
2. Deploy with provided Dockerfile
3. Set environment variables
4. Service boots in ~5 seconds

---

## 📊 Server Details

### Kira Server
- **Source**: MegaPlay
- **Features**: Extensive catalog, MAL/AniList support
- **Audio**: Sub, Dub
- **Best for**: General anime streaming

### Haiku Server
- **Source**: AnimeSalt Server 1
- **Features**: Multi-audio, Hindi dub default
- **Audio**: Japanese, English, Hindi, Tamil, Telugu
- **Best for**: Regional content, multi-language

### Naoka Server
- **Source**: Zoko
- **Features**: Encrypted streaming, skip timings
- **Audio**: Sub, Dub
- **Best for**: Quality-focused streaming
