# KaidoAPI — Professional Anime Embed Streaming Service

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
- **MP4 Downloads**: Real-time zero-transcode downloads (requires FFmpeg)
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
| `GET` | `/api/download?server={kira\|naoka\|haiku}&mal={mal}&ep={ep}&q={quality}&lang={lang}` | MP4 download (requires FFmpeg) |
| `GET` | `/p/{encrypted_token}` | Encrypted HLS/TS/VTT proxy |
| `GET` | `/health` | Service health check |

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
| `PROXY_SECRET` | *(required)* | 32-character AES-256 key |
| `ALLOWED_EMBED_DOMAINS` | `localhost,127.0.0.1` | Whitelisted embed domains |
| `ALLOWED_ORIGINS` | `localhost,127.0.0.1` | CORS-allowed origins |

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
