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
- **MP4 Downloads**: Zero-transcode remux with segment prefetch — complete faststart MP4 by default, live fMP4 streaming with `stream=1` (`format=ts` fast path; requires FFmpeg for MP4)
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
| `GET` | `/api/download?server={kira\|naoka\|haiku}&mal={mal}&ep={ep}&q={quality}&lang={lang}&format={mp4\|ts}&stream={0\|1}` | Direct episode download (no UI) |
| `GET` | `/download?...` | Alias of `/api/download` |
| `GET` | `/p/{encrypted_token}` | Encrypted HLS/TS/VTT proxy |
| `GET` | `/health` | Service health check |

---

## ⬇️ Episode Downloads

Triggers a browser Save dialog for a remuxed file — no player UI.

```
GET /api/download?server=kira&mal=5114&ep=1&lang=sub&q=1080&format=mp4
GET /api/download?server=kira&mal=5114&ep=1&lang=sub&stream=1
GET /api/download?server=naoka&mal=21&ep=1&lang=sub&q=720&format=ts
GET /api/download?server=haiku&ani=16498&ep=1&lang=hin
```

| Param | Default | Notes |
| :--- | :--- | :--- |
| `server` | `naoka` (or `haiku` if `slug`/`hash`) | `kira`, `naoka`, or `haiku` |
| `mal` / `ani` | — | MyAnimeList or AniList ID |
| `ep` | `1` | Episode number |
| `q` / `quality` | `best` | `best`, `1080`, `720`, `480`, `360` |
| `lang` | `sub` | `sub`, `dub`, or Haiku langs (`hin`, etc.) |
| `format` | `mp4` | `mp4` = FFmpeg `-c copy` remux; `ts` = raw segment concat (fastest, needs VLC/mpv) |
| `stream` | off | `1` = stream fragmented MP4 while remuxing (instant first bytes, no `Content-Length`); default remuxes to a complete regular MP4 first |
| `title` | auto | Optional filename title override |

**How it works:** HLS segments are fetched with a prefetch pool (12 parallel) and remuxed with FFmpeg `-c copy` (no re-encode). By default the episode is remuxed to a complete **regular MP4** (faststart, real `Content-Length`, seeking works everywhere) — the client sees no data until the remux finishes. `stream=1` switches to **fragmented MP4 streamed live**: first bytes arrive instantly and it’s CDN-timeout friendly, but some TVs/hardware players reject fMP4 and progress bars are indeterminate. Encrypted (`EXT-X-KEY`) or CMAF (`EXT-X-MAP`) playlists use FFmpeg’s HLS demuxer. Haiku redirects to an already-MP4 proxy URL with `Content-Disposition`.

**Expected time:** Remux CPU overhead is ~1–5%. Default (file) mode: user wait ≈ CDN→proxy transfer time (plus a small faststart pass), then the file downloads at full speed with a real progress bar. Rough guide for a ~24 min episode: 720p often under 1–2 min on a decent link; 1080p ~1–4 min.

**Requirements & limits:**
- **Docker / Railway:** FFmpeg is in the `Dockerfile` — MP4 remux works out of the box.
- **cPanel / Passenger:** Install `ffmpeg` on the host; without it MP4 requests return `503` (use `format=ts` for raw segments).
- **Concurrency:** Max 5 simultaneous downloads per instance; excess requests get `429`. Override with the `MAX_CONCURRENT_DOWNLOADS` env var on bigger instances.
- **Disk:** Default mode buffers one temp MP4 per active download in the OS temp dir (≈ one episode per download slot); files are deleted when the transfer ends and stale leftovers are swept on boot.
- **Cloudflare:** Proxied zones often kill idle connections after ~100s — in default mode nothing is sent until the remux completes. For long episodes on proxied zones prefer `stream=1`, the Railway/direct origin URL, or set the download path to DNS-only (grey cloud).

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
5. Install system `ffmpeg` if you need MP4 remux downloads (otherwise `.ts` fallback)

### Docker / Railway / VPS
1. Connect repository to Railway/Render/VPS
2. Deploy with provided Dockerfile (includes FFmpeg)
3. Set environment variables
4. Service boots in ~5 seconds
5. If Cloudflare sits in front, use the direct origin for long `/api/download` transfers

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
