# YumeZone Go Stream & Clean Embed Proxy API

High-performance, zero-cold-start streaming reverse proxy, anime embed provider, and interactive documentation engine built with Go 1.22 and Alpine Linux for YumeZone.

## 🚀 Features

- **Interactive Web Documentation & Embed Sandbox**: Built-in dark OLED web application served at `/`, `/docs`, and `/api` for webmasters to configure, test, and preview embeds in real-time.
- **MyAnimeList & AniList Auto-Resolution**: Direct embed routes by MAL ID (`/embed/megaplay/mal/{id}/{ep}/{lang}`) and AniList ID (`/embed/megaplay/ani/{id}/{ep}/{lang}`) with automated 3-tier fallback resolution (AniZip -> AniList GraphQL -> Kitsu).
- **Clean OLED Bespoke Video Player**: 100% ad-free, zero-popup player featuring 60fps scrubbing, 10s skip, mobile landscape fullscreen, touch volume, and multi-track subtitle switching.
- **Bi-Directional `postMessage` Telemetry**: Emits `time`, `complete`, `watching-log`, and `YUME_SWITCH_SERVER` events to the parent website for progress tracking and auto-next episode triggers.
- **HLS / TS Stream Proxying**: High-throughput zero-copy M3U8 playlist rewriting and chunk streaming with AES-GCM token verification.
- **30+ CDN Spoofing Whitelists**: Automatic Referer, Origin, and Sec-Fetch headers injection for upstream anime CDNs.
- **In-Memory Caching**: Ultra-fast sub-2ms response times for repeat playlist and embed requests.
- **Ultra-Low Resource Footprint**: Consumes only ~15–25MB RAM and near-zero idle CPU.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` or `/docs` or `/api` | Interactive Web Documentation & Live Embed Sandbox |
| `GET` | `/embed/megaplay/mal/{mal_id}/{ep_num}/{language}` | Clean OLED embed player for MyAnimeList ID |
| `GET` | `/embed/megaplay/ani/{anilist_id}/{ep_num}/{language}` | Clean OLED embed player for AniList ID (auto-resolved) |
| `GET` | `/embed/megaplay/s-2/{episode_id}/{language}` | Direct embed player for catalog episode ID |
| `GET` | `/p/{encrypted_token}` | Secure HLS playlist / TS video segment stream proxy |
| `GET` | `/stream/getSources` | Direct JSON stream sources extractor |
| `POST` | `/api/mapping-request` | Submit missing MAL/AniList catalog ID mapping requests |
| `GET` | `/health` | Service healthcheck & timestamp information |

---

## 💻 Webmaster Quick Integration

```html
<!-- Responsive 16:9 Video Wrapper -->
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

### Player `postMessage` Listener Example

```javascript
window.addEventListener("message", function (event) {
  let data = event.data;
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch (e) { return; }
  }
  if (!data) return;

  // Handle watch progress
  if (data.event === "time") {
    console.log("Progress:", data.time, "/", data.duration, "(" + data.percent + "%)");
  }

  // Handle auto-next episode
  if (data.event === "complete") {
    console.log("Episode completed. Triggering next episode...");
  }
});
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `5001` | Server listen port (automatically provided by Railway) |
| `PROXY_SECRET` | *(required)* | 32-character AES-256 key matching Render Backend |
| `ALLOWED_ORIGINS` | `yumezone.live,localhost` | Whitelisted origins for CORS |

---

## 🛠️ Local Development

```bash
# Run locally
go run main.go

# Build standalone binary
go build -ldflags="-s -w" -o yume-proxy main.go
```

---

## 🐳 Railway Deployment

1. Connect this repository (`yume-proxy-railway`) to **Railway**.
2. Railway will automatically build using the multi-stage `Dockerfile`.
3. Set the environment variables in Railway Dashboard:
   - `PROXY_SECRET`: (your shared secret key)
   - `ALLOWED_ORIGINS`: `https://yumezone.live,https://www.yumezone.live`
4. Add your custom domain or use Railway's default domain.
