# MegaPlay Stream & Clean Embed Proxy API

Dedicated high-performance Go reverse proxy and ad-free embed sanitizer for **MegaPlay** (`megaplay.buzz`). Extracts clean HLS streams, proxies M3U8 video chunks with automatic CDN referer spoofing and permissive CORS, and renders a 100% ad-free OLED video player with MyAnimeList & AniList catalog mapping.

## 🚀 Key Features

- **Ad & Popup Stripping**: Sanitizes MegaPlay stream sources by bypassing ad scripts (`app.main.js`), tracker beacons, and anti-sandbox blockers.
- **MyAnimeList & AniList Catalog Resolution**: Embed directly via MAL ID (`/embed/megaplay/mal/{id}/{ep}/{lang}`) or AniList ID (`/embed/megaplay/ani/{id}/{ep}/{lang}`) with automated 3-tier fallback resolution (AniZip -> AniList GraphQL -> Kitsu).
- **Clean OLED Bespoke Video Player**: High-resolution streaming with 60fps scrub bar, 10s skip, landscape fullscreen, mobile touch volume, and multi-track subtitle switching.
- **Bi-Directional `postMessage` Telemetry**: Emits `time`, `complete`, `watching-log`, and `YUME_SWITCH_SERVER` events to the parent website for progress tracking and auto-next episode triggers.
- **HLS / TS Stream Proxying**: High-throughput zero-copy M3U8 playlist rewriting and chunk streaming with AES-GCM token verification.
- **Upstream CDN Whitelists**: Injects required `Referer: https://megaplay.buzz/` and permissive CORS headers for all MegaPlay streaming CDNs.
- **Interactive Documentation & Sandbox**: Built-in dark OLED web application served at `/`, `/docs`, and `/api` for webmasters to configure, test, and preview embeds in real-time.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` or `/docs` or `/api` | Interactive Web Documentation & Live Embed Sandbox |
| `GET` | `/embed/megaplay/mal/{mal_id}/{ep_num}/{language}` | Clean OLED embed player for MyAnimeList ID |
| `GET` | `/embed/megaplay/ani/{anilist_id}/{ep_num}/{language}` | Clean OLED embed player for AniList ID (auto-resolved to MAL) |
| `GET` | `/embed/megaplay/s-2/{episode_id}/{language}` | Direct embed player for catalog episode ID |
| `GET` | `/p/{encrypted_token}` | Secure HLS playlist / TS video segment stream proxy |
| `GET` | `/stream/getSources` | Direct upstream JSON stream sources extractor |
| `GET` | `/health` | Service healthcheck & timestamp information |

---

## 💻 Webmaster Quick Integration

```html
<!-- Responsive 16:9 Video Embed Container -->
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
    console.log("Episode finished! Triggering next episode...");
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
