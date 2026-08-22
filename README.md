# YumeZone Go Stream & Clean Embed Proxy

High-performance, zero-cold-start streaming reverse proxy and embed sanitizer built with Go 1.22 and Alpine Linux for YumeZone.

## 🚀 Features

- **HLS / TS Stream Proxying**: High-throughput zero-copy m3u8 playlist rewriting and chunk streaming with AES-GCM token verification.
- **MegaPlay Clean Embed Sanitizer**: Real-time server-side HTML proxy for MegaPlay embed player:
  - Whitelisted partner referrers (`https://anikoto.cz/`).
  - Injects `<base href="https://megaplay.buzz/">`.
  - Strips ad scripts (`app.main.js`), tracker beacons, and anti-sandbox blockers.
  - Returns 100% clean, native JWPlayer iframe without popup tabs or redirects.
- **In-Memory Caching**: Ultra-fast sub-2ms response times for repeat playlist and embed requests.
- **Ultra-Low Resource Footprint**: Consumes only ~15–25MB RAM and near-zero idle CPU.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Healthcheck and timestamp info |
| `GET` | `/embed/megaplay/{embed_path}` | Clean sanitized MegaPlay embed HTML |
| `GET` | `/p/{encrypted_token}` | Secure HLS playlist / TS video stream proxy |

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

## 🐳 Railway Deployment

1. Connect this repository (`yume-proxy-railway`) to **Railway**.
2. Railway will automatically build using the multi-stage `Dockerfile`.
3. Set the environment variables in Railway Dashboard:
   - `PROXY_SECRET`: (your shared secret key)
   - `ALLOWED_ORIGINS`: `https://yumezone.live,https://www.yumezone.live`
4. Add your custom domain (e.g. `proxy.yumezone.live`) or use Railway's default domain.
