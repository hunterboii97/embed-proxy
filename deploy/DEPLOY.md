# MikazaAPI — Phase 2 deploy runbook

Six Node workers on 127.0.0.1:5001-5006, nginx in front (least_conn + 300 GB
NVMe cache), Cloudflare DNS as today. All configs here are written, not applied.

## Multi-worker audit (why 6 workers is safe)

- **No disk writes in the app.** Everything is in-memory or upstream; workers
  are fully stateless on disk.
- **One PROXY_SECRET.** All six instances share the same `.env`, so a token
  minted by one worker validates on every other (verified across 3 local
  workers in Gate 1G).
- **Shared-mode tokens are deterministic.** With `SHARED_SEGMENT_TOKENS=1` the
  token IV is derived from the plaintext + secret instead of random bytes, so
  every worker mints byte-identical URLs. This is what makes the nginx cache
  see one URL per segment. (Without it, each worker mints a different URL and
  the cache hit rate collapses.)
- **Caches are per worker by design.** M3U8 cache, segment RAM cache,
  stream-resolution caches, single-flight and token caches are all in-process.
  A cold object may be fetched once per worker; nginx `proxy_cache_lock`
  collapses viewer-side stampedes, and after the first warm fetch the shared
  disk cache absorbs all workers.
- **Prefetch through loopback** (`PREFETCH_VIA_LOOPBACK=1`) sends warm requests
  back through nginx, so a prefetch started on worker A may land on worker B:
  it fills both the nginx cache and B's RAM cache. Cross-worker by design.
- **Tier is per embed page, priority is per request header.** The parent site's
  Referer picks partner/free once per embed page (partner = ad-free + reserved
  prefetch lane). The player then sends `X-Embed-Tier: partner` on playlist and
  segment requests, so `/p/` URLs stay identical for both tiers and the nginx
  cache still holds one copy per segment. Embed HTML itself is `no-cache`
  because it differs by site; that is a few KB per page view, not the video path.
- **Rate limits are per worker.** Defaults (3000 embed/min, 30000 proxy/min per
  IP) apply to each worker independently, so the effective ceiling is 6×.
  Add the commented nginx `limit_req` below if you want a global per-IP cap.
  `RATE_LIMIT_ENABLED=false` turns the app limits off entirely.
- **Metrics:** the `/metrics` endpoint is not part of this build (Phase 0 work
  is parked on local branch `backup/phase0-metrics`). Live monitoring is the
  separate admin collector in section 7; it never runs inside the workers.

## 1. Prerequisites

    node -v              # must be v24 (or >= 18)
    nginx -v
    cd /opt && git clone <mikara repo> mikaza && cd mikaza

## 2. Kernel + limits

    cp deploy/99-mikaza-sysctl.conf /etc/sysctl.d/99-mikaza.conf
    sysctl --system
    sysctl net.ipv4.tcp_congestion_control   # expect bbr
    cp deploy/99-mikaza-limits.conf /etc/security/limits.d/99-mikaza.conf

## 3. App environment

    cd /opt/mikaza
    cp .env.example .env
    openssl rand -hex 32                 # put this in PROXY_SECRET
    chmod 600 .env

Required values in `.env`:

    PROXY_SECRET=<64 hex chars>
    LISTEN_HOST=127.0.0.1
    SHARED_SEGMENT_TOKENS=1
    PREFETCH_VIA_LOOPBACK=1
    EMBED_MODE=free                      # public embeds + redirect ads
    ALLOWED_EMBED_DOMAINS=<partner domains>   # ad-free + priority lane
    BLOCKED_EMBED_DOMAINS=<optional deny list>
    AD_DIRECT_URLS=<comma separated ad URLs>
    AD_INTERSTITIAL_URL=<sandboxed fallback ad URL>

## 4. Workers (systemd)

    cp deploy/mikaza-api@.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now mikaza-api@{1..6}
    systemctl status 'mikaza-api@*' --no-pager

    for p in 5001 5002 5003 5004 5005 5006; do
      curl -s -o /dev/null -w "$p %{http_code}\n" http://127.0.0.1:$p/docs
    done

## 5. nginx

    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    cp deploy/nginx.conf /etc/nginx/nginx.conf
    install -d -o www-data -g www-data -m 755 /var/cache/nginx/mikaza
    nginx -t && systemctl reload nginx

(RHEL: replace `www-data` with `nginx` in the config and the install command.)

## 6. Verify (measured, not assumed)

Workers healthy:

    for p in 5001 5002 5003 5004 5005 5006; do
      curl -s -o /dev/null -w "$p %{http_code}\n" http://127.0.0.1:$p/docs
    done

Same embed page → same proxied URLs (deterministic tokens):

    curl -s http://127.0.0.1/embed/zoko/mal/21/1/sub > /tmp/a.html
    curl -s http://127.0.0.1/embed/zoko/mal/21/1/sub > /tmp/b.html
    diff <(grep -o '/p/[^"]*' /tmp/a.html) <(grep -o '/p/[^"]*' /tmp/b.html) && echo SAME

Cache goes MISS → HIT (playlists: 60 s TTL; segments: 24 h):

    curl -sI http://127.0.0.1/p/<token>/master.m3u8 | grep -i x-cache-status
    curl -sI http://127.0.0.1/p/<token>/master.m3u8 | grep -i x-cache-status

Disk cache usage:

    du -sh /var/cache/nginx/mikaza

Player end-to-end: open `https://<host>/player/zoko?mal=21&ep=1&lang=sub`,
press play, seek ±10/±30/±120 s, then block a segment in devtools and confirm
the player switches source and resumes at the same timestamp.

## 7. Admin monitoring (collector)

One extra process owns SQLite and the dashboard; workers push snapshots over
loopback, so playback never waits on the collector. Add to `.env`:

    ADMIN_METRICS=1
    ADMIN_INGEST_TOKEN=<openssl rand -hex 32>
    ADMIN_TELEMETRY=1
    ADMIN_ALLOWED_IPS=<your public IP>
    ADMIN_EDGE_LOG=/var/log/nginx/mikaza-edge.json.log
    ADMIN_NGINX_STATUS=http://127.0.0.1:8099/nginx_status

`ADMIN_ALLOWED_IPS` is the only way in (empty = loopback only); everyone else
gets a plain 404. `ADMIN_SNAPSHOT_MS` defaults to 30000 (min 15000).

nginx already writes the JSON access log, proxies `/admin` and exposes
loopback-only `stub_status` (section 5 config). Refresh Cloudflare ranges once
and after any IP change:

    bash deploy/update-cloudflare-ips.sh
    nginx -t && systemctl reload nginx

Start the collector, then restart workers so they pick up `ADMIN_METRICS`:

    cp deploy/mikaza-admin.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now mikaza-admin
    systemctl restart 'mikaza-api@*'

Verify:

    curl -s http://127.0.0.1:5100/admin/api/health
    curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Real-IP: <your public IP>' http://127.0.0.1:5100/admin
    curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Real-IP: 203.0.113.9' http://127.0.0.1:5100/admin

Expect `200` for the allowed IP and `404` otherwise (the `X-Real-IP` header is
honoured because the curl socket is loopback). Then open `https://<host>/admin`
from an allowlisted network.

State lives in `data/admin/monitoring.db` (WAL, collector-only writes).
Retention is bounded by `ADMIN_DB_MAX_MB` (512 default) plus the `ADMIN_*_DAYS`
vars; pruning runs every 15 min. To reset stats, stop `mikaza-admin` and delete
`data/admin/`.

## Optional: global per-IP rate limit at nginx

    # in http{}:
    limit_req_zone $binary_remote_addr zone=embed_rl:20m rate=100r/s;
    # in location ~ ^/(embed|player)(/|$):
    limit_req zone=embed_rl burst=200 nodelay;

## Rollback

    systemctl stop 'mikaza-api@*'
    cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
    nginx -t && systemctl reload nginx

Every behavioral switch (`EMBED_MODE`, `SHARED_SEGMENT_TOKENS`,
`PREFETCH_UNDER_LOAD`, `RATE_LIMIT_ENABLED`) is an env var; worker restart is
the only step needed to flip one.
