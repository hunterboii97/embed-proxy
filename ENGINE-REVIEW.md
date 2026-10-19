# MikazaAPI Embed-Proxy — Senior Engineering Review

**Date:** 2026-10-18
**Reviewer:** Senior-level line-by-line review, code-only (no prior memory, no bias)
**Repo:** `yume-proxy-railway` @ `6df5ef3` (master), plus uncommitted `player.html` tweak
**Runtime reviewed:** Node.js (`app.js`, 6 systemd workers behind nginx + Cloudflare). The Go code (`main.go`, ~8k lines) is the legacy ancestor of this port and is not deployed — reviewed for context only.

---

## 1. Verdict & Score

| Category | Score | One-line reason |
|---|---|---|
| **Overall** | **7.5 / 10** | Genuinely well-built proxy engine; a handful of real bugs and one launch-blocking security item |
| Code quality | 8 / 10 | Clean, commented-where-it-matters, single-responsibility modules |
| Correctness | 7 / 10 | Two real engine flaws (waiter head-of-line blocking, 'best'=720p), nginx 206 risk unverified |
| Security | 6.5 / 10 | Reflected XSS, live SSRF-able download route, spoofable tier/IP signals — fixable, but public launch should wait |
| Engine design | 8 / 10 | Singleflight + creator-tee + buffered-prefix replay is above-average engineering |
| Scalability | 7 / 10 | App layer scales fine; the wall you'll hit is bandwidth, not the engine |
| Observability | 8.5 / 10 | Admin collector + 9-page dashboard is genuinely impressive for a solo project |
| Testing | 2 / 10 | No automated test suite exists anywhere in the repo |

**Bottom line:** this is a launchable product with roughly a week of hardening work. The engine will not be your bottleneck — bandwidth and upstream source bans will. Fix the items in §6 (launch blockers), then the plan in §8 gets you to 1–2k users/min.

---

## 2. Architecture Summary (what actually runs in prod)

```
Viewer → Cloudflare → nginx (least_conn, 300GB NVMe proxy_cache)
                       → 6× Node workers (127.0.0.1:5001–5006, systemd)
                         → upstream scrapers (zoko/kira/haiku/abyss/megaplay...)
```

- **Shell-first embed** (`src/routes/embeds.js`): static HTML shell is served instantly; `?resolve=1` JSON fetch does the real work under a **4 s deadline** with a **1.5 s hedge stagger** across providers and a 30 s/10 s negative memo on failures. This is the right design and rare in this space.
- **Segment engine** (`src/routes/proxy.js`, 1590 lines): per-worker LRU RAM cache (384 MB ts + 256 MB abyss), singleflight dedupe (`segFlight`), creator-tee (stream to first client while buffering), waiter fanout with buffered-prefix replay, lookahead prefetch. Solid.
- **Tokens** (`src/utils/crypto.js`): AES-256-GCM signed proxy tokens, deterministic IV via HMAC in shared mode so all viewers share a byte-identical cacheable URL. Clever and correct.
- **Abyss sources**: chunked MP4 with Sora tokens + AES-256-CTR first-64 KB decryption, fake-PNG (252-byte) TS prefix stripping.
- **Player** (`src/views/player/core.js`): Vidstack + hls.js fully vendored (import-map interception of jsdelivr URLs — no third-party requests), 720p-first start level, 30 s back buffer, fatal failover chain with resume, 15 s slow-start watchdog.
- **Admin sidecar** (`admin/`): separate collector on loopback :5100, node:sqlite WAL, nginx JSON log tailing, worker snapshots, player beacons, CIDR IP allowlist (fail-closed to loopback), timing-safe token compare. This is professional-grade.
- **Legacy Go** (`main.go`): not deployed. Keep for reference, don't maintain both.

---

## 3. Capacity — the honest answer to "how many users"

### 3.1 The engine itself is NOT the bottleneck

Every hot path is I/O: nginx reads a cached segment from NVMe and Node streams it. Node workers are async; 6 workers on an 8-core box comfortably sustain **tens of thousands of concurrent streams** at <30% CPU. Shells are static HTML; resolves happen once per new session (memoized, 4 s capped). The engine design (singleflight + tee + prefetch) means it degrades gracefully, not catastrophically.

### 3.2 Bandwidth is the wall

1080p anime H.264 web sources measure roughly **1.6–5.5 Mbps** depending on provider (megaplay's 1080p encodes are on the low end; other sources push ~5). Egress math:

| Concurrent viewers | @ 2 Mbps | @ 4 Mbps | @ 5.5 Mbps |
|---|---|---|---|
| 100 | 200 Mbps | 400 Mbps | 550 Mbps |
| 500 | 1 Gbps | 2 Gbps | 2.75 Gbps |
| 1,000 | 2 Gbps | 4 Gbps | 5.5 Gbps |
| 2,000 | 4 Gbps | 8 Gbps | 11 Gbps |
| 5,000 | 10 Gbps | 20 Gbps | 27.5 Gbps |

- **1 Gbps port** ≈ **180–500 concurrent viewers** (source-dependent).
- **10 Gbps port** ≈ **1,800–5,000 concurrent viewers**.

### 3.3 "1–2k users per minute" — what that actually means

Users/min is an **arrival rate**, not concurrency. If 1–2k users arrive per minute and watch ~20 min each, steady state is **20k–40k concurrent viewers** = **80–220 Gbps**. No single server does that — it's a CDN-scale product decision, not a tuning problem. Anyone who tells you "just optimize the engine" for that number is wrong.

The honest path:

1. **Cloudflare cache rules on `/p/*`** (edge cache) — popular episodes get 90%+ hit ratio; your VPS only serves first-watch misses. This is the single biggest lever, and it's free-plan territory.
2. **nginx NVMe cache** (already built) catches what CF misses and absorbs prefetch.
3. **Bunny pull zone** as an origin shield when CF caching stops being enough or bandwidth bills matter.

With CF caching in place, **1–2k users/min arriving is trivial for the app layer** (shells + resolves), and egress becomes a CDN bill, not a crash.

Request rate sanity check: HLS 4 s segments ≈ 15 req/min/viewer. 40k concurrent = 600k req/min = 10k req/s of segment traffic — all absorbed by CF/nginx caches; Node only sees the miss stream.

---

## 4. Bugs & Flaws (evidence-backed, file:line)

### CRITICAL — fix before public launch

**C1. Reflected XSS via Host header in docs page**
`src/views/docs.html:1292` → `const BASE_ORIGIN = "{{BASE_URL}}";`
`renderDocs()` (`src/views/player.js`) does a raw `replaceAll` with `baseURL` taken from `req.headers['host']` (attacker-controlled). A Host header like `evil";alert(1);//` breaks out of the JS string. Anyone pointing a scanner at your docs page with a poisoned Host gets script execution in your origin's context (and it reflects to whoever is served the poisoned cache entry).
**Fix:** validate Host against an allowlist (your domain) or JSON-escape the value (`scriptSafeJSON` already exists in `player.js` — use it).

**C2. Legacy download route: SSRF gap + unbounded ffmpeg, and it's LIVE**
- `.env:53` → `DOWNLOAD_ENABLED=true` on a public-facing config, while the code comments say "keep disabled on public deployments".
- `src/routes/download.js` feeds a scraper-derived `streamURL` to ffmpeg **without** an `isPrivateHost` guard (only `flixcloud.js` has one). A compromised/malicious upstream URL = SSRF into your network.
- Each download spawns an **ffmpeg process with no global concurrency cap**. 50 parallel downloads = 50 ffmpegs = box death.
**Fix:** disable publicly now; if you keep it, add `isPrivateHost()` on the streamURL, a global semaphore (e.g. 2–4 ffmpegs), and a size cap.

**C3. Synchronous event-loop blocking in the download path**
`src/utils/download-quota.js:16-17` → `Atomics.wait(...)` "sleep" is **synchronous**: it freezes the whole worker's event loop. `acquireLock` loops every 10 ms for up to 750 ms (`:30-48`), plus sync fs ops (`readFileSync`, `statSync`) per request. Under lock contention (two downloads from one IP), every request on that worker — including other viewers' video — stalls. `Atomics.wait` on a non-shared buffer also only works on the main thread, so this is a fragile trick.
**Fix:** make the lock async (`fs.promises` + `setTimeout`), or track quota in an in-process Map and don't persist at all.

### HIGH

**H1. Waiter head-of-line blocking in the segment fanout**
`src/routes/proxy.js:425` → `await fanToWaiters(buf)` runs **before** the creator's own write (`:427-429`). `fanToWaiters` (`:350-387`) awaits each slow waiter's drain. Result: **the slowest waiter throttles the creator and every other waiter** to its own pace — one viewer on a bad mobile link slows the segment for everyone else joining that flight. This is the one genuine engine defect.
**Fix:** decouple waiter writes from the creator loop — fire waiter writes without awaiting inside the creator's chunk loop (per-waiter bounded queue, drop/slow-path when a waiter's buffer exceeds a cap, e.g. 512 KB).

**H2. nginx 206/Range cache interaction for abyss is unverified**
`deploy/nginx.conf:100` → `proxy_cache_key "$scheme$request_method$host$request_uri"` — **no `$http_range`**. Abyss chunked requests carry `Range` headers and the app returns `206`. With `proxy_force_ranges on` (`:117`), nginx may strip/handle Range itself and cache a clamped partial body under the no-Range key → **cache poisoning of abyss segments** (wrong bytes served later). Behavior is nginx-version-dependent; I could not verify on a live box.
**Fix:** verify on the VPS (add `X-Cache-Status` debug header, request an abyss chunk with Range, check a subsequent miss/hit); if broken, either add `$http_range` to the key or normalize Range away for abyss routes.

**H3. Tier/priority spoofing**
`x-embed-tier` request header and `?prior=1` decide partner tier → priority prefetch. Any embedder (or bot) can send those and get partner treatment — at worst a prefetch-resource advantage, at best a way to skew telemetry/billing signals you may later build. Also `cf-connecting-ip` (`config.js:292-304`) is trusted first — fine behind Cloudflare, but **if your origin IP is ever reachable directly** (port scan, DNS leak), an attacker supplies the header and bypasses any IP-based limits/token binding.
**Fix:** keep origin behind CF-only firewall; treat tier as a soft hint with server-side caps, not a hard entitlement.

### MEDIUM

- **M1. `'best'` quality is actually 720p.** `src/utils/m3u8.js:123` `pickAtMost720` is used by the `'best'` branch (`:186-187`). UX lie + caps quality. Fix: make `best` the real highest, keep 720 as `auto`, add explicit `1080`/`2160` options.
- **M2. TLS verification globally disabled.** `src/utils/http.js:67` `rejectUnauthorized: false` for all upstream fetches → MITM-able streams. Pragmatic for flaky anime CDNs, but wrap it per-provider (allowlist of known-bad-cert hosts) instead of global.
- **M3. `engines: node >=18` vs `AbortSignal.any`** (Node 20+). Deploying on 18 crashes the request path. Bump engines to >=20 or replace.
- **M4. Legacy prefetch hard-gate.** `proxy.js:64` blocks all prefetch while `clientInflight > 0` — conservative, and it's per-worker while nginx `least_conn` spreads one viewer's segments across workers, so prefetch effectively never runs under any real load. The bounded alternative (`PREFETCH_UNDER_LOAD`, budget 16 + partner reserve 6) exists but is off by default in `.env`. Start-latency on cache-miss episodes will be noticeably higher under load. **Validate the bounded mode on the VPS in staging before enabling** — prefetch changes upstream load behavior.
- **M5. ~3.8 GB of RAM cache duplicated across 6 workers** (384+256 MB × 6). Not a bug, but a shared cache (Redis) or per-worker sizing would free RAM for page cache. Low priority.
- **M6. No automated tests anywhere.** 2/10. Token crypto, quota math, M3U8 pickers, and the abyss decryptors are pure functions — ideal unit-test targets. A single k6 script for segment throughput would have caught H1-class issues.

### LOW

- 5-min DNS memo (`http.js:10`) means upstream IP failover lags 5 min.
- Legacy `main.go` (8k lines) is dead weight in the repo — archive it to avoid the confusion of two engines.
- `/api/download` quota uses files on shared disk across workers — fine, but see C3.

---

## 5. Security Review Summary

| Area | Verdict |
|---|---|
| Token design (GCM, deterministic shared IV, expiry buckets) | Good — unusual care for this space |
| Admin panel (fail-closed CIDR allowlist, timing-safe compare, WAL) | Excellent |
| Player asset serving (whitelist map, no fs-per-request, versioned `?v=`) | Good |
| Player config injection (`scriptSafeJSON`) | Good |
| Docs page Host reflection | **Broken (C1)** |
| Download route SSRF + ffmpeg spawn | **Broken (C2)** |
| Upstream TLS | Disabled globally (M2) |
| IP/tier trust signals | Spoofable if origin reachable (H3) |
| Secret handling (`.env`, boot guard on PROXY_SECRET) | Good |

Net: a 6.5 that becomes an 8 after C1 + C2 + M2.

---

## 6. Launch-Blocking Checklist (do all before public)

1. **Fix C1** (escape `{{BASE_URL}}` in docs) — 10-minute change.
2. **Fix C2** — set `DOWNLOAD_ENABLED=false` publicly, or add SSRF guard + ffmpeg semaphore.
3. **Fix C3** — async quota lock (or remove the sync sleep).
4. **Verify H2 on the VPS** — abyss chunk + Range → check nginx cache behavior. Fix key if poisoned.
5. **CF-only firewall on origin** — otherwise H3 becomes "attacker is localhost".
6. **Decide M4** — validate `PREFETCH_UNDER_LOAD=1` in staging (watch upstream error rate + start latency), then set in prod `.env` if clean.
7. **Watch the admin dashboard during launch** — you built it, use it: worker CPU, cache hit ratio, slow-segment counts, alert on upstream failure spikes.
8. **One k6 smoke test** (100–500 virtual viewers hitting real segments through nginx) before announcing.

---

## 7. What's Genuinely Good (no bias cuts both ways)

- **Shell-first + 4 s resolve + 1.5 s hedge stagger** — instant paint, bounded provider race, negative memo. Best-in-class pattern.
- **Singleflight + creator-tee + buffered-prefix replay** — late joiners get bytes from buffer start, one upstream fetch serves N viewers. Correct and hard to get right.
- **Shared-segment deterministic token IV** — every viewer gets the byte-identical URL so nginx caches it once. Smart.
- **Vendored player with import-map interception** — zero third-party requests, patched-vs-cached solved with `?v=` content hashing.
- **Admin sidecar** — sampling, retention tiers, fail-closed auth. Most projects at this stage have nothing.
- **nginx `proxy_cache_lock` + `use_stale` + `background_update`** — the exact right config for cache stampedes.

---

## 8. The Plan: 1–2k users/min, max quality, instant load, no buffering

### Phase A — Code hardening (~3–5 days, £0)

1. **Fix H1** — decouple waiter fanout (per-waiter bounded queues, drop slow consumers). This is the "no buffering under load" fix.
2. **Fix C1/C2/C3/M3** as above.
3. **Quality honesty (M1)** — real `best`, plus `?quality=1080` embed option; add a 1080-first start level for partners while keeping 720-first default (instant-start and max-quality are in tension — default to fast, let embedders opt into max).
4. **Prefetch validation (M4)** — staging run of `PREFETCH_UNDER_LOAD=1`; measure start-latency p50/p95 on cache-miss episodes and upstream 4xx/5xx rate. Enable in prod only if both improve.
5. **Tests** — unit-test `crypto.js` (tokens, abyss decryptors), `m3u8.js` pickers, quota math; one k6 segment script; wire into a simple `npm test`.

### Phase B — Infra (this is where the scale actually comes from, ~1–2 days, £0)

1. **Cloudflare cache rules for `/p/*` (and `/player-assets/*`)** — edge-cache segments. This single change moves 90%+ of your bandwidth off the VPS. Do this before anything else.
2. **nginx tuning** — `proxy_cache_valid` for `.ts`/`.m4s` to hours (they're immutable tokens), confirm H2 fix, keep lock+stale.
3. **Monitor hit ratios** — CF analytics + nginx `X-Cache-Status`; target >90% on popular episodes.

### Phase C — CDN scale (when Phase B stops being enough)

- **Bunny pull zone** in front of the VPS as an origin shield; re-evaluate when sustained concurrency crosses ~2k (or when the CF free-plan caching limits bite).
- Multi-region only if your audience becomes global — not before.

### Quality/UX checklist for "instant load, smooth, max quality"

- Keep: 720-first default (fast start), 30 s back buffer, 4 s resolve cap, failover chain.
- Add: `<link rel="preconnect">` to the CF/segment host, `fetchpriority="high"` on the first segment, `?quality=1080` opt-in, and the H1 fix (slowest-waiter isolation).
- Consider: 6 s segments on your own encodes if you ever self-host originals (fewer requests, same quality).

---

## 9. "Where a mistake costs millions" — the real risk list, ranked

1. **Bandwidth bill, not code** — if segments aren't cached at CF, growth = linear egress cost. Phase B is the financial control.
2. **Upstream source bans** — scrapers hammering sources (prefetch doubles load) get your IPs blocked; then *every* embed breaks at once. Rate-limit resolves, respect sources, keep fallback chains healthy.
3. **Security incident on a live public embed** (C1/C2) — one reflected XSS or SSRF writeup kills an embed business's trust with site owners.
4. **Cache poisoning (H2)** — wrong bytes served to thousands of viewers = support storm + reputational damage.
5. **Legal/TOS exposure of embedded ads** — that's on the business side, but it's the one risk no code review can fix.

---

*Review conducted line-by-line over `app.js`, `src/routes/proxy.js` (1590 lines), `src/routes/embeds.js`, `src/routes/download.js`, all `src/utils/*`, `src/scrapers/*`, `config.js`, `src/views/*` (player + docs), `admin/*`, `deploy/*`, `.env`, and `main.go` (legacy).*
