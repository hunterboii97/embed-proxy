package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CDN Rule definition
type CDNRule struct {
	Matches func(host string) bool
	Referer string
	Origin  string
	SecSite string
}

type TokenPayload struct {
	URL       string `json:"url"`
	Ref       string `json:"ref,omitempty"`
	Exp       int64  `json:"exp"`
	IP        string `json:"ip,omitempty"`
	Key       string `json:"key,omitempty"`
	Cipher    string `json:"cipher,omitempty"`
	TotalSize int64  `json:"ts,omitempty"`
	PartSize  int64  `json:"ps,omitempty"`
	ChunkSize int64  `json:"cs,omitempty"`
	Md5ID     int    `json:"mid,omitempty"`
	ResID     int    `json:"rid,omitempty"`
	Domain    string `json:"dom,omitempty"`
}

var (
	proxySecretKey      []byte
	allowedOrigins      []string
	allowedEmbedDomains []string

	// Specialized HTTP Clients per service to prevent connection pool contention
	streamHttpClient    *http.Client // Dedicated for /p/ video chunk streaming (high-throughput, zero-timeout)
	megaplayHttpClient  *http.Client // Dedicated for MegaPlay scraping & endpoints
	animesaltHttpClient *http.Client // Dedicated for AnimeSalt scraping & mirrors
	zokoHttpClient      *http.Client // Dedicated for Zoko scraping & endpoints
	apiHttpClient       *http.Client // Dedicated for AniList GraphQL / AniZip / MAL metadata
	httpClient          *http.Client // Fallback general HTTP client

	// Caches for extracted stream URLs and playlists (RAM light: <20MB for thousands of episodes)
	megaplayStreamCache sync.Map
	zokoStreamCache     sync.Map

	// 64KB Buffer Pool for zero-copy high-throughput video segment streaming
	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 64*1024)
			return &b
		},
	}
	uriRegex = regexp.MustCompile(`URI="([^"]+)"`)
)

type MegaplayStreamCacheEntry struct {
	HLSFile   string
	Tracks    []SubtitleTrack
	ExpiresAt time.Time
}

type ZokoStreamCacheEntry struct {
	StreamFile string
	Tracks     []SubtitleTrack
	Skip       *ZokoSkip
	ExpiresAt  time.Time
}

var cdnRules = []CDNRule{
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".aniwatchtv.uk") || h == "aniwatchtv.uk" ||
				strings.HasSuffix(h, ".zokoanime.video") || h == "zokoanime.video"
		},
		Referer: "https://zokoanime.video/", Origin: "https://zokoanime.video", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".shiora.site") || h == "shiora.site" ||
				strings.HasSuffix(h, ".shiora.top") || h == "shiora.top" ||
				strings.HasSuffix(h, ".imgnex.top") || h == "imgnex.top" ||
				strings.HasSuffix(h, ".nexabloom.top") || h == "nexabloom.top" ||
				strings.HasSuffix(h, ".quavex.top") || h == "quavex.top" ||
				strings.HasSuffix(h, ".qeltrix.top") || h == "qeltrix.top" ||
				strings.HasSuffix(h, ".tiktokcdn.com") || h == "tiktokcdn.com" ||
				strings.HasSuffix(h, ".ipstatp.com") || h == "ipstatp.com"
		},
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".otakuu.se") || h == "otakuu.se" },
		Referer: "https://animex.one/", Origin: "https://animex.one", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return h == "vibeplayer.site" || strings.HasSuffix(h, ".vibeplayer.site") },
		Referer: "https://vibeplayer.site/", Origin: "https://vibeplayer.site", SecSite: "same-origin",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".mofl.pro") || h == "mofl.pro" },
		Referer: "https://kem.clvd.xyz/", Origin: "https://kem.clvd.xyz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".vidhosters.com") || h == "vidhosters.com" },
		Referer: "https://kem.clvd.xyz/", Origin: "https://kem.clvd.xyz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".burntburst45.store") || h == "burntburst45.store" },
		Referer: "", Origin: "https://play2.echovideo.ru", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".streamzone1.site") || h == "streamzone1.site" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".zencloudz.cc") || h == "zencloudz.cc" },
		Referer: "https://aniwave.at/", Origin: "https://aniwave.at", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".cinewave2.site") || h == "cinewave2.site" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".watching.onl") || h == "watching.onl" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".ibyteimg.com") || h == "ibyteimg.com" ||
				strings.HasSuffix(h, ".byteimg.com") || h == "byteimg.com" ||
				strings.HasSuffix(h, ".byteoversea.com") || h == "byteoversea.com" ||
				strings.HasSuffix(h, ".vivibebe.site") || h == "vivibebe.site"
		},
		Referer: "https://vivibebe.site/", Origin: "https://vivibebe.site", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".krussdomi.com") || h == "krussdomi.com" },
		Referer: "https://krussdomi.com/", Origin: "https://krussdomi.com", SecSite: "same-origin",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".owocdn.top") || h == "owocdn.top" },
		Referer: "https://kwik.cx/", Origin: "https://kwik.cx", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".kwik.cx") || h == "kwik.cx" },
		Referer: "https://kwik.cx/", Origin: "https://kwik.cx", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".anime-dunya.com") || h == "anime-dunya.com" },
		Referer: "https://anime-dunya.com/", Origin: "https://anime-dunya.com", SecSite: "same-origin",
	},
	{
		Matches: func(h string) bool { return strings.HasPrefix(h, "rrr.") },
		Referer: "https://megaup.nl/", Origin: "https://megaup.nl", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return h == "megaup.nl" || strings.HasSuffix(h, ".megaup.nl") || h == "hub26link.site" || strings.HasSuffix(h, ".hub26link.site")
		},
		Referer: "https://megaup.nl/", Origin: "https://megaup.nl", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".mewstream.buzz") || h == "mewstream.buzz" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".anidb.app") || h == "anidb.app" },
		Referer: "https://anidb.app/", Origin: "https://anidb.app", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".as-cdn26.top") || h == "as-cdn26.top" ||
				strings.HasSuffix(h, ".as-cdn28.top") || h == "as-cdn28.top" ||
				strings.HasSuffix(h, ".as-cdn.top") || h == "as-cdn.top" ||
				strings.Contains(h, "as-cdn") ||
				strings.HasSuffix(h, ".animesalt.cx") || h == "animesalt.cx"
		},
		Referer: "https://animesalt.cx/", Origin: "https://as-cdn26.top", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".sssrr.org") || h == "sssrr.org" ||
				strings.HasSuffix(h, ".abyssplayer.com") || h == "abyssplayer.com"
		},
		Referer: "https://abyssplayer.com/", Origin: "https://abyssplayer.com", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".vid-cdn.xyz") || h == "vid-cdn.xyz" },
		Referer: "https://anizone.to/", Origin: "https://anizone.to", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".24stream.xyz") || h == "24stream.xyz" },
		Referer: "https://animex.one/", Origin: "https://animex.one", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return h == "animegg.org" || strings.HasSuffix(h, ".animegg.org") },
		Referer: "https://animegg.org/", Origin: "https://animegg.org", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".uwucdn.top") || h == "uwucdn.top" },
		Referer: "https://kwik.cx/", Origin: "https://kwik.cx", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".lostproject.club") || h == "lostproject.club" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".nekostream.site") || h == "nekostream.site" },
		Referer: "https://megaplay.buzz/", Origin: "https://megaplay.buzz", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".neongambit.com") || h == "neongambit.com" },
		Referer: "https://2dhive.com/", Origin: "https://2dhive.com", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return h == "allanime.uns.bio" || strings.HasSuffix(h, ".allanime.uns.bio") || h == "allanime.day" || strings.HasSuffix(h, ".allanime.day")
		},
		Referer: "https://allanime.day/", Origin: "https://allanime.day", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return h == "ecotechshop.cfd" || strings.HasSuffix(h, ".ecotechshop.cfd") },
		Referer: "https://allanime.day/", Origin: "https://allanime.day", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return h == "playeng.animeapps.top" || strings.HasSuffix(h, ".playeng.animeapps.top")
		},
		Referer: "https://playeng.animeapps.top/", Origin: "https://playeng.animeapps.top", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".ninstream.com") || h == "ninstream.com" },
		Referer: "https://senshi.live/", Origin: "https://senshi.live", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".vivibebe.site") || h == "vivibebe.site" },
		Referer: "https://vivibebe.site/", Origin: "https://vivibebe.site", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".fast4speed.rsvp") || h == "fast4speed.rsvp" },
		Referer: "https://animex.one/", Origin: "https://animex.one", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".animeonsen.xyz") || h == "animeonsen.xyz" },
		Referer: "https://www.animeonsen.xyz/", Origin: "https://www.animeonsen.xyz", SecSite: "same-origin",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".heisenburger.workers.dev") || h == "heisenburger.workers.dev" || strings.HasSuffix(h, ".reanime.to") || h == "reanime.to"
		},
		Referer: "https://reanime.to/", Origin: "https://reanime.to", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".slopnet.site") || h == "slopnet.site" },
		Referer: "https://flixcloud.cc/", Origin: "https://flixcloud.cc", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".flixcloud.cc") || h == "flixcloud.cc" },
		Referer: "https://reanime.to/", Origin: "https://reanime.to", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".vibevibe.workers.dev") || h == "vibevibe.workers.dev" || strings.HasSuffix(h, ".anineko.to") || h == "anineko.to"
		},
		Referer: "https://anineko.to/", Origin: "https://anineko.to", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".senshi.live") || h == "senshi.live" },
		Referer: "https://senshi.live/", Origin: "https://senshi.live", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".anixtv.in") || h == "anixtv.in" },
		Referer: "https://anixtv.in/", Origin: "https://anixtv.in", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool {
			return strings.HasSuffix(h, ".animepahe.ru") || h == "animepahe.ru" || strings.HasSuffix(h, ".animepahe.com") || h == "animepahe.com"
		},
		Referer: "https://animepahe.ru/", Origin: "https://animepahe.ru", SecSite: "cross-site",
	},
	{
		Matches: func(h string) bool { return strings.HasSuffix(h, ".anidap.com") || h == "anidap.com" },
		Referer: "https://anidap.com/", Origin: "https://anidap.com", SecSite: "cross-site",
	},
}

func loadEnvFile(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"\'`)
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	}
}

func isPrivateHost(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" || h == "169.254.169.254" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func initConfig() {
	loadEnvFile(".env")
	loadEnvFile("apps/proxy/.env")
	loadEnvFile("backend/.env")
	loadEnvFile("/opt/yumezone/backend/.env")
	loadEnvFile("/opt/yumezone/apps/proxy/.env")
	loadEnvFile("../../.env")
	loadEnvFile("../web/.env")
	loadEnvFile("../../backend/.env")

	secret := os.Getenv("PROXY_SECRET")
	if secret == "" {
		secret = "e8b2f9a9416b9b32c69d82e1c9db8c56fa769f373cfd715dfc6b45a0d33b4991"
	}
	hash := sha256.Sum256([]byte(secret))
	proxySecretKey = hash[:]

	originsStr := os.Getenv("ALLOWED_ORIGINS")
	if originsStr == "" {
		originsStr = "yumezone.live,localhost,127.0.0.1"
	}
	for _, o := range strings.Split(originsStr, ",") {
		o = strings.TrimSpace(strings.ToLower(o))
		if o != "" {
			allowedOrigins = append(allowedOrigins, o)
		}
	}

	embedStr := os.Getenv("ALLOWED_EMBED_DOMAINS")
	if embedStr == "" {
		embedStr = os.Getenv("ALLOWED_ORIGINS")
	}
	if embedStr == "" {
		embedStr = "yumezone.live,*.yumezone.live,localhost,127.0.0.1"
	}
	for _, o := range strings.Split(embedStr, ",") {
		o = strings.TrimSpace(strings.ToLower(o))
		if o != "" {
			allowedEmbedDomains = append(allowedEmbedDomains, o)
		}
	}

	// 1. streamHttpClient: High-capacity pool for video streaming (/p/*) with NO timeout
	streamTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 90 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2500,
		MaxIdleConnsPerHost:   400,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 25 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}
	streamHttpClient = &http.Client{
		Transport: streamTransport,
		Timeout:   0, // No client timeout for streaming video segments!
	}

	// 2. megaplayHttpClient: Dedicated pool for MegaPlay scraping with fast-fail timeouts
	megaplayTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 45 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
	}
	megaplayHttpClient = &http.Client{
		Transport: megaplayTransport,
		Timeout:   10 * time.Second,
	}

	// 3. animesaltHttpClient: Dedicated pool for AnimeSalt scraping & mirrors
	animesaltTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 45 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
	}
	animesaltHttpClient = &http.Client{
		Transport: animesaltTransport,
		Timeout:   10 * time.Second,
	}

	// 4. zokoHttpClient: Dedicated pool for Zoko scraping
	zokoTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 45 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          300,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression:    true,
	}
	zokoHttpClient = &http.Client{
		Transport: zokoTransport,
		Timeout:   10 * time.Second,
	}

	// 5. apiHttpClient: Rapid metadata resolver (AniZip, AniList GraphQL, MAL)
	apiTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   4 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableCompression:    true,
	}
	apiHttpClient = &http.Client{
		Transport: apiTransport,
		Timeout:   5 * time.Second,
	}

	// 6. General fallback client
	httpClient = &http.Client{
		Transport: streamTransport,
		Timeout:   30 * time.Second,
	}
}

func isDomainAllowed(hostOrURL string, proxyHost string) bool {
	if hostOrURL == "" {
		return false
	}
	h := hostOrURL
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err == nil {
			h = u.Hostname()
		}
	} else {
		h = strings.Split(h, ":")[0]
	}
	h = strings.ToLower(strings.TrimSpace(h))

	cleanProxyHost := strings.ToLower(strings.TrimSpace(strings.Split(proxyHost, ":")[0]))
	if cleanProxyHost != "" && (h == cleanProxyHost || strings.HasSuffix(h, "."+cleanProxyHost)) {
		return true
	}

	for _, allowed := range allowedEmbedDomains {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if strings.Contains(allowed, "://") {
			u, err := url.Parse(allowed)
			if err == nil {
				allowed = u.Hostname()
			}
		} else {
			allowed = strings.Split(allowed, ":")[0]
		}

		if allowed == "" {
			continue
		}
		if allowed == "*" {
			return true
		}
		if (allowed == "localhost" || allowed == "127.0.0.1") && (h == "localhost" || h == "127.0.0.1") {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*.")
			if h == suffix || strings.HasSuffix(h, "."+suffix) {
				return true
			}
		}
		if h == allowed || strings.HasSuffix(h, "."+allowed) {
			return true
		}
	}
	return false
}

func isEmbedAllowed(r *http.Request) bool {
	secDest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	secMode := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")))
	ref := r.Header.Get("Referer")
	origin := r.Header.Get("Origin")

	// 1. Direct browser tab navigation: user opens URL directly in address bar to watch
	if (secDest == "document" || secDest == "") && (secMode == "navigate" || secMode == "") {
		if ref == "" || isDomainAllowed(ref, r.Host) {
			return true
		}
	}

	// 2. Iframe embed request: must have an authorized Referer or Origin
	if secDest == "iframe" || secMode == "nested-navigate" {
		if ref != "" && isDomainAllowed(ref, r.Host) {
			return true
		}
		if origin != "" && isDomainAllowed(origin, r.Host) {
			return true
		}
		// Unauthorized or stripped referer within an iframe
		return false
	}

	// 3. General request with Referer
	if ref != "" {
		return isDomainAllowed(ref, r.Host)
	}

	// Direct link access with no referer
	return true
}

func buildFrameAncestorsCSP(proxyHost string) string {
	ancestors := []string{"'self'"}
	if proxyHost != "" {
		h := strings.Split(proxyHost, ":")[0]
		ancestors = append(ancestors, fmt.Sprintf("https://%s", h), fmt.Sprintf("http://%s", h))
		if strings.Contains(proxyHost, ":") {
			ancestors = append(ancestors, fmt.Sprintf("http://%s", proxyHost), fmt.Sprintf("https://%s", proxyHost))
		}
	}

	for _, d := range allowedEmbedDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") {
			ancestors = append(ancestors, d)
			continue
		}
		if d == "localhost" || d == "127.0.0.1" {
			ancestors = append(ancestors, "http://localhost:*", "http://127.0.0.1:*", "http://localhost", "http://127.0.0.1")
			continue
		}
		if strings.HasPrefix(d, "*.") {
			ancestors = append(ancestors, fmt.Sprintf("https://%s", d), fmt.Sprintf("http://%s", d))
		} else {
			ancestors = append(ancestors, fmt.Sprintf("https://%s", d), fmt.Sprintf("https://*.%s", d), fmt.Sprintf("http://%s", d))
		}
	}

	seen := make(map[string]bool)
	var unique []string
	for _, a := range ancestors {
		if !seen[a] {
			seen[a] = true
			unique = append(unique, a)
		}
	}
	return strings.Join(unique, " ")
}

func decryptToken(tokenStr string) (*TokenPayload, error) {
	data, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(tokenStr)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 encoding: %w", err)
		}
	}

	if len(data) < 12 {
		return nil, fmt.Errorf("token too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(proxySecretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	var payload TokenPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	return &payload, nil
}

func encryptToken(payload *TokenPayload) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(proxySecretKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	combined := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(combined), nil
}

func encryptPlaylistResponse(text string, hexKey string) (string, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(text), nil)
	combined := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(combined), nil
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, X-Requested-With")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Type, Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")
}

func resolveAbsoluteURL(rel string, base string) string {
	if strings.HasPrefix(rel, "http://") || strings.HasPrefix(rel, "https://") {
		return rel
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return rel
	}
	relURL, err := url.Parse(rel)
	if err != nil {
		return rel
	}
	resolved := baseURL.ResolveReference(relURL)
	if relURL.RawQuery == "" && baseURL.RawQuery != "" && strings.Contains(strings.ToLower(relURL.Path), ".m3u8") {
		resolved.RawQuery = baseURL.RawQuery
	}
	return resolved.String()
}

func rewriteM3U8(text string, targetURL string, referer string, clientIP string, expires int64, playlistKey string, pkParam string, isEncrypted bool) string {
	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(text))
	// Allocate 1MB max line buffer for huge master playlists
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	pkQuery := ""
	if pkParam != "" {
		pkQuery = "?pk=" + url.QueryEscape(pkParam)
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, `URI="`) {
			newLine := uriRegex.ReplaceAllStringFunc(line, func(match string) string {
				submatches := uriRegex.FindStringSubmatch(match)
				if len(submatches) < 2 {
					return match
				}
				uri := submatches[1]
				abs := resolveAbsoluteURL(uri, targetURL)
				cleanPath := strings.ToLower(strings.Split(abs, "?")[0])
				isManifest := strings.Contains(cleanPath, ".m3u8") && !strings.HasSuffix(cleanPath, ".ts") && !strings.HasSuffix(cleanPath, ".key")

				tokPayload := &TokenPayload{
					URL: abs,
					Ref: referer,
					Exp: expires,
					IP:  clientIP,
				}
				if playlistKey != "" && isManifest {
					tokPayload.Key = playlistKey
				}
				tok, err := encryptToken(tokPayload)
				if err != nil {
					return match
				}

				encParam := ""
				if isManifest && isEncrypted {
					if pkQuery != "" {
						encParam = "&enc=1"
					} else {
						encParam = "?enc=1"
					}
				}
				return fmt.Sprintf(`URI="/p/%s%s%s"`, tok, pkQuery, encParam)
			})
			sb.WriteString(newLine)
			sb.WriteString("\n")
		} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			abs := resolveAbsoluteURL(trimmed, targetURL)
			cleanPath := strings.ToLower(strings.Split(abs, "?")[0])
			isManifest := strings.Contains(cleanPath, ".m3u8") && !strings.HasSuffix(cleanPath, ".ts") && !strings.HasSuffix(cleanPath, ".key")

			tokPayload := &TokenPayload{
				URL: abs,
				Ref: referer,
				Exp: expires,
				IP:  clientIP,
			}
			if playlistKey != "" && isManifest {
				tokPayload.Key = playlistKey
			}
			tok, err := encryptToken(tokPayload)
			if err != nil {
				sb.WriteString(line)
				sb.WriteString("\n")
				continue
			}

			encParam := ""
			if isManifest && isEncrypted {
				if pkQuery != "" {
					encParam = "&enc=1"
				} else {
					encParam = "?enc=1"
				}
			}
			sb.WriteString(fmt.Sprintf("/p/%s%s%s\n", tok, pkQuery, encParam))
		} else {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}
	return r.RemoteAddr
}

func genSoraToken(path string, size int64) string {
	sizeStr := strconv.FormatInt(size, 10)
	quirkBytes := make([]byte, len(sizeStr))
	for i := 0; i < len(sizeStr); i++ {
		quirkBytes[i] = sizeStr[i] - '0'
	}
	h := md5.Sum(quirkBytes)
	hexKey := hex.EncodeToString(h[:])
	key := []byte(hexKey)
	iv := key[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	ctr := cipher.NewCTR(block, iv)
	enc := make([]byte, len(path))
	ctr.XORKeyStream(enc, []byte(path))

	b1 := strings.TrimRight(base64.StdEncoding.EncodeToString(enc), "=")
	b2 := strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(b1)), "=")
	return b2
}

func streamAbyssCTR(w http.ResponseWriter, resp *http.Response, payload *TokenPayload, reqRange string) {
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Accept-Ranges", "bytes")
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}
	w.WriteHeader(resp.StatusCode)

	var rangeStart int64 = 0
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		parts := strings.Split(cr, " ")
		if len(parts) == 2 {
			rangePart := strings.Split(parts[1], "/")[0]
			startStr := strings.Split(rangePart, "-")[0]
			rangeStart, _ = strconv.ParseInt(startStr, 10, 64)
		}
	} else if reqRange != "" {
		trimmed := strings.TrimPrefix(reqRange, "bytes=")
		startStr := strings.Split(trimmed, "-")[0]
		rangeStart, _ = strconv.ParseInt(startStr, 10, 64)
	}

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	if rangeStart >= 65536 {
		io.CopyBuffer(w, resp.Body, *bufPtr)
		return
	}

	filename := payload.Key
	if filename == "" {
		uParts := strings.Split(strings.Split(payload.URL, "?")[0], "/")
		filename = uParts[len(uParts)-1]
	}
	h := md5.Sum([]byte(filename))
	hexKey := hex.EncodeToString(h[:])
	key := []byte(hexKey)
	iv := key[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		io.CopyBuffer(w, resp.Body, *bufPtr)
		return
	}
	ctr := cipher.NewCTR(block, iv)

	if rangeStart > 0 {
		discard := make([]byte, rangeStart)
		ctr.XORKeyStream(discard, discard)
	}

	encBytesRemaining := int64(65536 - rangeStart)
	buf := *bufPtr

	for encBytesRemaining > 0 {
		readSize := int64(len(buf))
		if readSize > encBytesRemaining {
			readSize = encBytesRemaining
		}
		n, rErr := resp.Body.Read(buf[:readSize])
		if n > 0 {
			ctr.XORKeyStream(buf[:n], buf[:n])
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return
			}
			encBytesRemaining -= int64(n)
		}
		if rErr != nil {
			return
		}
	}

	copyWithImmediateFlush(w, resp.Body, buf)
}

func copyWithImmediateFlush(w http.ResponseWriter, src io.Reader, buf []byte) error {
	flusher, hasFlusher := w.(http.Flusher)
	first := true
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if _, ew := w.Write(buf[:nr]); ew != nil {
				return ew
			}
			if first && hasFlusher {
				flusher.Flush()
				first = false
			}
		}
		if er != nil {
			if er != io.EOF {
				return er
			}
			break
		}
	}
	if hasFlusher {
		flusher.Flush()
	}
	return nil
}

func handleAbyssChunkedProxy(w http.ResponseWriter, r *http.Request, payload *TokenPayload) {
	totalSize := payload.TotalSize
	chunkSize := payload.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 5242880
	}

	rangeHeader := r.Header.Get("Range")
	var start int64 = 0
	var end int64 = totalSize - 1

	if rangeHeader != "" && strings.HasPrefix(rangeHeader, "bytes=") {
		spec := strings.TrimPrefix(rangeHeader, "bytes=")
		parts := strings.Split(spec, "-")
		if len(parts) == 2 {
			if pStart, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
				start = pStart
			}
			if parts[1] != "" {
				if pEnd, err := strconv.ParseInt(parts[1], 10, 64); err == nil && pEnd < totalSize {
					end = pEnd
				}
			}
		}
	}

	if start > end || start >= totalSize {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
		http.Error(w, "Requested range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := end - start + 1
	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.WriteHeader(http.StatusPartialContent)

	startChunkIdx := start / chunkSize
	endChunkIdx := end / chunkSize

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	for idx := startChunkIdx; idx <= endChunkIdx; idx++ {
		select {
		case <-r.Context().Done():
			return
		default:
		}

		cStartByte := idx * chunkSize
		cEndByte := cStartByte + chunkSize - 1
		if cEndByte >= totalSize {
			cEndByte = totalSize - 1
		}

		reqStartInChunk := int64(0)
		if start > cStartByte {
			reqStartInChunk = start - cStartByte
		}

		reqEndInChunk := cEndByte - cStartByte
		if end < cEndByte {
			reqEndInChunk = end - cStartByte
		}

		soraPath := fmt.Sprintf("/mp4/%d/%d/%d/%d/%d", payload.Md5ID, payload.ResID, totalSize, chunkSize, idx)
		soraToken := genSoraToken(soraPath, totalSize)
		chunkURL := fmt.Sprintf("https://%s/sora/%d/%s", payload.Domain, totalSize, soraToken)

		cReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, chunkURL, nil)
		if err != nil {
			return
		}
		cReq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", reqStartInChunk, reqEndInChunk))
		cReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		cReq.Header.Set("Referer", "https://abyssplayer.com/")
		cReq.Header.Set("Origin", "https://abyssplayer.com")
		cReq.Header.Set("Connection", "keep-alive")
		cReq.Header.Set("Sec-Fetch-Dest", "video")
		cReq.Header.Set("Sec-Fetch-Mode", "cors")
		cReq.Header.Set("Sec-Fetch-Site", "cross-site")

		cResp, err := streamHttpClient.Do(cReq)
		if err != nil {
			return
		}
		copyErr := copyWithImmediateFlush(w, cResp.Body, buf)
		cResp.Body.Close()
		if copyErr != nil {
			return
		}
	}
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/p/")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		http.Error(w, `{"error":"Missing proxy token"}`, http.StatusBadRequest)
		return
	}

	tokenStr := path
	if idx := strings.Index(tokenStr, "/"); idx != -1 {
		tokenStr = tokenStr[:idx]
	}

	payload, err := decryptToken(tokenStr)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Decryption failed: %s"}`, err.Error()), http.StatusForbidden)
		return
	}

	// Check token expiration
	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		http.Error(w, `{"error":"Token expired"}`, http.StatusGone)
		return
	}

	if payload.Cipher == "abyss-chunked" {
		handleAbyssChunkedProxy(w, r, payload)
		return
	}

	targetURL := payload.URL
	parsedTarget, err := url.Parse(targetURL)
	if err != nil || (parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https") {
		http.Error(w, `{"error":"Invalid target URL"}`, http.StatusBadRequest)
		return
	}

	targetHost := strings.ToLower(parsedTarget.Hostname())

	// SSRF Protection: Deny private / loopback IP accesses
	if isPrivateHost(targetHost) {
		http.Error(w, `{"error":"Access denied: target host is private or restricted"}`, http.StatusForbidden)
		return
	}

	effectiveReferer := payload.Ref
	effectiveOrigin := ""
	effectiveSecSite := "cross-site"

	// Match CDN rules
	matchedRule := false
	for _, rule := range cdnRules {
		if rule.Matches(targetHost) {
			matchedRule = true
			if effectiveReferer == "" {
				effectiveReferer = rule.Referer
			}
			effectiveOrigin = rule.Origin
			effectiveSecSite = rule.SecSite
			break
		}
	}

	if !matchedRule && effectiveReferer != "" {
		if refParsed, err := url.Parse(effectiveReferer); err == nil {
			effectiveOrigin = fmt.Sprintf("%s://%s", refParsed.Scheme, refParsed.Host)
		}
	}
	if effectiveReferer == "" {
		effectiveReferer = fmt.Sprintf("https://%s/", targetHost)
	}
	if effectiveOrigin == "" {
		effectiveOrigin = fmt.Sprintf("https://%s", targetHost)
	}

	// Build upstream request
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, `{"error":"Failed to build upstream request"}`, http.StatusInternalServerError)
		return
	}

	// Browser spoofing headers
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	if strings.Contains(targetHost, "flixcloud") || strings.Contains(targetHost, "slopnet") {
		ua = "Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/109.0.0.0 Mobile Safari/537.36"
	}
	upstreamReq.Header.Set("User-Agent", ua)
	upstreamReq.Header.Set("Accept", "*/*")
	upstreamReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if effectiveReferer != "" {
		upstreamReq.Header.Set("Referer", effectiveReferer)
	}
	if effectiveOrigin != "" {
		upstreamReq.Header.Set("Origin", effectiveOrigin)
	}
	if effectiveSecSite != "" {
		upstreamReq.Header.Set("Sec-Fetch-Dest", "empty")
		upstreamReq.Header.Set("Sec-Fetch-Mode", "cors")
		upstreamReq.Header.Set("Sec-Fetch-Site", effectiveSecSite)
	}

	// Pass Range header for video seeking
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
		upstreamReq.Header.Set("Range", rangeHdr)
	}

	clientIP := getClientIP(r)
	if clientIP != "" {
		upstreamReq.Header.Set("X-Forwarded-For", clientIP)
		upstreamReq.Header.Set("X-Real-IP", clientIP)
		upstreamReq.Header.Set("True-Client-IP", clientIP)
	}

	resp, err := streamHttpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Upstream fetch failed: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	cleanPath := strings.ToLower(strings.Split(targetURL, "?")[0])
	isM3U8 := strings.Contains(contentType, "mpegurl") || strings.Contains(contentType, "x-mpegurl") || strings.HasSuffix(cleanPath, ".m3u8")

	if isM3U8 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, `{"error":"Failed reading m3u8 playlist"}`, http.StatusBadGateway)
			return
		}

		pkParam := r.URL.Query().Get("pk")
		if pkParam != "" && !bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("#EXTM3U")) {
			keyBytes, err := base64.StdEncoding.DecodeString(pkParam)
			if err == nil && len(keyBytes) > 0 {
				klen := len(keyBytes)
				for i := range bodyBytes {
					bodyBytes[i] ^= keyBytes[i%klen]
				}
			}
		}

		isEncrypted := r.URL.Query().Get("enc") == "1"
		rewritten := rewriteM3U8(string(bodyBytes), targetURL, effectiveReferer, clientIP, payload.Exp, payload.Key, pkParam, isEncrypted)

		if payload.Key != "" && isEncrypted {
			encrypted, err := encryptPlaylistResponse(rewritten, payload.Key)
			if err == nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(resp.StatusCode)
				w.Write([]byte(encrypted))
				return
			}
		}

		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(resp.StatusCode)
		w.Write([]byte(rewritten))
		return
	}

	// For binary streams (TS chunks, MP4, VTT, SRT, AES Keys)
	isVTT := strings.HasSuffix(cleanPath, ".vtt") || strings.Contains(cleanPath, "/subtitles/")
	isSRT := strings.HasSuffix(cleanPath, ".srt")
	if isVTT {
		w.Header().Set("Content-Type", "text/vtt; charset=utf-8")
	} else if isSRT {
		w.Header().Set("Content-Type", "application/x-subrip")
	} else if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}

	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")

	if payload.Cipher == "abyss-ctr" {
		streamAbyssCTR(w, resp, payload, r.Header.Get("Range"))
		return
	}

	// Transparently strip fake PNG header (252 bytes) prepended by MegaPlay/TikTok/ByteDance CDNs
	if resp.StatusCode == http.StatusOK && !isVTT && !isSRT {
		leadBuf := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, leadBuf)
		if n >= 253 && bytes.HasPrefix(leadBuf, []byte("\x89PNG\r\n\x1a\n")) && leadBuf[252] == 0x47 {
			w.Header().Set("Content-Type", "video/mp2t")
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				if totalLen, parseErr := strconv.ParseInt(cl, 10, 64); parseErr == nil && totalLen >= 252 {
					w.Header().Set("Content-Length", strconv.FormatInt(totalLen-252, 10))
				}
			}
			w.WriteHeader(resp.StatusCode)
			w.Write(leadBuf[252:n])
			bufPtr := bufferPool.Get().(*[]byte)
			defer bufferPool.Put(bufPtr)
			_ = copyWithImmediateFlush(w, resp.Body, *bufPtr)
			return
		}

		// Ensure raw MPEG-TS video chunks (e.g. from MegaPlay CDNs disguised with .jpg or .html extensions) get correct MIME
		if n > 0 && leadBuf[0] == 0x47 {
			w.Header().Set("Content-Type", "video/mp2t")
		}

		if cl := resp.Header.Get("Content-Length"); cl != "" {
			w.Header().Set("Content-Length", cl)
		}
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			w.Header().Set("Content-Range", cr)
		}
		w.WriteHeader(resp.StatusCode)
		if n > 0 {
			w.Write(leadBuf[:n])
		}
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		_ = copyWithImmediateFlush(w, resp.Body, *bufPtr)
		return
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}

	w.WriteHeader(resp.StatusCode)

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	_ = copyWithImmediateFlush(w, resp.Body, *bufPtr)
}

// MegaPlay embed cache structure
type EmbedCacheEntry struct {
	HTML      string
	ExpiresAt time.Time
}

var (
	embedCache     sync.Map
	appMainJsRegex = regexp.MustCompile(`(?i)<script[^>]*src="[^"]*app\.main\.js[^"]*"[^>]*>\s*<\/script>`)
	trackerRegex   = regexp.MustCompile(`(?i)<script[^>]*src="[^"]*(statlytic\.net|cloudflareinsights)[^"]*"[^>]*>\s*<\/script>`)
	cfBeaconRegex  = regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?__cfRLUnblockHandlers[\s\S]*?<\/script>`)
)

var (
	malIdCache sync.Map
)

func resolveMalId(idNum int) int {
	if idNum <= 0 {
		return 0
	}
	if cached, ok := malIdCache.Load(idNum); ok {
		return cached.(int)
	}

	// Tier 1: AniZip API
	reqURL := fmt.Sprintf("https://api.ani.zip/mappings?anilist_id=%d", idNum)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := apiHttpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var data struct {
				Mappings struct {
					MalID int `json:"mal_id"`
				} `json:"mappings"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Mappings.MalID > 0 {
				resp.Body.Close()
				malIdCache.Store(idNum, data.Mappings.MalID)
				return data.Mappings.MalID
			}
			resp.Body.Close()
		}
	}

	// Tier 2: AniList GraphQL API
	graphqlQuery := `query ($id: Int) { Media (id: $id, type: ANIME) { idMal } }`
	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"query": graphqlQuery,
		"variables": map[string]interface{}{
			"id": idNum,
		},
	})
	gqlReq, err := http.NewRequest(http.MethodPost, "https://graphql.anilist.co", bytes.NewBuffer(bodyBytes))
	if err == nil {
		gqlReq.Header.Set("Content-Type", "application/json")
		gqlReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		resp, err := apiHttpClient.Do(gqlReq)
		if err == nil && resp.StatusCode == http.StatusOK {
			var gqlRes struct {
				Data struct {
					Media struct {
						IDMal int `json:"idMal"`
					} `json:"Media"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&gqlRes); err == nil && gqlRes.Data.Media.IDMal > 0 {
				resp.Body.Close()
				malIdCache.Store(idNum, gqlRes.Data.Media.IDMal)
				return gqlRes.Data.Media.IDMal
			}
			resp.Body.Close()
		}
	}

	// Tier 3: Kitsu API Fallback
	kitsuURL := fmt.Sprintf("https://kitsu.io/api/edge/anime?filter[anilist_id]=%d", idNum)
	kitsuReq, err := http.NewRequest(http.MethodGet, kitsuURL, nil)
	if err == nil {
		kitsuReq.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := apiHttpClient.Do(kitsuReq)
		if err == nil && resp.StatusCode == http.StatusOK {
			var kitsuData struct {
				Data []struct {
					Attributes struct {
						MalID int `json:"malId"`
					} `json:"attributes"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&kitsuData); err == nil && len(kitsuData.Data) > 0 {
				malId := kitsuData.Data[0].Attributes.MalID
				if malId > 0 {
					resp.Body.Close()
					malIdCache.Store(idNum, malId)
					return malId
				}
			}
			resp.Body.Close()
		}
	}

	return 0
}

func normalizeMegaplayPath(rawPath string) string {
	cleanPath := strings.TrimPrefix(rawPath, "/")
	parts := strings.Split(cleanPath, "/")
	if len(parts) == 0 || parts[0] == "" {
		return rawPath
	}

	prefix := ""
	idStr := ""
	ep := "1"
	lang := "sub"

	if parts[0] == "mal" || parts[0] == "ani" {
		prefix = parts[0]
		if len(parts) > 1 {
			idStr = parts[1]
		}
		if len(parts) > 2 {
			ep = parts[2]
		}
		if len(parts) > 3 {
			lang = parts[3]
		}
	} else {
		idStr = parts[0]
		if len(parts) > 1 {
			ep = parts[1]
		}
		if len(parts) > 2 {
			lang = parts[2]
		}
	}
	if lang != "dub" {
		lang = "sub"
	}

	idNum, err := strconv.Atoi(idStr)
	if err != nil || idNum <= 0 {
		return rawPath
	}

	// If prefix is mal and idNum is small (< 100000), check if it's already a valid MAL ID
	if prefix == "mal" && idNum < 100000 {
		return fmt.Sprintf("mal/%d/%s/%s", idNum, ep, lang)
	}

	// Try resolving idNum as AniList ID -> MAL ID
	malId := resolveMalId(idNum)
	if malId > 0 {
		return fmt.Sprintf("mal/%d/%s/%s", malId, ep, lang)
	}

	if prefix != "" {
		return fmt.Sprintf("%s/%d/%s/%s", prefix, idNum, ep, lang)
	}
	return fmt.Sprintf("mal/%d/%s/%s", idNum, ep, lang)
}

func fetchMegaplayStream(ctx context.Context, path string) (string, int, error) {
	upstreamURL := "https://megaplay.buzz/stream/" + strings.TrimPrefix(path, "/")
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return "", 500, err
	}

	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	upstreamReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	upstreamReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	upstreamReq.Header.Set("Referer", "https://anikoto.cz/")
	upstreamReq.Header.Set("Sec-Fetch-Dest", "iframe")
	upstreamReq.Header.Set("Sec-Fetch-Mode", "navigate")
	upstreamReq.Header.Set("Sec-Fetch-Site", "cross-site")

	resp, err := megaplayHttpClient.Do(upstreamReq)
	if err != nil {
		return "", 502, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 502, err
	}

	return string(bodyBytes), resp.StatusCode, nil
}

func isMegaplayValid(html string) bool {
	if html == "" {
		return false
	}
	if strings.Contains(html, "Oops! Something went wrong") ||
		strings.Contains(html, "Error Code: 404") ||
		strings.Contains(html, "<title>Error") ||
		strings.Contains(html, "Error - MegaPlay") {
		return false
	}
	return strings.Contains(html, "megaplay-player") ||
		strings.Contains(html, "newclient.min.js") ||
		strings.Contains(html, "mg3-player") ||
		strings.Contains(html, "e1-player") ||
		strings.Contains(html, "jwplayer") ||
		len(html) > 3800
}

var (
	megaplayAESKey = func() []byte {
		k := make([]byte, 32)
		copy(k, "i?LMTAx0Q6,:}50U")
		return k
	}()
	megaplayIV      = []byte("W0;27ToaUpl_P%'c")
	megaplayHMACKey = []byte("MpCdnT0k3n!9f2K#xQ7vL5mR8wN1pY4s")
	pathKeyRegex    = regexp.MustCompile(`(?i)/([a-f0-9]{32})/([a-f0-9]{32})/`)
)

func decryptMegaplayEnc(enc string) (string, error) {
	b64 := strings.ReplaceAll(strings.ReplaceAll(enc, "-", "+"), "_", "/")
	if pad := len(b64) % 4; pad != 0 {
		b64 += strings.Repeat("=", 4-pad)
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %w", err)
	}

	if len(cipherBytes) == 0 || len(cipherBytes)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext size: %d", len(cipherBytes))
	}

	block, err := aes.NewCipher(megaplayAESKey)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, megaplayIV)
	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)

	// PKCS7 unpad
	padLen := int(plain[len(plain)-1])
	if padLen <= 0 || padLen > aes.BlockSize {
		return "", fmt.Errorf("invalid PKCS7 padding: %d", padLen)
	}
	for i := len(plain) - padLen; i < len(plain); i++ {
		if plain[i] != byte(padLen) {
			return "", fmt.Errorf("bad PKCS7 byte")
		}
	}
	plain = plain[:len(plain)-padLen]

	var decRes struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(plain, &decRes); err != nil {
		return "", fmt.Errorf("json unmarshal error: %w", err)
	}

	fileURL := decRes.File
	if fileURL == "" {
		return "", fmt.Errorf("empty file URL in decrypted payload")
	}

	// Attach CDN token if path key matches and not already present
	if !strings.Contains(fileURL, "token=") {
		matches := pathKeyRegex.FindStringSubmatch(fileURL)
		if len(matches) >= 3 {
			pathKey := strings.ToLower(matches[1]) + "/" + strings.ToLower(matches[2])
			exp := time.Now().Unix() + 86400
			msg := fmt.Sprintf("%d|%s", exp, pathKey)
			h := hmac.New(sha256.New, megaplayHMACKey)
			h.Write([]byte(msg))
			sig := h.Sum(nil)
			token := base64.RawURLEncoding.EncodeToString([]byte(msg)) + "." + base64.RawURLEncoding.EncodeToString(sig)

			sep := "?"
			if strings.Contains(fileURL, "?") {
				sep = "&"
			}
			fileURL = fileURL + sep + "token=" + url.QueryEscape(token)
		}
	}

	return fileURL, nil
}

func parseMegaplaySourcesResponse(body []byte) (string, []SubtitleTrack, error) {
	var res struct {
		Sources json.RawMessage `json:"sources"`
		Enc     string          `json:"enc"`
		Tracks  []SubtitleTrack `json:"tracks"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", nil, err
	}

	var streamFile string

	// 1. Try decrypting enc first if present
	if res.Enc != "" {
		decryptedFile, err := decryptMegaplayEnc(res.Enc)
		if err == nil && decryptedFile != "" {
			streamFile = decryptedFile
		}
	}

	// 2. If no file from enc, try plain sources (object or array)
	if streamFile == "" && len(res.Sources) > 0 {
		var objSource struct {
			File string `json:"file"`
		}
		if err := json.Unmarshal(res.Sources, &objSource); err == nil && objSource.File != "" {
			streamFile = objSource.File
		} else {
			var arrSource []struct {
				File string `json:"file"`
			}
			if err := json.Unmarshal(res.Sources, &arrSource); err == nil && len(arrSource) > 0 && arrSource[0].File != "" {
				streamFile = arrSource[0].File
			}
		}
	}

	if streamFile == "" {
		return "", nil, fmt.Errorf("no stream file found in getSources response")
	}

	return streamFile, res.Tracks, nil
}

type SubtitleTrack struct {
	File    string `json:"file"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
	Default bool   `json:"default"`
}

func extractMegaplayHLS(ctx context.Context, targetPath string) (string, []SubtitleTrack, error) {
	upstreamURL := "https://megaplay.buzz/stream/" + targetPath
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return "", nil, err
	}
	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	upstreamReq.Header.Set("Referer", "https://anikoto.cz/")
	upstreamReq.Header.Set("Sec-Fetch-Dest", "iframe")
	upstreamReq.Header.Set("Sec-Fetch-Mode", "navigate")

	resp, err := megaplayHttpClient.Do(upstreamReq)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	html := string(bodyBytes)

	cidRegex := regexp.MustCompile(`cid\s*:\s*['"]([^'"]+)['"]`)
	ciduRegex := regexp.MustCompile(`cidu\s*:\s*['"]([^'"]+)['"]`)
	dataIdRegex := regexp.MustCompile(`data-id\s*=\s*["']([^"']+)["']`)

	cidMatch := cidRegex.FindStringSubmatch(html)
	ciduMatch := ciduRegex.FindStringSubmatch(html)
	dataIdMatch := dataIdRegex.FindStringSubmatch(html)

	if len(cidMatch) < 2 || len(ciduMatch) < 2 || len(dataIdMatch) < 2 {
		return "", nil, fmt.Errorf("could not extract player IDs from HTML")
	}

	cid := cidMatch[1]
	cidu := ciduMatch[1]
	dataId := dataIdMatch[1]

	// 1. Try getSourcesNew (new MegaPlay client endpoint)
	apiURL := fmt.Sprintf("https://megaplay.buzz/stream/getSourcesNew?id=%s&cid=%s&cidu=%s", dataId, cid, cidu)
	apiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err == nil {
		apiReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		apiReq.Header.Set("Referer", "https://megaplay.buzz/")
		apiReq.Header.Set("X-Requested-With", "XMLHttpRequest")

		apiResp, err := megaplayHttpClient.Do(apiReq)
		if err == nil {
			if apiResp.StatusCode == http.StatusOK {
				bodyBytes, err := io.ReadAll(apiResp.Body)
				apiResp.Body.Close()
				if err == nil {
					if file, tracks, parseErr := parseMegaplaySourcesResponse(bodyBytes); parseErr == nil && file != "" {
						return file, tracks, nil
					}
				}
			} else {
				apiResp.Body.Close()
			}
		}
	}

	// 2. Fallback to legacy getSources
	legacyURL := fmt.Sprintf("https://megaplay.buzz/stream/getSources?id=%s&cid=%s&cidu=%s", dataId, cid, cidu)
	legacyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, legacyURL, nil)
	if err != nil {
		return "", nil, err
	}
	legacyReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	legacyReq.Header.Set("Referer", "https://megaplay.buzz/")
	legacyReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	legacyResp, err := megaplayHttpClient.Do(legacyReq)
	if err != nil {
		return "", nil, err
	}
	defer legacyResp.Body.Close()

	if legacyResp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("getSources status %d", legacyResp.StatusCode)
	}

	bodyBytes, err = io.ReadAll(legacyResp.Body)
	if err != nil {
		return "", nil, err
	}

	return parseMegaplaySourcesResponse(bodyBytes)
}

type AnimeSaltAudioOption struct {
	Label    string `json:"label"`
	Language string `json:"language"`
	LangCode string `json:"langCode"`
}

func renderCleanArtplayer(streamURL string, subtitleTracks []SubtitleTrack, preferredLang string, episodeKey string, audioOptions ...AnimeSaltAudioOption) string {
	tracksJSON, _ := json.Marshal(subtitleTracks)
	if preferredLang == "" {
		preferredLang = "sub"
	}
	var auds []AnimeSaltAudioOption
	if len(audioOptions) > 0 {
		auds = audioOptions
	}
	audsJSON, _ := json.Marshal(auds)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>YumeZone Player</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; user-select: none; -webkit-user-select: none; }
        html, body {
            width: 100%%;
            height: 100%%;
            margin: 0;
            padding: 0;
            background: #000000;
            overflow: hidden;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            -webkit-font-smoothing: antialiased;
        }
        #yume-player-container {
            width: 100%%;
            height: 100%%;
            position: relative;
            background: #000000;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        video {
            width: 100%%;
            height: 100%%;
            object-fit: contain;
            background: #000000;
            outline: none;
        }

        /* Fullscreen Landscape Enforcement */
        :fullscreen video, :-webkit-full-screen video {
            width: 100vw !important;
            height: 100vh !important;
            object-fit: contain !important;
        }

        /* Dark Premium Center Play Button */
        .yume-center-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%%;
            height: 100%%;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 40;
            background: rgba(0, 0, 0, 0.4);
            cursor: pointer;
            transition: opacity 0.25s ease;
        }
        .yume-center-overlay.hidden {
            opacity: 0;
            pointer-events: none;
        }
        #yume-start-screen {
            background: #000000 !important;
            z-index: 100 !important;
        }
        .yume-big-play-btn {
            width: 78px;
            height: 78px;
            background: rgba(14, 14, 18, 0.78);
            border-radius: 50%%;
            border: 1.5px solid rgba(255, 255, 255, 0.25);
            box-shadow: 0 14px 40px rgba(0, 0, 0, 0.9);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1), background 0.2s ease, border-color 0.2s ease;
        }
        .yume-center-overlay:hover .yume-big-play-btn {
            transform: scale(1.12);
            background: rgba(22, 22, 28, 0.9);
            border-color: rgba(255, 255, 255, 0.45);
        }
        .yume-big-play-btn svg {
            width: 32px;
            height: 32px;
            fill: #ffffff;
            margin-left: 4px;
        }

        /* Top Bar Floating Time (Mobile) */
        #yume-top-bar {
            position: absolute;
            top: 14px;
            left: 14px;
            display: none;
            z-index: 45;
            pointer-events: none;
        }
        .yume-time-badge {
            background: rgba(13, 13, 16, 0.75);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            padding: 4px 10px;
            font-size: 12px;
            font-weight: 600;
            color: #ffffff;
            letter-spacing: 0.5px;
        }

        /* Anime Subtitle Layer */
        #yume-subtitle-display {
            position: absolute;
            bottom: 68px;
            left: 5%%;
            right: 5%%;
            text-align: center;
            pointer-events: none;
            z-index: 35;
            transition: bottom 0.25s ease;
        }
        #yume-player-container.controls-hidden #yume-subtitle-display {
            bottom: 24px;
        }
        .yume-sub-text {
            display: inline-block;
            font-family: 'Outfit', sans-serif;
            font-weight: 600;
            font-size: clamp(20px, 3.2vw, 36px);
            color: #ffffff;
            text-shadow: -2px -2px 0 #000, 2px -2px 0 #000, -2px 2px 0 #000, 2px 2px 0 #000, 0 3px 6px rgba(0,0,0,0.95);
            line-height: 1.35;
            padding: 2px 10px;
        }
        :fullscreen .yume-sub-text {
            font-size: clamp(24px, 4vw, 48px);
        }

        /* Flash Effect on Screenshot */
        #yume-flash {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%%;
            height: 100%%;
            background: #ffffff;
            opacity: 0;
            pointer-events: none;
            z-index: 2000;
            transition: opacity 0.15s ease-out;
        }
        #yume-flash.flash {
            opacity: 0.8;
            transition: none;
        }

        /* Bottom Controls Bar */
        #yume-controls-bar {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            background: linear-gradient(to top, rgba(0, 0, 0, 0.94) 0%%, rgba(0, 0, 0, 0.6) 60%%, transparent 100%%);
            padding: 24px 16px 12px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            z-index: 50;
            transition: opacity 0.25s ease, transform 0.25s ease;
        }
        #yume-player-container.controls-hidden #yume-controls-bar {
            opacity: 0;
            pointer-events: none;
            transform: translateY(10px);
        }

        /* Progress Timeline Bar */
        .yume-progress-container {
            position: relative;
            width: 100%%;
            height: 16px;
            display: flex;
            align-items: center;
            cursor: pointer;
            touch-action: none;
        }
        .yume-progress-bg {
            position: relative;
            width: 100%%;
            height: 4px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 2px;
            overflow: hidden;
            transition: height 0.15s ease;
        }
        .yume-progress-container:hover .yume-progress-bg,
        .yume-progress-container.scrubbing .yume-progress-bg {
            height: 6px;
        }
        .yume-progress-buffered {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%%;
            width: 0%%;
            background: rgba(255, 255, 255, 0.4);
            border-radius: 2px;
            pointer-events: none;
        }
        .yume-progress-played {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%%;
            width: 0%%;
            background: #ffffff;
            border-radius: 2px;
            pointer-events: none;
            box-shadow: 0 0 10px rgba(255, 255, 255, 0.8);
        }
        .yume-progress-thumb {
            position: absolute;
            left: 0%%;
            width: 14px;
            height: 14px;
            border-radius: 50%%;
            background: #ffffff;
            transform: translate(-50%%, 0) scale(0);
            transition: transform 0.15s cubic-bezier(0.34, 1.56, 0.64, 1);
            pointer-events: none;
            box-shadow: 0 0 8px rgba(0, 0, 0, 0.8);
        }
        .yume-progress-container:hover .yume-progress-thumb,
        .yume-progress-container.scrubbing .yume-progress-thumb {
            transform: translate(-50%%, 0) scale(1);
        }

        /* Hover Time Tooltip */
        #yume-hover-time {
            position: absolute;
            bottom: 22px;
            left: 0%%;
            transform: translateX(-50%%);
            background: rgba(13, 13, 16, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.18);
            border-radius: 6px;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 600;
            color: #ffffff;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.15s ease;
            white-space: nowrap;
        }
        .yume-progress-container:hover #yume-hover-time {
            opacity: 1;
        }

        /* Controls Row */
        .yume-controls-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }
        .yume-controls-left, .yume-controls-right {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Control Buttons */
        .yume-btn {
            background: transparent;
            border: none;
            color: #e4e4e7;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 6px;
            border-radius: 8px;
            outline: none;
            transition: color 0.15s ease, transform 0.15s ease, background 0.15s ease;
        }
        .yume-btn:hover {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.1);
            transform: scale(1.08);
        }
        .yume-btn:active {
            transform: scale(0.94);
        }
        #yume-btn-cc.active {
            color: #818cf8;
            background: rgba(99, 102, 241, 0.18);
        }
        #yume-btn-cc.active svg {
            stroke: #a5b4fc;
            filter: drop-shadow(0 0 6px rgba(99, 102, 241, 0.8));
        }

        /* Modern Touch-Friendly Volume Slider */
        .yume-vol-wrap {
            display: flex;
            align-items: center;
            position: relative;
        }
        .yume-vol-slider-wrap {
            width: 0;
            overflow: hidden;
            transition: width 0.25s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.2s ease;
            opacity: 0;
            display: flex;
            align-items: center;
            padding: 8px 0;
        }
        .yume-vol-wrap:hover .yume-vol-slider-wrap,
        .yume-vol-slider-wrap:focus-within,
        .yume-vol-wrap.active .yume-vol-slider-wrap {
            width: 80px;
            opacity: 1;
        }
        .yume-vol-slider {
            -webkit-appearance: none;
            appearance: none;
            width: 70px;
            height: 6px;
            background: linear-gradient(to right, #ffffff 0%%, #ffffff var(--vol-pct, 100%%), rgba(255, 255, 255, 0.3) var(--vol-pct, 100%%), rgba(255, 255, 255, 0.3) 100%%);
            border-radius: 3px;
            outline: none;
            cursor: pointer;
            touch-action: none;
        }
        .yume-vol-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 14px;
            height: 14px;
            border-radius: 50%%;
            background: #ffffff;
            box-shadow: 0 0 6px rgba(0,0,0,0.7);
            cursor: pointer;
        }
        .yume-vol-slider::-moz-range-thumb {
            width: 14px;
            height: 14px;
            border-radius: 50%%;
            background: #ffffff;
            border: none;
            box-shadow: 0 0 6px rgba(0,0,0,0.7);
            cursor: pointer;
        }

        /* Time Text */
        .yume-time-text {
            font-family: 'Outfit', sans-serif;
            font-size: 13px;
            font-weight: 600;
            color: #e4e4e7;
            letter-spacing: 0.5px;
            margin-left: 2px;
        }

        /* Floating Settings Popover Elevated Above Timeline */
        #yume-settings-popover {
            position: absolute;
            bottom: 70px;
            right: 16px;
            width: 230px;
            max-height: 280px;
            background: rgba(13, 13, 16, 0.96);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 14px;
            box-shadow: 0 14px 44px rgba(0, 0, 0, 0.9);
            z-index: 1000;
            overflow: hidden;
            color: #ffffff;
            font-family: 'Outfit', sans-serif;
            transition: opacity 0.18s ease, transform 0.18s ease;
        }
        #yume-settings-popover.hidden {
            opacity: 0;
            pointer-events: none;
            transform: translateY(8px) scale(0.96);
        }
        .yume-menu-view {
            padding: 6px 0;
            max-height: 280px;
            overflow-y: auto;
        }
        .yume-menu-view.hidden {
            display: none;
        }
        .yume-menu-header {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            cursor: pointer;
            font-size: 13px;
            font-weight: 700;
            color: #e4e4e7;
        }
        .yume-menu-header:hover {
            background: rgba(255, 255, 255, 0.08);
        }
        .yume-menu-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            font-size: 13px;
            font-weight: 500;
            color: #e4e4e7;
            cursor: pointer;
            transition: background 0.15s ease;
        }
        .yume-menu-item:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }
        .yume-item-val {
            display: flex;
            align-items: center;
            gap: 4px;
            font-size: 12px;
            color: #a1a1aa;
            font-weight: 600;
        }
        .yume-option {
            padding: 9px 14px;
            font-size: 13px;
            font-weight: 500;
            color: #a1a1aa;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .yume-option:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
        }
        .yume-option.active {
            color: #ffffff !important;
            font-weight: 700 !important;
            background: rgba(255, 255, 255, 0.08);
        }

        /* Volume Boost Sub-Setting UI - Pure B&W Theme */
        .yume-boost-panel {
            padding: 14px 16px 18px 16px;
        }
        .yume-boost-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }
        .yume-boost-title {
            font-size: 13px;
            font-weight: 500;
            color: #a1a1aa;
            letter-spacing: 0.2px;
        }
        .yume-boost-val {
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 0.3px;
            font-variant-numeric: tabular-nums;
        }
        .yume-boost-slider-wrap {
            width: 100%%;
            display: flex;
            align-items: center;
            position: relative;
            padding: 4px 0;
        }
        .yume-boost-slider {
            -webkit-appearance: none;
            appearance: none;
            width: 100%%;
            height: 6px;
            background: linear-gradient(to right, #ffffff 0%%, #ffffff var(--boost-pct, 0%%), rgba(255, 255, 255, 0.3) var(--boost-pct, 0%%), rgba(255, 255, 255, 0.3) 100%%);
            border-radius: 3px;
            outline: none;
            cursor: pointer;
            margin: 0;
            padding: 0;
            touch-action: none;
        }
        .yume-boost-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 14px;
            height: 14px;
            border-radius: 50%%;
            background: #ffffff;
            box-shadow: 0 0 6px rgba(0, 0, 0, 0.7);
            cursor: pointer;
        }
        .yume-boost-slider::-moz-range-thumb {
            width: 14px;
            height: 14px;
            border-radius: 50%%;
            background: #ffffff;
            border: none;
            box-shadow: 0 0 6px rgba(0, 0, 0, 0.7);
            cursor: pointer;
        }
        .yume-boost-ticks {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 12px;
            padding: 0 2px;
            user-select: none;
        }
        .yume-boost-tick {
            font-size: 12px;
            font-weight: 500;
            color: #a1a1aa;
            cursor: pointer;
            padding: 3px 8px;
            border-radius: 6px;
            transition: all 0.15s ease;
        }
        .yume-boost-tick:hover {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.1);
        }
        .yume-boost-tick.active {
            color: #ffffff !important;
            font-weight: 700 !important;
            background: rgba(255, 255, 255, 0.12);
        }

        /* Mobile Responsiveness */
        @media (max-width: 640px) {
            #yume-top-bar {
                display: block;
            }
            .yume-time-text {
                display: none;
            }
            .yume-sub-text {
                font-size: clamp(16px, 4.5vw, 24px);
            }
            #yume-controls-bar {
                padding: 6px 10px 10px 10px;
            }
            .yume-big-play-btn {
                width: 64px;
                height: 64px;
            }
            .yume-big-play-btn svg {
                width: 26px;
                height: 26px;
            }
            .yume-vol-wrap:hover .yume-vol-slider-wrap,
            .yume-vol-wrap.active .yume-vol-slider-wrap {
                width: 65px;
            }
            .yume-vol-slider {
                width: 58px;
            }
            #yume-settings-popover {
                right: 8px;
                bottom: 64px;
                width: 210px;
            }
        }
    </style>
</head>
<body>
    <div id="yume-player-container">
        <!-- Main HTML5 Video Element -->
        <video id="yume-video" playsinline preload="auto"></video>

        <!-- Flash Effect for Screenshot -->
        <div id="yume-flash"></div>

        <!-- Floating Top Time for Mobile -->
        <div id="yume-top-bar">
            <span class="yume-time-badge" id="yume-top-time">00:00 / 00:00</span>
        </div>

        <!-- Bespoke Anime Subtitles Display -->
        <div id="yume-subtitle-display">
            <span class="yume-sub-text" id="yume-sub-content"></span>
        </div>

        <!-- Initial Start Screen (Clean OLED click to unmute & play) -->
        <div id="yume-start-screen" class="yume-center-overlay">
            <div class="yume-big-play-btn">
                <svg viewBox="0 0 24 24"><path d="M8 5.14v13.72a1 1 0 0 0 1.5.86l11-6.86a1 1 0 0 0 0-1.72l-11-6.86a1 1 0 0 0-1.5.86z"/></svg>
            </div>
        </div>

        <!-- Pause Center Overlay -->
        <div id="yume-pause-overlay" class="yume-center-overlay hidden">
            <div class="yume-big-play-btn">
                <svg viewBox="0 0 24 24"><path d="M8 5.14v13.72a1 1 0 0 0 1.5.86l11-6.86a1 1 0 0 0 0-1.72l-11-6.86a1 1 0 0 0-1.5.86z"/></svg>
            </div>
        </div>

        <!-- Floating Settings Popover Elevated Above Timeline -->
        <div id="yume-settings-popover" class="hidden">
            <div id="yume-menu-main" class="yume-menu-view">
                <div class="yume-menu-item" id="yume-row-audio" style="display: none;">
                    <span>Audio Track</span>
                    <span class="yume-item-val" id="yume-val-audio">Default <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>
                </div>
                <div class="yume-menu-item" id="yume-row-quality">
                    <span>Quality</span>
                    <span class="yume-item-val" id="yume-val-quality">Auto <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>
                </div>
                <div class="yume-menu-item" id="yume-row-subtitles">
                    <span>Subtitles</span>
                    <span class="yume-item-val" id="yume-val-subtitles">Off <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>
                </div>
                <div class="yume-menu-item" id="yume-row-speed">
                    <span>Speed</span>
                    <span class="yume-item-val" id="yume-val-speed">Normal <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>
                </div>
                <div class="yume-menu-item" id="yume-row-boost">
                    <span>Volume Boost</span>
                    <span class="yume-item-val" id="yume-val-boost">100%% <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg></span>
                </div>
            </div>

            <div id="yume-menu-audio" class="yume-menu-view hidden">
                <div class="yume-menu-header" id="yume-back-audio">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Audio Track</span>
                </div>
                <div id="yume-audio-list"></div>
            </div>

            <div id="yume-menu-quality" class="yume-menu-view hidden">
                <div class="yume-menu-header" id="yume-back-quality">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Quality</span>
                </div>
                <div id="yume-quality-list"></div>
            </div>

            <div id="yume-menu-subtitles" class="yume-menu-view hidden">
                <div class="yume-menu-header" id="yume-back-subtitles">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Subtitles</span>
                </div>
                <div id="yume-subtitles-list"></div>
            </div>

            <div id="yume-menu-speed" class="yume-menu-view hidden">
                <div class="yume-menu-header" id="yume-back-speed">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Speed</span>
                </div>
                <div id="yume-speed-list"></div>
            </div>

            <div id="yume-menu-boost" class="yume-menu-view hidden">
                <div class="yume-menu-header" id="yume-back-boost">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="15 18 9 12 15 6"></polyline></svg>
                    <span>Volume Boost</span>
                </div>
                <div class="yume-boost-panel">
                    <div class="yume-boost-header">
                        <span class="yume-boost-title">Level</span>
                        <span class="yume-boost-val" id="yume-boost-val-text">100%%</span>
                    </div>
                    <div class="yume-boost-slider-wrap">
                        <input type="range" class="yume-boost-slider" id="yume-boost-range" min="100" max="200" step="1" value="100">
                    </div>
                    <div class="yume-boost-ticks">
                        <span class="yume-boost-tick active" data-val="100">100%%</span>
                        <span class="yume-boost-tick" data-val="150">150%%</span>
                        <span class="yume-boost-tick" data-val="200">200%%</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Controls Bar -->
        <div id="yume-controls-bar">
            <!-- Progress Timeline -->
            <div class="yume-progress-container" id="yume-progress-wrap">
                <div id="yume-hover-time">00:00</div>
                <div class="yume-progress-bg">
                    <div class="yume-progress-buffered" id="yume-prog-buf"></div>
                    <div class="yume-progress-played" id="yume-prog-play"></div>
                </div>
                <div class="yume-progress-thumb" id="yume-prog-thumb"></div>
            </div>

            <!-- Controls Row -->
            <div class="yume-controls-row">
                <div class="yume-controls-left">
                    <!-- Play / Pause -->
                    <button class="yume-btn" id="yume-btn-play" title="Play / Pause">
                        <svg id="yume-icon-play" width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5.14v13.72a1 1 0 0 0 1.5.86l11-6.86a1 1 0 0 0 0-1.72l-11-6.86a1 1 0 0 0-1.5.86z"/></svg>
                        <svg id="yume-icon-pause" width="22" height="22" viewBox="0 0 24 24" fill="currentColor" style="display:none;"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>
                    </button>

                    <!-- Rewind -->
                    <button class="yume-btn" id="yume-btn-rewind" title="Rewind 10s">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                            <path d="M12.5 3a9 9 0 1 0 7.8 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                            <path d="M12.5 1v4l4-2z" fill="currentColor"/>
                            <text x="12" y="15.5" font-size="7.5" font-weight="700" fill="currentColor" text-anchor="middle" font-family="Outfit, sans-serif">10</text>
                        </svg>
                    </button>

                    <!-- Forward -->
                    <button class="yume-btn" id="yume-btn-forward" title="Forward 10s">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                            <path d="M11.5 3a9 9 0 1 1-7.8 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                            <path d="M11.5 1v4l-4-2z" fill="currentColor"/>
                            <text x="12" y="15.5" font-size="7.5" font-weight="700" fill="currentColor" text-anchor="middle" font-family="Outfit, sans-serif">10</text>
                        </svg>
                    </button>

                    <!-- Volume -->
                    <div class="yume-vol-wrap" id="yume-vol-wrap-box">
                        <button class="yume-btn" id="yume-btn-vol" title="Mute / Unmute">
                            <svg id="yume-icon-vol-high" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>
                            <svg id="yume-icon-vol-mute" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none;"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg>
                        </button>
                        <div class="yume-vol-slider-wrap">
                            <input type="range" class="yume-vol-slider" id="yume-vol-range" min="0" max="1" step="0.05" value="1">
                        </div>
                    </div>

                    <!-- Time Text -->
                    <span class="yume-time-text" id="yume-time-display">00:00 / 00:00</span>
                </div>

                <div class="yume-controls-right">
                    <!-- CC Subtitle Button -->
                    <button class="yume-btn" id="yume-btn-cc" title="Toggle Subtitles (CC)">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M10 10a2 2 0 0 0-2 2v0a2 2 0 0 0 2 2"/><path d="M16 10a2 2 0 0 0-2 2v0a2 2 0 0 0 2 2"/></svg>
                    </button>

                    <!-- Screenshot Button -->
                    <button class="yume-btn" id="yume-btn-snap" title="Screenshot">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"></path><circle cx="12" cy="13" r="4"></circle></svg>
                    </button>

                    <!-- Settings Gear -->
                    <button class="yume-btn" id="yume-btn-settings" title="Settings">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                    </button>

                    <!-- Fullscreen -->
                    <button class="yume-btn" id="yume-btn-fs" title="Fullscreen">
                        <svg id="yume-icon-fs-enter" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"></path></svg>
                        <svg id="yume-icon-fs-exit" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none;"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"></path></svg>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const streamURL = '%s';
        const rawTracks = %s || [];
        const preferredLang = '%s';
        const episodeKey = '%s';
        const rawAudioOptions = %s || [];

        const container = document.getElementById('yume-player-container');
        const video = document.getElementById('yume-video');
        const startScreen = document.getElementById('yume-start-screen');
        const pauseOverlay = document.getElementById('yume-pause-overlay');
        const progWrap = document.getElementById('yume-progress-wrap');
        const progBuf = document.getElementById('yume-prog-buf');
        const progPlay = document.getElementById('yume-prog-play');
        const progThumb = document.getElementById('yume-prog-thumb');
        const hoverTime = document.getElementById('yume-hover-time');

        const btnSettings = document.getElementById('yume-btn-settings');
        const settingsPopover = document.getElementById('yume-settings-popover');
        const btnFs = document.getElementById('yume-btn-fs');
        const iconFsEnter = document.getElementById('yume-icon-fs-enter');
        const iconFsExit = document.getElementById('yume-icon-fs-exit');

        const subDisplay = document.getElementById('yume-subtitle-display');
        const subContent = document.getElementById('yume-sub-content');

        let hlsInstance = null;
        let isScrubbing = false;
        let hideControlsTimeout = null;

        // Web Audio API Volume Boost
        let audioCtx = null;
        let gainNode = null;
        let compressorNode = null;

        function initAudioBoost() {
            if (audioCtx) {
                if (audioCtx.state === 'suspended') {
                    audioCtx.resume().catch(() => {});
                }
                return;
            }
            try {
                audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                const source = audioCtx.createMediaElementSource(video);
                gainNode = audioCtx.createGain();
                gainNode.gain.value = 1.0;
                compressorNode = audioCtx.createDynamicsCompressor();
                compressorNode.threshold.setValueAtTime(-3, audioCtx.currentTime);
                compressorNode.knee.setValueAtTime(6, audioCtx.currentTime);
                compressorNode.ratio.setValueAtTime(20, audioCtx.currentTime);
                compressorNode.attack.setValueAtTime(0.003, audioCtx.currentTime);
                compressorNode.release.setValueAtTime(0.25, audioCtx.currentTime);
                source.connect(gainNode);
                gainNode.connect(compressorNode);
                compressorNode.connect(audioCtx.destination);
                // Restore saved boost level
                try {
                    const sb = localStorage.getItem('yume_volume_boost');
                    if (sb) {
                        const parsed = parseFloat(sb);
                        let boostVal = 100;
                        if (parsed >= 100 && parsed <= 200) boostVal = parsed;
                        else if (parsed >= 1.0 && parsed <= 2.0) boostVal = parsed * 100;
                        gainNode.gain.value = boostVal / 100.0;
                    }
                } catch(e) {}
            } catch(e) { console.warn('AudioBoost init failed:', e); }
        }

        // Continue Watching - Seamless Exact Position Tracking
        const RESUME_TTL = 4 * 60 * 60 * 1000; // 4 hours
        let resumeTime = 0;
        let resumeApplied = false;
        let lastSaveTime = 0;
        let saveProgressTimer = null;

        function clearProgress() {
            if (!episodeKey) return;
            try { localStorage.removeItem('yume_resume_' + episodeKey); } catch(e) {}
        }

        function loadResumeTime() {
            if (!episodeKey) return 0;
            try {
                const raw = localStorage.getItem('yume_resume_' + episodeKey);
                if (!raw) return 0;
                const data = JSON.parse(raw);
                if (!data.ts || (Date.now() - data.ts > RESUME_TTL)) {
                    clearProgress();
                    return 0;
                }
                const savedTime = typeof data.time === 'number' ? data.time : parseFloat(data.time);
                if (isNaN(savedTime) || savedTime < 5) return 0;

                if (data.duration && isFinite(data.duration) && data.duration > 30) {
                    if ((data.duration - savedTime < 15) || (savedTime / data.duration) > 0.98) {
                        clearProgress();
                        return 0;
                    }
                }
                return savedTime;
            } catch(e) { return 0; }
        }

        function saveProgress(force) {
            if (!episodeKey) return;
            // Never overwrite saved position before initial resume has applied
            if (!resumeApplied && resumeTime > 0) return;
            const cur = video.currentTime;
            const dur = video.duration;
            if (!dur || !isFinite(dur) || dur < 30 || isNaN(cur) || video.seeking) return;

            const now = Date.now();
            if (!force && (now - lastSaveTime < 1000)) return;
            lastSaveTime = now;

            if (cur < 5) return;

            if (dur - cur < 15 || (cur / dur) > 0.98) {
                clearProgress();
                return;
            }

            try {
                localStorage.setItem('yume_resume_' + episodeKey, JSON.stringify({
                    time: Math.round(cur * 10) / 10,
                    duration: Math.round(dur),
                    ts: now
                }));
            } catch(e) {}
        }

        function applyResume() {
            if (resumeApplied || resumeTime <= 0) return;
            try {
                if (Math.abs(video.currentTime - resumeTime) > 0.5) {
                    video.currentTime = resumeTime;
                }
                if (Math.abs(video.currentTime - resumeTime) <= 1.5) {
                    resumeApplied = true;
                }
            } catch(e) {}
        }

        resumeTime = loadResumeTime();
        let activeCues = [];

        // Time Formatter (HH:MM:SS or MM:SS)
        function formatTime(seconds) {
            if (isNaN(seconds) || seconds < 0) return '00:00';
            const sec = Math.floor(seconds);
            const h = Math.floor(sec / 3600);
            const m = Math.floor((sec %% 3600) / 60);
            const s = sec %% 60;
            if (h > 0) {
                return (h < 10 ? '0' + h : h) + ':' + (m < 10 ? '0' + m : m) + ':' + (s < 10 ? '0' + s : s);
            }
            return (m < 10 ? '0' + m : m) + ':' + (s < 10 ? '0' + s : s);
        }

        // Video Stream Initialization (HLS for MegaPlay/Zoko or Native MP4 for AnimeSalt)
        const isHls = streamURL.indexOf('.mp4') === -1 && streamURL.indexOf('video.mp4') === -1;
        if (isHls && Hls.isSupported()) {
            hlsInstance = new Hls({
                maxBufferLength: 30,
                maxMaxBufferLength: 60,
                enableWorker: true,
                startPosition: resumeTime > 0 ? resumeTime : -1
            });
            hlsInstance.loadSource(streamURL);
            hlsInstance.attachMedia(video);

            hlsInstance.on(Hls.Events.MANIFEST_PARSED, function () {
                if (hlsInstance.levels && hlsInstance.levels.length > 0) {
                    hlsInstance.currentLevel = hlsInstance.levels.length - 1;
                }
                initQualityMenu(hlsInstance);
                initAudioMenu(hlsInstance, preferredLang);
                applyResume();
            });

            hlsInstance.on(Hls.Events.AUDIO_TRACKS_UPDATED, function () {
                initAudioMenu(hlsInstance, preferredLang);
            });

            hlsInstance.on(Hls.ErrorTypes.NETWORK_ERROR, () => hlsInstance.startLoad());
            hlsInstance.on(Hls.ErrorTypes.MEDIA_ERROR, () => hlsInstance.recoverMediaError());
        } else if (isHls && video.canPlayType('application/vnd.apple.mpegurl')) {
            video.src = streamURL;
        } else {
            // Direct MP4 playback (AnimeSalt, etc.)
            video.src = streamURL;
            initQualityMenu(null);
            initAudioMenu(null, preferredLang);
            if (resumeTime > 0) {
                video.currentTime = resumeTime;
            }
        }

        video.addEventListener('loadedmetadata', () => {
            if (video.duration && isFinite(video.duration)) {
                const curTime = resumeTime > 0 ? resumeTime : video.currentTime;
                const pct = (curTime / video.duration) * 100;
                updateTimelineUI(pct);
                document.getElementById('yume-time-display').textContent = formatTime(curTime) + ' / ' + formatTime(video.duration);
                document.getElementById('yume-top-time').textContent = formatTime(curTime) + ' / ' + formatTime(video.duration);
            }
            applyResume();
        });

        video.addEventListener('canplay', applyResume);

        // Play / Pause Logic
        function togglePlay() {
            if (video.paused || video.ended) {
                video.play();
            } else {
                video.pause();
            }
        }

        video.addEventListener('play', () => {
            initAudioBoost();
            applyResume();
            document.getElementById('yume-icon-play').style.display = 'none';
            document.getElementById('yume-icon-pause').style.display = 'block';
            pauseOverlay.classList.add('hidden');
            resetHideControlsTimer();
            if (!saveProgressTimer) saveProgressTimer = setInterval(() => saveProgress(false), 5000);
        });

        video.addEventListener('playing', () => {
            applyResume();
            resumeApplied = true;
        });

        video.addEventListener('pause', () => {
            saveProgress(true);
            document.getElementById('yume-icon-play').style.display = 'block';
            document.getElementById('yume-icon-pause').style.display = 'none';
            if (!startScreen || startScreen.classList.contains('hidden')) {
                pauseOverlay.classList.remove('hidden');
            }
            container.classList.remove('controls-hidden');
            if (hideControlsTimeout) clearTimeout(hideControlsTimeout);
        });

        video.addEventListener('seeked', () => {
            if (resumeTime > 0 && Math.abs(video.currentTime - resumeTime) <= 2) {
                resumeApplied = true;
            }
            saveProgress(true);
        });

        document.getElementById('yume-btn-play').addEventListener('click', togglePlay);
        pauseOverlay.addEventListener('click', togglePlay);
        video.addEventListener('click', (e) => {
            if (!settingsPopover.contains(e.target) && !e.target.closest('#yume-btn-settings')) {
                togglePlay();
            }
        });

        // Start Screen Click-to-Play
        startScreen.addEventListener('click', () => {
            startScreen.classList.add('hidden');
            video.volume = 1.0;
            video.muted = false;
            initAudioBoost();
            applyResume();
            video.play().catch(() => {});
            if (!saveProgressTimer) saveProgressTimer = setInterval(() => saveProgress(false), 5000);
            setTimeout(() => { if (startScreen.parentNode) startScreen.parentNode.removeChild(startScreen); }, 350);
        });

        // Rewind & Forward
        document.getElementById('yume-btn-rewind').addEventListener('click', () => {
            video.currentTime = Math.max(0, video.currentTime - 10);
            resetHideControlsTimer();
            saveProgress(true);
        });
        document.getElementById('yume-btn-forward').addEventListener('click', () => {
            video.currentTime = Math.min(video.duration || 9999, video.currentTime + 10);
            resetHideControlsTimer();
            saveProgress(true);
        });

        // Screenshot
        document.getElementById('yume-btn-snap').addEventListener('click', () => {
            try {
                if (!video.videoWidth) return;
                const canvas = document.createElement('canvas');
                canvas.width = video.videoWidth; canvas.height = video.videoHeight;
                canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
                document.getElementById('yume-flash').classList.add('flash');
                setTimeout(() => document.getElementById('yume-flash').classList.remove('flash'), 150);
                const a = document.createElement('a'); a.href = canvas.toDataURL('image/png'); a.download = 'YumeZone_Snapshot.png';
                document.body.appendChild(a); a.click(); document.body.removeChild(a);
            } catch(e) {}
            resetHideControlsTimer();
        });

        // Volume Controller
        const volWrapBox = document.getElementById('yume-vol-wrap-box');
        const volRange = document.getElementById('yume-vol-range');
        function updateVolumeUI(val, isMuted) {
            volRange.value = isMuted ? 0 : val;
            volRange.style.setProperty('--vol-pct', (isMuted ? 0 : val) * 100 + '%%');
            document.getElementById('yume-icon-vol-high').style.display = (isMuted || val == 0) ? 'none' : 'block';
            document.getElementById('yume-icon-vol-mute').style.display = (isMuted || val == 0) ? 'block' : 'none';
        }
        volRange.addEventListener('input', (e) => { video.volume = parseFloat(e.target.value); video.muted = (video.volume === 0); updateVolumeUI(video.volume, video.muted); });
        document.getElementById('yume-btn-vol').addEventListener('click', (e) => {
            e.stopPropagation();
            video.muted = !video.muted;
            updateVolumeUI(video.volume, video.muted);
        });

        // Timeline Progress Tracking & Time Code Updates
        video.addEventListener('timeupdate', () => {
            // Safety fallback for resume
            if (!resumeApplied && resumeTime > 0) {
                if (video.currentTime < 2 && video.readyState >= 1) {
                    applyResume();
                } else if (video.currentTime >= 2 && Math.abs(video.currentTime - resumeTime) < 5) {
                    resumeApplied = true;
                }
            }

            // Continuously track exact position (throttled to 1s)
            saveProgress(false);

            if (!isScrubbing && video.duration) {
                const pct = (video.currentTime / video.duration) * 100;
                updateTimelineUI(pct);
            }
            const cur = formatTime(video.currentTime);
            const dur = formatTime(video.duration || 0);
            document.getElementById('yume-time-display').textContent = cur + ' / ' + dur;
            document.getElementById('yume-top-time').textContent = cur + ' / ' + dur;
            updateSubtitles();
            try {
                window.parent.postMessage({ type: 'time', currentTime: video.currentTime, duration: video.duration || 0 }, '*');
            } catch(e) {}
        });

        video.addEventListener('ended', () => {
            clearProgress();
            resumeApplied = true;
            if (saveProgressTimer) { clearInterval(saveProgressTimer); saveProgressTimer = null; }
            try { window.parent.postMessage({ type: 'complete' }, '*'); } catch(e) {}
        });

        // Lifecycle save progress flushes
        window.addEventListener('beforeunload', () => saveProgress(true));
        window.addEventListener('pagehide', () => saveProgress(true));
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') saveProgress(true);
        });

        video.addEventListener('progress', () => {
            if (video.duration && video.buffered.length > 0) {
                const bufEnd = video.buffered.end(video.buffered.length - 1);
                const pct = (bufEnd / video.duration) * 100;
                progBuf.style.width = pct + '%%';
            }
        });

        function updateTimelineUI(pct) {
            progPlay.style.width = pct + '%%';
            progThumb.style.left = pct + '%%';
        }

        // Seeking & Scrubbing Gestures
        function getScrubPos(e) {
            const rect = progWrap.getBoundingClientRect();
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const x = Math.max(0, Math.min(rect.width, clientX - rect.left));
            return x / rect.width;
        }

        function onScrubStart(e) {
            isScrubbing = true;
            progWrap.classList.add('scrubbing');
            const pos = getScrubPos(e);
            updateTimelineUI(pos * 100);
            hoverTime.textContent = formatTime(pos * (video.duration || 0));
            hoverTime.style.left = (pos * 100) + '%%';
            window.addEventListener('mousemove', onScrubMove);
            window.addEventListener('touchmove', onScrubMove);
            window.addEventListener('mouseup', onScrubEnd);
            window.addEventListener('touchend', onScrubEnd);
        }

        function onScrubMove(e) {
            if (!isScrubbing) return;
            const pos = getScrubPos(e);
            requestAnimationFrame(() => {
                updateTimelineUI(pos * 100);
                hoverTime.textContent = formatTime(pos * (video.duration || 0));
                hoverTime.style.left = (pos * 100) + '%%';
            });
        }

        function onScrubEnd(e) {
            if (!isScrubbing) return;
            isScrubbing = false;
            progWrap.classList.remove('scrubbing');
            const pos = getScrubPos(e);
            if (video.duration) {
                video.currentTime = pos * video.duration;
                saveProgress(true);
            }
            window.removeEventListener('mousemove', onScrubMove);
            window.removeEventListener('touchmove', onScrubMove);
            window.removeEventListener('mouseup', onScrubEnd);
            window.removeEventListener('touchend', onScrubEnd);
        }

        progWrap.addEventListener('mousedown', onScrubStart);
        progWrap.addEventListener('touchstart', onScrubStart, { passive: false });
        progWrap.addEventListener('mousemove', (e) => {
            if (isScrubbing) return;
            const pos = getScrubPos(e);
            hoverTime.style.left = (pos * 100) + '%%';
            hoverTime.textContent = formatTime(pos * (video.duration || 0));
        });

        // Mobile Landscape Lock & Fullscreen Controller
        async function lockLandscape() {
            try {
                if (screen.orientation && screen.orientation.lock) {
                    await screen.orientation.lock('landscape');
                } else if (screen.lockOrientation) {
                    screen.lockOrientation('landscape');
                } else if (screen.mozLockOrientation) {
                    screen.mozLockOrientation('landscape');
                } else if (screen.msLockOrientation) {
                    screen.msLockOrientation('landscape');
                }
            } catch(e) {}
        }

        async function unlockOrientation() {
            try {
                if (screen.orientation && screen.orientation.unlock) {
                    screen.orientation.unlock();
                } else if (screen.unlockOrientation) {
                    screen.unlockOrientation();
                } else if (screen.mozUnlockOrientation) {
                    screen.mozUnlockOrientation();
                } else if (screen.msUnlockOrientation) {
                    screen.msUnlockOrientation();
                }
            } catch(e) {}
        }

        async function toggleFullscreen() {
            const isFs = Boolean(document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement);
            if (!isFs) {
                try {
                    if (container.requestFullscreen) {
                        await container.requestFullscreen();
                    } else if (container.webkitRequestFullscreen) {
                        await container.webkitRequestFullscreen();
                    } else if (container.mozRequestFullScreen) {
                        await container.mozRequestFullScreen();
                    } else if (container.msRequestFullscreen) {
                        await container.msRequestFullscreen();
                    } else if (video.webkitEnterFullscreen) {
                        video.webkitEnterFullscreen();
                    }
                    await lockLandscape();
                } catch(e) {
                    if (video.webkitEnterFullscreen) {
                        try { video.webkitEnterFullscreen(); } catch(err) {}
                    }
                }
            } else {
                unlockOrientation();
                try {
                    if (document.exitFullscreen) {
                        await document.exitFullscreen();
                    } else if (document.webkitExitFullscreen) {
                        await document.webkitExitFullscreen();
                    } else if (document.mozCancelFullScreen) {
                        await document.mozCancelFullScreen();
                    } else if (document.msExitFullscreen) {
                        await document.msExitFullscreen();
                    }
                } catch(e) {}
            }
        }

        function onFullscreenChange() {
            const isFs = Boolean(document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement);
            iconFsEnter.style.display = isFs ? 'none' : 'block';
            iconFsExit.style.display = isFs ? 'block' : 'none';
            if (isFs) {
                lockLandscape();
            } else {
                unlockOrientation();
            }
        }

        btnFs.addEventListener('click', toggleFullscreen);
        document.addEventListener('fullscreenchange', onFullscreenChange);
        document.addEventListener('webkitfullscreenchange', onFullscreenChange);
        document.addEventListener('mozfullscreenchange', onFullscreenChange);
        document.addEventListener('MSFullscreenChange', onFullscreenChange);
        video.addEventListener('webkitendfullscreen', () => {
            unlockOrientation();
            iconFsEnter.style.display = 'block';
            iconFsExit.style.display = 'none';
        });

        // Auto-Hide Controls
        function resetHideControlsTimer() {
            container.classList.remove('controls-hidden');
            if (hideControlsTimeout) clearTimeout(hideControlsTimeout);
            if (!video.paused) {
                hideControlsTimeout = setTimeout(() => {
                    if (!settingsPopover.classList.contains('hidden') || isScrubbing) return;
                    container.classList.add('controls-hidden');
                }, 2500);
            }
        }
        container.addEventListener('mousemove', resetHideControlsTimer);
        container.addEventListener('touchstart', resetHideControlsTimer);

        // Settings Popover Controller
        const menuMain = document.getElementById('yume-menu-main');
        const menuAudio = document.getElementById('yume-menu-audio');
        const menuQuality = document.getElementById('yume-menu-quality');
        const menuSubtitles = document.getElementById('yume-menu-subtitles');
        const menuSpeed = document.getElementById('yume-menu-speed');
        const menuBoost = document.getElementById('yume-menu-boost');

        function toggleSettings() {
            if (settingsPopover.classList.contains('hidden')) {
                showMenu('main');
                settingsPopover.classList.remove('hidden');
            } else {
                settingsPopover.classList.add('hidden');
            }
        }

        function showMenu(name) {
            [menuMain, menuAudio, menuQuality, menuSubtitles, menuSpeed, menuBoost].forEach(m => m && m.classList.add('hidden'));
            if (name === 'main' && menuMain) menuMain.classList.remove('hidden');
            if (name === 'audio' && menuAudio) menuAudio.classList.remove('hidden');
            if (name === 'quality' && menuQuality) menuQuality.classList.remove('hidden');
            if (name === 'subtitles' && menuSubtitles) menuSubtitles.classList.remove('hidden');
            if (name === 'speed' && menuSpeed) menuSpeed.classList.remove('hidden');
            if (name === 'boost' && menuBoost) menuBoost.classList.remove('hidden');
        }

        btnSettings.addEventListener('click', (e) => { e.stopPropagation(); toggleSettings(); });

        document.getElementById('yume-row-audio').addEventListener('click', () => showMenu('audio'));
        document.getElementById('yume-row-quality').addEventListener('click', () => showMenu('quality'));
        document.getElementById('yume-row-subtitles').addEventListener('click', () => showMenu('subtitles'));
        document.getElementById('yume-row-speed').addEventListener('click', () => showMenu('speed'));
        document.getElementById('yume-row-boost').addEventListener('click', () => showMenu('boost'));

        document.getElementById('yume-back-audio').addEventListener('click', () => showMenu('main'));
        document.getElementById('yume-back-quality').addEventListener('click', () => showMenu('main'));
        document.getElementById('yume-back-subtitles').addEventListener('click', () => showMenu('main'));
        document.getElementById('yume-back-speed').addEventListener('click', () => showMenu('main'));
        document.getElementById('yume-back-boost').addEventListener('click', () => showMenu('main'));

        document.addEventListener('click', (e) => {
            if (!settingsPopover.contains(e.target) && !e.target.closest('#yume-btn-settings')) settingsPopover.classList.add('hidden');
            if (!volWrapBox.contains(e.target)) volWrapBox.classList.remove('active');
        });

        // Audio Track Menu Setup with Preferred Language (e.g. Hindi Dub) Auto-Selection
        function initAudioMenu(hls, pref) {
            const list = document.getElementById('yume-audio-list');
            const rowAudio = document.getElementById('yume-row-audio');
            if (!list || !rowAudio) return;

            if (!hls) {
                if (!rawAudioOptions || rawAudioOptions.length <= 1) {
                    rowAudio.style.display = 'none';
                    return;
                }
                rowAudio.style.display = 'flex';
                list.innerHTML = '';
                const targetLang = (pref || 'hin').toLowerCase();
                let curLabel = rawAudioOptions[0].label;

                rawAudioOptions.forEach(opt => {
                    const oLang = (opt.langCode || '').toLowerCase();
                    const isActive = oLang === targetLang ||
                                     ((targetLang === 'sub' || targetLang === 'jpn') && (oLang === 'sub' || oLang === 'jpn')) ||
                                     ((targetLang === 'dub' || targetLang === 'eng') && (oLang === 'dub' || oLang === 'eng'));
                    if (isActive) curLabel = opt.label;
                    const div = document.createElement('div');
                    div.className = 'yume-option' + (isActive ? ' active' : '');
                    div.textContent = opt.label;
                    div.onclick = () => {
                        const u = new URL(window.location.href);
                        u.searchParams.set('lang', opt.langCode);
                        window.location.href = u.toString();
                    };
                    list.appendChild(div);
                });

                document.getElementById('yume-val-audio').innerHTML = curLabel + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                return;
            }

            if (!hls.audioTracks || hls.audioTracks.length <= 1) {
                rowAudio.style.display = 'none';
                return;
            }
            rowAudio.style.display = 'flex';
            list.innerHTML = '';

            const tracks = hls.audioTracks;
            let selectedIdx = hls.audioTrack >= 0 ? hls.audioTrack : 0;
            const targetLang = (pref || 'sub').toLowerCase();

            // Auto-select preferred language on manifest load if not already manually set
            if (!window.__userSelectedAudio) {
                for (let i = 0; i < tracks.length; i++) {
                    const tName = (tracks[i].name || '').toLowerCase();
                    const tLang = (tracks[i].lang || '').toLowerCase();
                    if (targetLang === 'hin' && (tName.includes('hin') || tLang.includes('hin') || tName.includes('hindi'))) {
                        selectedIdx = i;
                        break;
                    } else if ((targetLang === 'dub' || targetLang === 'eng') && (tName.includes('eng') || tLang.includes('eng') || tName.includes('english'))) {
                        selectedIdx = i;
                        break;
                    } else if ((targetLang === 'sub' || targetLang === 'jpn') && (tName.includes('jpn') || tLang.includes('jpn') || tName.includes('jap'))) {
                        selectedIdx = i;
                        break;
                    }
                }
                try { hls.audioTrack = selectedIdx; } catch(e) {}
            }

            const currentLabel = tracks[selectedIdx]?.name || ('Audio ' + (selectedIdx + 1));
            document.getElementById('yume-val-audio').innerHTML = currentLabel + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';

            tracks.forEach((t, idx) => {
                const div = document.createElement('div');
                div.className = 'yume-option' + (idx === selectedIdx ? ' active' : '');
                div.textContent = t.name || ('Track ' + (idx + 1));
                div.onclick = () => {
                    window.__userSelectedAudio = true;
                    hls.audioTrack = idx;
                    list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                    document.getElementById('yume-val-audio').innerHTML = (t.name || ('Track ' + (idx + 1))) + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                    showMenu('main');
                };
                list.appendChild(div);
            });
        }

        // Quality Menu Setup
        function initQualityMenu(hls) {
            const list = document.getElementById('yume-quality-list');
            if (!list) return;
            if (!hls || !hls.levels) {
                document.getElementById('yume-val-quality').innerHTML = '1080P <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                list.innerHTML = '<div class="yume-option active">1080P (FHD)</div>';
                return;
            }
            list.innerHTML = '';
            const levels = hls.levels;
            const highestLabel = (levels[levels.length - 1]?.height || '1080') + 'P';
            document.getElementById('yume-val-quality').innerHTML = highestLabel + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
            const options = [{ label: 'Auto (' + highestLabel + ')', level: -1 }];
            for (let i = levels.length - 1; i >= 0; i--) options.push({ label: (levels[i].height || 'Quality ' + (i+1)) + 'P', level: i });
            options.forEach((opt, idx) => {
                const div = document.createElement('div');
                div.className = 'yume-option' + (idx === 1 ? ' active' : '');
                div.textContent = opt.label;
                div.onclick = () => {
                    hls.currentLevel = opt.level;
                    list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                    document.getElementById('yume-val-quality').innerHTML = opt.label.split(' ')[0] + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                    showMenu('main');
                };
                list.appendChild(div);
            });
        }

        // Subtitles Parser
        function parseVTT(text) {
            const cues = []; const lines = text.split(/\r?\n/);
            for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes('-->')) {
                    const parts = lines[i].split('-->');
                    const start = parseVTTTime(parts[0].trim());
                    const end = parseVTTTime(parts[1].trim().split(' ')[0]);
                    let content = ''; i++;
                    while (i < lines.length && lines[i].trim() !== '') { content += (content ? '<br>' : '') + lines[i].trim(); i++; }
                    cues.push({ start, end, text: content });
                }
            }
            return cues;
        }
        function parseVTTTime(str) {
            const parts = str.split(':');
            return parts.length === 3 ? parseFloat(parts[0]) * 3600 + parseFloat(parts[1]) * 60 + parseFloat(parts[2]) : parseFloat(parts[0]) * 60 + parseFloat(parts[1]);
        }
        function updateSubtitles() {
            if (!activeCues.length) { subContent.innerHTML = ''; return; }
            const currentCue = activeCues.find(c => video.currentTime >= c.start && video.currentTime <= c.end);
            subContent.innerHTML = currentCue ? currentCue.text : '';
        }
        function initSubtitlesMenu() {
            const list = document.getElementById('yume-subtitles-list');
            const ccBtn = document.getElementById('yume-btn-cc');
            if (!list) return;
            list.innerHTML = '';

            const offDiv = document.createElement('div');
            offDiv.className = 'yume-option active';
            offDiv.textContent = 'Off';
            offDiv.onclick = () => {
                activeCues = [];
                subContent.innerHTML = '';
                list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                offDiv.classList.add('active');
                if (ccBtn) ccBtn.classList.remove('active');
                document.getElementById('yume-val-subtitles').innerHTML = 'Off <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                showMenu('main');
            };
            list.appendChild(offDiv);

            rawTracks.forEach((t, idx) => {
                const div = document.createElement('div');
                div.className = 'yume-option';
                const label = t.label || ('Subtitle ' + (idx + 1));
                div.textContent = label;
                
                const activateTrack = () => {
                    fetch(t.file)
                        .then(r => r.text())
                        .then(vtt => {
                            activeCues = parseVTT(vtt);
                            if (ccBtn) ccBtn.classList.add('active');
                        })
                        .catch(() => {
                            activeCues = [];
                            if (ccBtn) ccBtn.classList.remove('active');
                        });
                    list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                    document.getElementById('yume-val-subtitles').innerHTML = label + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                };

                div.onclick = () => {
                    activateTrack();
                    showMenu('main');
                };
                list.appendChild(div);
            });

            if (ccBtn) {
                if (rawTracks.length === 0) {
                    ccBtn.style.opacity = '0.35';
                    ccBtn.title = 'No Subtitles Available';
                } else {
                    ccBtn.style.opacity = '1';
                    ccBtn.onclick = () => {
                        if (activeCues.length > 0) {
                            activeCues = [];
                            subContent.innerHTML = '';
                            ccBtn.classList.remove('active');
                            list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                            offDiv.classList.add('active');
                            document.getElementById('yume-val-subtitles').innerHTML = 'Off <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                        } else {
                            const firstTrack = list.querySelectorAll('.yume-option')[1];
                            if (firstTrack) firstTrack.click();
                        }
                    };
                }
            }
        }
        function initSpeedMenu() {
            const list = document.getElementById('yume-speed-list');
            if (!list) return;
            [0.5, 0.75, 1.0, 1.25, 1.5, 2.0].forEach(s => {
                const div = document.createElement('div');
                div.className = 'yume-option' + (s === 1.0 ? ' active' : '');
                div.textContent = s === 1.0 ? 'Normal' : s + 'x';
                div.onclick = () => {
                    video.playbackRate = s;
                    list.querySelectorAll('.yume-option').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                    document.getElementById('yume-val-speed').innerHTML = div.textContent + ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';
                    showMenu('main');
                };
                list.appendChild(div);
            });
        }
        initSubtitlesMenu();
        initSpeedMenu();

        // Volume Boost Menu
        function initBoostMenu() {
            const range = document.getElementById('yume-boost-range');
            const valText = document.getElementById('yume-boost-val-text');
            const mainVal = document.getElementById('yume-val-boost');
            const ticks = document.querySelectorAll('.yume-boost-tick');
            if (!range || !valText || !mainVal) return;

            const chevron = ' <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"></polyline></svg>';

            let currentBoostVal = 100; // Default 100%% (1.0x gain), ranges to 200%% (2.0x gain)
            try {
                const sb = localStorage.getItem('yume_volume_boost');
                if (sb) {
                    const parsed = parseFloat(sb);
                    if (parsed >= 100 && parsed <= 200) {
                        currentBoostVal = Math.round(parsed);
                    } else if (parsed >= 1.0 && parsed <= 2.0) {
                        currentBoostVal = Math.round(parsed * 100);
                    }
                }
            } catch(e) {}

            function updateBoost(val, persist) {
                currentBoostVal = Math.max(100, Math.min(200, Math.round(val)));
                range.value = currentBoostVal;

                // Fill percentage (0%% at 100, 100%% at 200)
                const pct = currentBoostVal - 100;
                range.style.setProperty('--boost-pct', pct + '%%');

                const label = currentBoostVal + '%%';
                valText.textContent = label;
                mainVal.innerHTML = label + chevron;

                ticks.forEach(t => {
                    const tVal = parseInt(t.getAttribute('data-val'), 10);
                    if (tVal === currentBoostVal) {
                        t.classList.add('active');
                    } else {
                        t.classList.remove('active');
                    }
                });

                if (gainNode) {
                    gainNode.gain.value = currentBoostVal / 100.0;
                }

                if (persist) {
                    try { localStorage.setItem('yume_volume_boost', String(currentBoostVal)); } catch(e) {}
                }
            }

            range.addEventListener('input', (e) => {
                initAudioBoost();
                updateBoost(parseFloat(e.target.value), false);
            });

            range.addEventListener('change', () => {
                try { localStorage.setItem('yume_volume_boost', String(currentBoostVal)); } catch(e) {}
            });

            range.addEventListener('click', (e) => e.stopPropagation());

            ticks.forEach(t => {
                t.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const targetVal = parseInt(t.getAttribute('data-val'), 10);
                    if (!isNaN(targetVal)) {
                        initAudioBoost();
                        updateBoost(targetVal, true);
                    }
                });
            });

            // Initial apply
            updateBoost(currentBoostVal, false);
        }
        initBoostMenu();
    </script>
</body>
</html>`, streamURL, string(tracksJSON), preferredLang, episodeKey, string(audsJSON))
}

func renderCustomProxy404(path string, message string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body {
            width: 100%;
            height: 100%;
            background-color: #000000;
            color: #ffffff;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            text-align: center;
            padding: 24px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.98); }
            to { opacity: 1; transform: scale(1); }
        }
        .code {
            font-size: clamp(72px, 15vw, 120px);
            font-weight: 800;
            letter-spacing: -0.05em;
            line-height: 1;
            color: #ffffff;
            user-select: none;
        }
        .desc {
            margin-top: 12px;
            font-size: 13px;
            font-weight: 500;
            color: #71717a;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            user-select: none;
        }
        .btn-reload {
            margin-top: 28px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 9px 18px;
            background: #000000;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 999px;
            color: #a1a1aa;
            font-size: 12px;
            font-weight: 500;
            font-family: inherit;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .btn-reload:hover {
            border-color: rgba(255, 255, 255, 0.3);
            color: #ffffff;
            background: #0d0d11;
            transform: translateY(-1px);
        }
        .btn-reload svg {
            transition: transform 0.3s ease;
        }
        .btn-reload:hover svg {
            transform: rotate(90deg);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="code">404</div>
        <div class="desc">Not Found</div>
        <button class="btn-reload" onclick="window.location.reload()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
            <span>Reload</span>
        </button>
    </div>
</body>
</html>`
}

func extractMegaplayHLSWithFallback(ctx context.Context, originalPath string) (string, []SubtitleTrack, error) {
	normPath := normalizeMegaplayPath(originalPath)

	// Check cache first for 0ms instant hit
	if val, ok := megaplayStreamCache.Load(normPath); ok {
		entry := val.(MegaplayStreamCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry.HLSFile, entry.Tracks, nil
		}
	}
	if originalPath != normPath {
		if val, ok := megaplayStreamCache.Load(originalPath); ok {
			entry := val.(MegaplayStreamCacheEntry)
			if time.Now().Before(entry.ExpiresAt) {
				return entry.HLSFile, entry.Tracks, nil
			}
		}
	}

	// Prepare candidate mirrors
	candidates := []string{normPath}
	if originalPath != normPath {
		candidates = append(candidates, originalPath)
	}
	if strings.HasPrefix(normPath, "mal/") {
		candidates = append(candidates, "ani/"+strings.TrimPrefix(normPath, "mal/"))
	} else if strings.HasPrefix(normPath, "ani/") {
		candidates = append(candidates, "mal/"+strings.TrimPrefix(normPath, "ani/"))
	}

	if len(candidates) == 1 {
		hlsFile, tracks, err := extractMegaplayHLS(ctx, candidates[0])
		if err == nil && hlsFile != "" {
			cacheEntry := MegaplayStreamCacheEntry{
				HLSFile:   hlsFile,
				Tracks:    tracks,
				ExpiresAt: time.Now().Add(3 * time.Hour),
			}
			megaplayStreamCache.Store(normPath, cacheEntry)
			return hlsFile, tracks, nil
		}
		return "", nil, err
	}

	// Run candidates in parallel race! First valid stream wins and cancels others
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type candResult struct {
		file   string
		tracks []SubtitleTrack
		err    error
	}

	resChan := make(chan candResult, len(candidates))
	for _, cand := range candidates {
		c := cand
		go func() {
			f, t, e := extractMegaplayHLS(subCtx, c)
			resChan <- candResult{file: f, tracks: t, err: e}
		}()
	}

	var lastErr error
	for i := 0; i < len(candidates); i++ {
		res := <-resChan
		if res.err == nil && res.file != "" {
			cancel() // Cancel remaining candidate requests immediately
			cacheEntry := MegaplayStreamCacheEntry{
				HLSFile:   res.file,
				Tracks:    res.tracks,
				ExpiresAt: time.Now().Add(3 * time.Hour),
			}
			megaplayStreamCache.Store(normPath, cacheEntry)
			if originalPath != normPath {
				megaplayStreamCache.Store(originalPath, cacheEntry)
			}
			return res.file, res.tracks, nil
		}
		if res.err != nil {
			lastErr = res.err
		}
	}

	return "", nil, fmt.Errorf("all megaplay extraction mirrors failed for path: %s (last err: %v)", originalPath, lastErr)
}

func handleMegaplayEmbed(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Enforce Allowed Site / Domain Embed Restriction
	if !isEmbedAllowed(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Embedding not allowed: domain is not authorized to embed this player."))
		return
	}

	targetPath := strings.TrimPrefix(r.URL.Path, "/embed/megaplay/")
	targetPath = strings.TrimPrefix(targetPath, "/embed/megaplay")
	targetPath = strings.TrimPrefix(targetPath, "/")
	if targetPath == "" {
		http.Error(w, `{"error":"Missing embed path"}`, http.StatusBadRequest)
		return
	}

	// Auto-normalize path and resolve AniList ID to MAL ID
	targetPath = normalizeMegaplayPath(targetPath)
	frameAncestors := buildFrameAncestorsCSP(r.Host)
	cspHeader := fmt.Sprintf("default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors %s;", frameAncestors)

	// Check cache for instant load
	cacheKey := "megaplay:clean:" + targetPath
	if val, ok := embedCache.Load(cacheKey); ok {
		entry := val.(EmbedCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(entry.HTML))
			return
		}
	}

	// 1. Extract clean decrypted HLS stream directly from MegaPlay with multi-mirror fallbacks
	hlsFile, tracks, err := extractMegaplayHLSWithFallback(r.Context(), targetPath)
	if err == nil && hlsFile != "" {
		// Proxy subtitle tracks through /p/ token route so they load with proper CORS
		var proxiedTracks []SubtitleTrack
		for _, t := range tracks {
			if t.File != "" {
				subToken, subErr := encryptToken(&TokenPayload{
					URL: t.File,
					Ref: "https://megaplay.buzz/",
					Exp: time.Now().Add(6 * time.Hour).Unix(),
				})
				if subErr == nil {
					t.File = "/p/" + subToken
				}
			}
			proxiedTracks = append(proxiedTracks, t)
		}

		// Generate encrypted proxy token for HLS streaming with Referer: https://megaplay.buzz/
		streamToken, err := encryptToken(&TokenPayload{
			URL: hlsFile,
			Ref: "https://megaplay.buzz/",
			Exp: time.Now().Add(6 * time.Hour).Unix(),
		})
		if err == nil {
			proxiedStreamURL := "/p/" + streamToken
			prefLang := "sub"
			if strings.HasSuffix(targetPath, "/dub") {
				prefLang = "dub"
			}
			cleanTarget := strings.TrimSuffix(strings.TrimSuffix(targetPath, "/dub"), "_dub")
			html := renderCleanArtplayer(proxiedStreamURL, proxiedTracks, prefLang, "megaplay_"+strings.ReplaceAll(cleanTarget, "/", "_"))

			embedCache.Store(cacheKey, EmbedCacheEntry{
				HTML:      html,
				ExpiresAt: time.Now().Add(2 * time.Hour),
			})

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(html))
			return
		}
	}

	// 2. Custom 404 UI fallback when stream is unavailable
	errorHTML := renderCustomProxy404(targetPath, "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Del("X-Frame-Options")
	w.Header().Del("Cross-Origin-Opener-Policy")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(errorHTML))
}

func handleMegaplaySources(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	path := r.URL.Path
	if path == "/stream/getSources" {
		path = "/stream/getSourcesNew"
	}
	upstreamURL := "https://megaplay.buzz" + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, `{"error":"Failed to create upstream request"}`, http.StatusInternalServerError)
		return
	}

	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	upstreamReq.Header.Set("Accept", "*/*")
	upstreamReq.Header.Set("Referer", "https://megaplay.buzz/")
	upstreamReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := megaplayHttpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, `{"error":"Upstream fetch failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read upstream response"}`, http.StatusBadGateway)
		return
	}

	// Decrypt enc and inject sources for backwards compatibility with older clients
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonMap); err == nil {
		if encVal, ok := jsonMap["enc"].(string); ok && encVal != "" {
			if fileURL, decErr := decryptMegaplayEnc(encVal); decErr == nil && fileURL != "" {
				jsonMap["sources"] = []map[string]interface{}{
					{"file": fileURL},
				}
				if reencoded, err := json.Marshal(jsonMap); err == nil {
					bodyBytes = reencoded
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.WriteHeader(resp.StatusCode)
	w.Write(bodyBytes)
}

func handleMegaplayLib(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	upstreamURL := "https://megaplay.buzz" + r.URL.Path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	upstreamReq.Header.Set("Referer", "https://megaplay.buzz/")

	resp, err := megaplayHttpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, "error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ─────────────────────────────────────────────────────────────────────────────
// AnimeSalt Server 1 (as-cdn26) Scraping, Hindi Dub Extraction & Custom Player
// ─────────────────────────────────────────────────────────────────────────────

type AnimeSaltSourcesResponse struct {
	Hls          bool   `json:"hls"`
	VideoSource  string `json:"videoSource"`
	VideoSources []struct {
		File  string `json:"file"`
		Label string `json:"label"`
		Type  string `json:"type"`
	} `json:"videoSources"`
	VideoImage string          `json:"videoImage"`
	Tracks     []SubtitleTrack `json:"tracks"`
}

type AnimeSaltStreamCacheEntry struct {
	ProxiedURL   string
	Tracks       []SubtitleTrack
	AudioOptions []AnimeSaltAudioOption
	ResolvedSlug string
	ExpiresAt    time.Time
}

type AnimeSaltAudioLinksCacheEntry struct {
	AudioLinks []AbyssAudioLink
	ExpiresAt  time.Time
}

type AnimeSaltSubCacheEntry struct {
	Tracks    []SubtitleTrack
	ExpiresAt time.Time
}

var (
	animeSaltSlugCache       sync.Map
	animeTitleCache          sync.Map
	animeSaltCache           sync.Map
	animeSaltStreamCache     sync.Map
	animeSaltAudioLinksCache sync.Map
	animeSaltSubCache        sync.Map
)

func readResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("empty response")
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if strings.Contains(encoding, "gzip") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gzReader.Close()
			reader = gzReader
		}
	} else if strings.Contains(encoding, "deflate") {
		flReader := flate.NewReader(resp.Body)
		defer flReader.Close()
		reader = flReader
	}

	return io.ReadAll(reader)
}

func resolveAnimeTitle(anilistID int, malID int) string {
	if anilistID <= 0 && malID <= 0 {
		return ""
	}
	cacheKey := fmt.Sprintf("ani:%d_mal:%d", anilistID, malID)
	if cached, ok := animeTitleCache.Load(cacheKey); ok {
		return cached.(string)
	}

	// 1. AniZip API (supports both anilist_id and mal_id)
	var aniZipURL string
	if anilistID > 0 {
		aniZipURL = fmt.Sprintf("https://api.ani.zip/mappings?anilist_id=%d", anilistID)
	} else {
		aniZipURL = fmt.Sprintf("https://api.ani.zip/mappings?mal_id=%d", malID)
	}

	req, err := http.NewRequest(http.MethodGet, aniZipURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		resp, err := apiHttpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			bodyBytes, bErr := readResponseBody(resp)
			if bErr == nil {
				var data struct {
					Titles struct {
						En        string `json:"en"`
						Canonical string `json:"canonical"`
						Rj        string `json:"rj"`
					} `json:"titles"`
				}
				if err := json.Unmarshal(bodyBytes, &data); err == nil {
					title := data.Titles.En
					if title == "" {
						title = data.Titles.Canonical
					}
					if title == "" {
						title = data.Titles.Rj
					}
					if title != "" {
						animeTitleCache.Store(cacheKey, title)
						return title
					}
				}
			}
		}
	}

	// 2. AniList GraphQL (if anilistID is present)
	if anilistID > 0 {
		graphqlQuery := `query ($id: Int) { Media (id: $id, type: ANIME) { title { english userPreferred romaji } } }`
		bodyBytes, _ := json.Marshal(map[string]interface{}{
			"query": graphqlQuery,
			"variables": map[string]interface{}{
				"id": anilistID,
			},
		})
		gqlReq, err := http.NewRequest(http.MethodPost, "https://graphql.anilist.co", bytes.NewBuffer(bodyBytes))
		if err == nil {
			gqlReq.Header.Set("Content-Type", "application/json")
			gqlReq.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := apiHttpClient.Do(gqlReq)
			if err == nil && resp.StatusCode == http.StatusOK {
				bodyBytes, bErr := readResponseBody(resp)
				if bErr == nil {
					var gqlRes struct {
						Data struct {
							Media struct {
								Title struct {
									English       string `json:"english"`
									UserPreferred string `json:"userPreferred"`
									Romaji        string `json:"romaji"`
								} `json:"title"`
							} `json:"Media"`
						} `json:"data"`
					}
					if err := json.Unmarshal(bodyBytes, &gqlRes); err == nil {
						t := gqlRes.Data.Media.Title.English
						if t == "" {
							t = gqlRes.Data.Media.Title.UserPreferred
						}
						if t == "" {
							t = gqlRes.Data.Media.Title.Romaji
						}
						if t != "" {
							animeTitleCache.Store(cacheKey, t)
							return t
						}
					}
				}
			}
		}
	}

	// 3. Jikan / MAL API (if malID is present)
	if malID > 0 {
		reqURL := fmt.Sprintf("https://api.jikan.moe/v4/anime/%d", malID)
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := apiHttpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				bodyBytes, bErr := readResponseBody(resp)
				if bErr == nil {
					var jikanData struct {
						Data struct {
							TitleEnglish string `json:"title_english"`
							Title        string `json:"title"`
						} `json:"data"`
					}
					if err := json.Unmarshal(bodyBytes, &jikanData); err == nil {
						t := jikanData.Data.TitleEnglish
						if t == "" {
							t = jikanData.Data.Title
						}
						if t != "" {
							animeTitleCache.Store(cacheKey, t)
							return t
						}
					}
				}
			}
		}
	}

	return ""
}

func resolveAnimeSaltSlug(ctx context.Context, anilistID int, malID int, manualSlug string) (string, error) {
	if manualSlug != "" {
		return manualSlug, nil
	}
	cacheKey := fmt.Sprintf("ani:%d_mal:%d", anilistID, malID)
	if cached, ok := animeSaltSlugCache.Load(cacheKey); ok {
		return cached.(string), nil
	}

	title := resolveAnimeTitle(anilistID, malID)
	if title == "" {
		return "", fmt.Errorf("could not resolve anime title for ani:%d mal:%d", anilistID, malID)
	}

	cleanTitle := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
			return r
		}
		return ' '
	}, title)
	cleanTitle = strings.Join(strings.Fields(cleanTitle), " ")

	queries := []string{cleanTitle}
	if strings.Contains(title, ":") {
		queries = append(queries, strings.TrimSpace(strings.Split(title, ":")[0]))
	}
	if strings.Contains(title, "-") {
		queries = append(queries, strings.TrimSpace(strings.Split(title, "-")[0]))
	}

	targetSlug := strings.ToLower(strings.ReplaceAll(cleanTitle, " ", "-"))
	slugRegex := regexp.MustCompile(`https?://animesalt\.cx/series/([a-zA-Z0-9\-]+)/?`)

	for _, q := range queries {
		encodedQ := url.QueryEscape(q)
		searchURL := "https://animesalt.cx/?s=" + encodedQ
		searchReq, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
		if err != nil {
			continue
		}
		searchReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		searchReq.Header.Set("Referer", "https://animesalt.cx/")

		resp, err := animesaltHttpClient.Do(searchReq)
		if err != nil {
			continue
		}
		bodyBytes, err := readResponseBody(resp)
		if err != nil {
			continue
		}

		html := string(bodyBytes)
		allMatches := slugRegex.FindAllStringSubmatch(html, -1)
		if len(allMatches) > 0 {
			for _, m := range allMatches {
				if len(m) > 1 && m[1] == targetSlug {
					animeSaltSlugCache.Store(cacheKey, m[1])
					return m[1], nil
				}
			}
			firstSlug := allMatches[0][1]
			animeSaltSlugCache.Store(cacheKey, firstSlug)
			return firstSlug, nil
		}
	}

	// Direct slug fallback from cleanTitle if search yielded no hits
	if targetSlug != "" {
		animeSaltSlugCache.Store(cacheKey, targetSlug)
		return targetSlug, nil
	}

	return "", fmt.Errorf("no matching series found on AnimeSalt for: %s", title)
}

type AbyssAudioLink struct {
	Language string `json:"language"`
	Link     string `json:"link"`
}

type AbyssDatas struct {
	Slug   string `json:"slug"`
	Md5ID  int    `json:"md5_id"`
	UserID int    `json:"user_id"`
	Media  string `json:"media"`
}

type AbyssSource struct {
	Label    string `json:"label"`
	ResID    int    `json:"res_id"`
	Size     int64  `json:"size"`
	Codec    string `json:"codec"`
	Status   bool   `json:"status"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	PartSize int64  `json:"partSize"`
	Sub      string `json:"sub"`
}

type AbyssFristData struct {
	ResID    int    `json:"res_id"`
	Size     int64  `json:"size"`
	Codec    string `json:"codec"`
	URL      string `json:"url"`
	PartSize int64  `json:"partSize"`
}

type AbyssMedia struct {
	MP4 struct {
		Sources    []AbyssSource    `json:"sources"`
		Domains    []string         `json:"domains"`
		FristDatas []AbyssFristData `json:"fristDatas"`
	} `json:"mp4"`
}

func extractAnimeSaltStream(ctx context.Context, slug string, season int, ep int, hashDirect string, requestedLang string) (string, []SubtitleTrack, []AnimeSaltAudioOption, string, error) {
	if requestedLang == "" {
		requestedLang = "hin"
	}
	requestedLang = strings.ToLower(strings.TrimSpace(requestedLang))

	cacheKey := fmt.Sprintf("stream:%s:%d:%d:%s:%s", slug, season, ep, hashDirect, requestedLang)
	if val, ok := animeSaltStreamCache.Load(cacheKey); ok {
		entry := val.(AnimeSaltStreamCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry.ProxiedURL, entry.Tracks, entry.AudioOptions, entry.ResolvedSlug, nil
		}
	}

	selectedLink := ""
	var audioOptions []AnimeSaltAudioOption

	if slug != "" {
		if season <= 0 {
			season = 1
		}
		if ep <= 0 {
			ep = 1
		}

		var audioLinks []AbyssAudioLink
		audioLinksKey := fmt.Sprintf("%s:%d:%d", slug, season, ep)
		if val, ok := animeSaltAudioLinksCache.Load(audioLinksKey); ok {
			entry := val.(AnimeSaltAudioLinksCacheEntry)
			if time.Now().Before(entry.ExpiresAt) {
				audioLinks = entry.AudioLinks
			}
		}

		if len(audioLinks) == 0 {
			episodeReferer := fmt.Sprintf("https://animesalt.cx/episode/%s-%dx%d/", slug, season, ep)

			epReq, err := http.NewRequestWithContext(ctx, http.MethodGet, episodeReferer, nil)
			if err != nil {
				return "", nil, nil, "", err
			}
			epReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
			epReq.Header.Set("Referer", fmt.Sprintf("https://animesalt.cx/series/%s/", slug))

			epResp, err := animesaltHttpClient.Do(epReq)
			if err != nil {
				return "", nil, nil, "", err
			}
			defer epResp.Body.Close()

			if epResp.StatusCode != http.StatusOK {
				return "", nil, nil, "", fmt.Errorf("animesalt episode page returned %d", epResp.StatusCode)
			}

			bodyBytes, err := readResponseBody(epResp)
			if err != nil {
				return "", nil, nil, "", err
			}
			html := string(bodyBytes)

			reData := regexp.MustCompile(`multi-lang-plyr\.php\?data=([a-zA-Z0-9%_-]+)`)
			m := reData.FindStringSubmatch(html)
			if len(m) > 1 {
				unescapedData, _ := url.QueryUnescape(m[1])
				b64Dec, err := base64.StdEncoding.DecodeString(unescapedData)
				if err != nil {
					b64Dec, _ = base64.URLEncoding.DecodeString(unescapedData)
				}
				if err := json.Unmarshal(b64Dec, &audioLinks); err == nil && len(audioLinks) > 0 {
					animeSaltAudioLinksCache.Store(audioLinksKey, AnimeSaltAudioLinksCacheEntry{
						AudioLinks: audioLinks,
						ExpiresAt:  time.Now().Add(2 * time.Hour),
					})
				}
			}
		}

		if len(audioLinks) > 0 {
			for _, a := range audioLinks {
				lLower := strings.ToLower(a.Language)
				lCode := "sub"
				lLabel := a.Language
				if strings.Contains(lLower, "hindi") {
					lCode = "hin"
					lLabel = "Hindi (Default Dub)"
				} else if strings.Contains(lLower, "japan") {
					lCode = "sub"
					lLabel = "Japanese (Sub)"
				} else if strings.Contains(lLower, "english") {
					lCode = "dub"
					lLabel = "English (Dub)"
				} else if strings.Contains(lLower, "tamil") {
					lCode = "tam"
					lLabel = "Tamil"
				} else if strings.Contains(lLower, "telugu") {
					lCode = "tel"
					lLabel = "Telugu"
				} else if strings.Contains(lLower, "kannada") {
					lCode = "kan"
					lLabel = "Kannada"
				}
				audioOptions = append(audioOptions, AnimeSaltAudioOption{
					Label:    lLabel,
					Language: a.Language,
					LangCode: lCode,
				})

				if selectedLink == "" {
					if (requestedLang == "hin" && strings.Contains(lLower, "hindi")) ||
						((requestedLang == "sub" || requestedLang == "jpn") && strings.Contains(lLower, "japan")) ||
						((requestedLang == "dub" || requestedLang == "eng") && strings.Contains(lLower, "english")) ||
						(requestedLang == "tam" && strings.Contains(lLower, "tamil")) ||
						(requestedLang == "tel" && strings.Contains(lLower, "telugu")) ||
						(requestedLang == "kan" && strings.Contains(lLower, "kannada")) {
						selectedLink = a.Link
					}
				}
			}
			if selectedLink == "" && len(audioLinks) > 0 {
				selectedLink = audioLinks[0].Link
			}
		}
	}

	if selectedLink == "" && hashDirect != "" {
		if strings.HasPrefix(hashDirect, "http") {
			selectedLink = hashDirect
		} else {
			selectedLink = fmt.Sprintf("https://abyssplayer.com/%s", hashDirect)
		}
	}

	if selectedLink == "" {
		return "", nil, nil, "", fmt.Errorf("could not locate Server 1 AbyssPlayer link on episode page")
	}

	// Check if selectedLink Abyss stream metadata is already cached
	if val, ok := animeSaltStreamCache.Load(selectedLink); ok {
		entry := val.(AnimeSaltStreamCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			resEntry := AnimeSaltStreamCacheEntry{
				ProxiedURL:   entry.ProxiedURL,
				Tracks:       entry.Tracks,
				AudioOptions: audioOptions,
				ResolvedSlug: entry.ResolvedSlug,
				ExpiresAt:    entry.ExpiresAt,
			}
			animeSaltStreamCache.Store(cacheKey, resEntry)
			return entry.ProxiedURL, entry.Tracks, audioOptions, entry.ResolvedSlug, nil
		}
	}

	abyssReq, err := http.NewRequestWithContext(ctx, http.MethodGet, selectedLink, nil)
	if err != nil {
		return "", nil, nil, "", err
	}
	abyssReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	abyssReq.Header.Set("Referer", "https://animesalt.cx/")

	abyssResp, err := animesaltHttpClient.Do(abyssReq)
	if err != nil {
		return "", nil, nil, "", err
	}
	defer abyssResp.Body.Close()

	if abyssResp.StatusCode != http.StatusOK {
		return "", nil, nil, "", fmt.Errorf("abyssplayer returned %d", abyssResp.StatusCode)
	}

	abyssBytes, err := readResponseBody(abyssResp)
	if err != nil {
		return "", nil, nil, "", err
	}
	abyssHtml := string(abyssBytes)

	reDatas := regexp.MustCompile(`const datas = "([^"]+)"`)
	mDatas := reDatas.FindStringSubmatch(abyssHtml)
	if len(mDatas) < 2 {
		return "", nil, nil, "", fmt.Errorf("const datas payload not found in abyssplayer page")
	}

	datasRaw, err := base64.StdEncoding.DecodeString(mDatas[1])
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("failed base64 decoding datas: %w", err)
	}

	var utf8Buf strings.Builder
	for _, b := range datasRaw {
		utf8Buf.WriteRune(rune(b))
	}

	var datas AbyssDatas
	if err := json.Unmarshal([]byte(utf8Buf.String()), &datas); err != nil {
		return "", nil, nil, "", fmt.Errorf("failed unmarshaling datas metadata: %w", err)
	}

	keyStr := fmt.Sprintf("%d:%s:%d", datas.UserID, datas.Slug, datas.Md5ID)
	hKey := md5.Sum([]byte(keyStr))
	hexKey := hex.EncodeToString(hKey[:])
	keyBytes := []byte(hexKey)
	ivBytes := keyBytes[:16]

	mediaRunes := []rune(datas.Media)
	cipherMedia := make([]byte, len(mediaRunes))
	for i, r := range mediaRunes {
		cipherMedia[i] = byte(r)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", nil, nil, "", fmt.Errorf("failed creating cipher: %w", err)
	}
	ctr := cipher.NewCTR(block, ivBytes)
	decryptedMedia := make([]byte, len(cipherMedia))
	ctr.XORKeyStream(decryptedMedia, cipherMedia)

	var media AbyssMedia
	if err := json.Unmarshal(decryptedMedia, &media); err != nil {
		return "", nil, nil, "", fmt.Errorf("failed parsing decrypted media json: %w", err)
	}

	// 1. Check for Direct H.264 Source (Type A)
	var bestSource *AbyssSource
	for _, s := range media.MP4.Sources {
		if s.Codec == "av1" || !s.Status || s.Path == "" || s.URL == "" {
			continue
		}
		if bestSource == nil || s.ResID > bestSource.ResID {
			curr := s
			bestSource = &curr
		}
	}

	if bestSource != nil {
		parts := strings.Split(bestSource.Path, "/")
		filename := parts[len(parts)-1]
		streamToken, err := encryptToken(&TokenPayload{
			URL:    fmt.Sprintf("%s/%s", bestSource.URL, bestSource.Path),
			Ref:    "https://abyssplayer.com/",
			Key:    filename,
			Cipher: "abyss-ctr",
			Exp:    time.Now().Add(6 * time.Hour).Unix(),
		})
		if err != nil {
			return "", nil, nil, "", err
		}
		proxiedURL := "/p/" + streamToken + "/video.mp4"
		resEntry := AnimeSaltStreamCacheEntry{
			ProxiedURL:   proxiedURL,
			Tracks:       nil,
			AudioOptions: audioOptions,
			ResolvedSlug: datas.Slug,
			ExpiresAt:    time.Now().Add(2 * time.Hour),
		}
		animeSaltStreamCache.Store(cacheKey, resEntry)
		animeSaltStreamCache.Store(selectedLink, resEntry)
		return proxiedURL, nil, audioOptions, datas.Slug, nil
	}

	// 2. Check for Chunked FristData H.264 Source (Type B)
	var bestFD *AbyssFristData
	for _, fd := range media.MP4.FristDatas {
		if fd.Codec == "av1" || fd.URL == "" {
			continue
		}
		if bestFD == nil || fd.ResID > bestFD.ResID {
			curr := fd
			bestFD = &curr
		}
	}

	if bestFD != nil {
		domain := ""
		for _, s := range media.MP4.Sources {
			if s.ResID == bestFD.ResID && s.Sub != "" {
				domain = s.Sub + ".sssrr.org"
				break
			}
		}
		if domain == "" && len(media.MP4.Domains) > 0 {
			domain = media.MP4.Domains[0]
		}
		parts := strings.Split(bestFD.URL, "/")
		filename := parts[len(parts)-1]
		streamToken, err := encryptToken(&TokenPayload{
			URL:       bestFD.URL,
			Ref:       "https://abyssplayer.com/",
			Key:       filename,
			Cipher:    "abyss-chunked",
			TotalSize: bestFD.Size,
			PartSize:  bestFD.PartSize,
			ChunkSize: 5242880,
			Md5ID:     datas.Md5ID,
			ResID:     bestFD.ResID,
			Domain:    domain,
			Exp:       time.Now().Add(6 * time.Hour).Unix(),
		})
		if err != nil {
			return "", nil, nil, "", err
		}
		proxiedURL := "/p/" + streamToken + "/video.mp4"
		resEntry := AnimeSaltStreamCacheEntry{
			ProxiedURL:   proxiedURL,
			Tracks:       nil,
			AudioOptions: audioOptions,
			ResolvedSlug: datas.Slug,
			ExpiresAt:    time.Now().Add(2 * time.Hour),
		}
		animeSaltStreamCache.Store(cacheKey, resEntry)
		animeSaltStreamCache.Store(selectedLink, resEntry)
		return proxiedURL, nil, audioOptions, datas.Slug, nil
	}

	return "", nil, nil, "", fmt.Errorf("no valid H.264 stream found in Abyss response")
}

func extractAnimeSaltHLS(ctx context.Context, slug string, season int, ep int, hashDirect string) (string, []SubtitleTrack, string, error) {
	url, tracks, _, resolvedSlug, err := extractAnimeSaltStream(ctx, slug, season, ep, hashDirect, "hin")
	return url, tracks, resolvedSlug, err
}

func handleAnimeSaltEmbed(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !isEmbedAllowed(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Embedding not allowed: domain is not authorized to embed this player."))
		return
	}

	rawPath := r.URL.Path
	rawPath = strings.TrimPrefix(rawPath, "/embed/animesalt/")
	rawPath = strings.TrimPrefix(rawPath, "/embed/animesalt")
	rawPath = strings.TrimPrefix(rawPath, "/embed/as-cdn/")
	rawPath = strings.TrimPrefix(rawPath, "/embed/as-cdn")
	rawPath = strings.TrimPrefix(rawPath, "/")

	parts := strings.Split(rawPath, "/")
	slug := ""
	season := 1
	ep := 1
	lang := "hin"
	hash := ""
	anilistID := 0
	malID := 0

	if len(parts) >= 2 && parts[0] == "ani" {
		anilistID, _ = strconv.Atoi(parts[1])
		if len(parts) > 2 && parts[2] != "" {
			ep, _ = strconv.Atoi(parts[2])
		}
		if len(parts) > 3 && parts[3] != "" {
			lang = parts[3]
		}
		var err error
		slug, err = resolveAnimeSaltSlug(r.Context(), anilistID, 0, "")
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Failed to resolve AnimeSalt slug: %s"}`, err.Error()), http.StatusNotFound)
			return
		}
	} else if len(parts) >= 2 && parts[0] == "mal" {
		malID, _ = strconv.Atoi(parts[1])
		if len(parts) > 2 && parts[2] != "" {
			ep, _ = strconv.Atoi(parts[2])
		}
		if len(parts) > 3 && parts[3] != "" {
			lang = parts[3]
		}
		var err error
		slug, err = resolveAnimeSaltSlug(r.Context(), 0, malID, "")
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Failed to resolve AnimeSalt slug: %s"}`, err.Error()), http.StatusNotFound)
			return
		}
	} else if len(parts) >= 1 && (parts[0] == "video" || len(parts[0]) >= 24) {
		if parts[0] == "video" && len(parts) > 1 {
			hash = parts[1]
		} else {
			hash = parts[0]
		}
	} else if len(parts) >= 1 {
		epPart := parts[0]
		if parts[0] == "episode" && len(parts) > 1 {
			epPart = parts[1]
		}
		epRegex := regexp.MustCompile(`^(.*?)-(\d+)x(\d+)$`)
		if m := epRegex.FindStringSubmatch(epPart); len(m) > 3 {
			slug = m[1]
			season, _ = strconv.Atoi(m[2])
			ep, _ = strconv.Atoi(m[3])
		} else {
			slug = epPart
			if len(parts) > 1 && parts[1] != "" {
				ep, _ = strconv.Atoi(parts[1])
			}
			if len(parts) > 2 && parts[2] != "" {
				lang = parts[2]
			}
		}
	}

	if qEp := r.URL.Query().Get("ep"); qEp != "" {
		if e, err := strconv.Atoi(qEp); err == nil && e > 0 {
			ep = e
		}
	}
	if qSeason := r.URL.Query().Get("season"); qSeason != "" {
		if s, err := strconv.Atoi(qSeason); err == nil && s > 0 {
			season = s
		}
	}
	if qLang := r.URL.Query().Get("lang"); qLang != "" {
		lang = qLang
	}
	if ep <= 0 {
		ep = 1
	}
	if season <= 0 {
		season = 1
	}
	if lang == "" {
		lang = "hin"
	}

	frameAncestors := buildFrameAncestorsCSP(r.Host)
	cspHeader := fmt.Sprintf("default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors %s;", frameAncestors)

	cacheKey := fmt.Sprintf("animesalt:clean:%s:%d:%d:%s:%s", slug, season, ep, hash, lang)
	if val, ok := animeSaltCache.Load(cacheKey); ok {
		entry := val.(EmbedCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(entry.HTML))
			return
		}
	}

	var malIDForSub int
	if malID > 0 {
		malIDForSub = malID
	} else if anilistID > 0 {
		malIDForSub = resolveMalId(anilistID)
	}

	var subTracks []SubtitleTrack
	var subChan chan []SubtitleTrack
	if malIDForSub > 0 {
		subKey := fmt.Sprintf("%d:%d", malIDForSub, ep)
		if val, ok := animeSaltSubCache.Load(subKey); ok {
			entry := val.(AnimeSaltSubCacheEntry)
			if time.Now().Before(entry.ExpiresAt) {
				subTracks = entry.Tracks
			}
		}
		if subTracks == nil {
			subChan = make(chan []SubtitleTrack, 1)
			go func() {
				subCtx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
				defer cancel()
				_, mTracks, err := extractMegaplayHLS(subCtx, fmt.Sprintf("mal/%d/%d/sub", malIDForSub, ep))
				if err == nil && len(mTracks) > 0 {
					animeSaltSubCache.Store(subKey, AnimeSaltSubCacheEntry{
						Tracks:    mTracks,
						ExpiresAt: time.Now().Add(2 * time.Hour),
					})
					subChan <- mTracks
				} else {
					subChan <- nil
				}
			}()
		}
	}

	proxiedStreamURL, tracks, audioOpts, _, err := extractAnimeSaltStream(r.Context(), slug, season, ep, hash, lang)
	if err == nil && proxiedStreamURL != "" {
		// Backfill subtitles from MegaPlay if Server 1 does not provide .vtt tracks directly
		if len(tracks) == 0 {
			if len(subTracks) > 0 {
				tracks = subTracks
			} else if subChan != nil {
				select {
				case t := <-subChan:
					if len(t) > 0 {
						tracks = t
					}
				case <-time.After(200 * time.Millisecond):
				}
			}
		}

		var proxiedTracks []SubtitleTrack
		for _, t := range tracks {
			if t.File != "" {
				subToken, subErr := encryptToken(&TokenPayload{
					URL: t.File,
					Ref: "https://megaplay.buzz/",
					Exp: time.Now().Add(6 * time.Hour).Unix(),
				})
				if subErr == nil {
					t.File = "/p/" + subToken
				}
			}
			proxiedTracks = append(proxiedTracks, t)
		}

		html := renderCleanArtplayer(proxiedStreamURL, proxiedTracks, lang, fmt.Sprintf("animesalt_%s_%d_%d", slug, season, ep), audioOpts...)

		animeSaltCache.Store(cacheKey, EmbedCacheEntry{
			HTML:      html,
			ExpiresAt: time.Now().Add(2 * time.Hour),
		})

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(html))
			return
		}

	errorHTML := renderCustomProxy404(rawPath, "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(errorHTML))
}

func handleCustomSaltPlayer(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	slug := q.Get("slug")
	season := q.Get("season")
	if season == "" {
		season = "1"
	}
	ep := q.Get("ep")
	if ep == "" {
		ep = "1"
	}
	lang := q.Get("lang")
	if lang == "" {
		lang = "hin"
	}
	anilist := q.Get("anilist")
	mal := q.Get("mal")
	hash := q.Get("hash")

	if anilist != "" {
		r.URL.Path = fmt.Sprintf("/embed/animesalt/ani/%s/%s/%s", anilist, ep, lang)
	} else if mal != "" {
		r.URL.Path = fmt.Sprintf("/embed/animesalt/mal/%s/%s/%s", mal, ep, lang)
	} else if hash != "" {
		r.URL.Path = fmt.Sprintf("/embed/as-cdn/%s", hash)
	} else if slug != "" {
		r.URL.Path = fmt.Sprintf("/embed/animesalt/%s-%sx%s", slug, season, ep)
	}
	handleAnimeSaltEmbed(w, r)
}

func handleAnimeSaltSourceAPI(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	q := r.URL.Query()
	slug := q.Get("slug")
	seasonStr := q.Get("season")
	epStr := q.Get("ep")
	hash := q.Get("hash")
	anilistStr := q.Get("anilist")
	malStr := q.Get("mal")

	season := 1
	if s, err := strconv.Atoi(seasonStr); err == nil && s > 0 {
		season = s
	}
	ep := 1
	if e, err := strconv.Atoi(epStr); err == nil && e > 0 {
		ep = e
	}

	if slug == "" && anilistStr != "" {
		if aId, err := strconv.Atoi(anilistStr); err == nil && aId > 0 {
			slug, _ = resolveAnimeSaltSlug(r.Context(), aId, 0, "")
		}
	}
	if slug == "" && malStr != "" {
		if mId, err := strconv.Atoi(malStr); err == nil && mId > 0 {
			slug, _ = resolveAnimeSaltSlug(r.Context(), 0, mId, "")
		}
	}

	lang := q.Get("lang")
	if lang == "" {
		lang = "hin"
	}

	var malIDForSub int
	if malStr != "" {
		malIDForSub, _ = strconv.Atoi(malStr)
	} else if anilistStr != "" {
		if aId, err := strconv.Atoi(anilistStr); err == nil && aId > 0 {
			malIDForSub = resolveMalId(aId)
		}
	}

	var subTracks []SubtitleTrack
	if malIDForSub > 0 {
		subKey := fmt.Sprintf("%d:%d", malIDForSub, ep)
		if val, ok := animeSaltSubCache.Load(subKey); ok {
			entry := val.(AnimeSaltSubCacheEntry)
			if time.Now().Before(entry.ExpiresAt) {
				subTracks = entry.Tracks
			}
		}
	}

	proxiedStreamURL, tracks, audioOpts, resolvedSlug, err := extractAnimeSaltStream(r.Context(), slug, season, ep, hash, lang)
	if err != nil || proxiedStreamURL == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   true,
			"message": err.Error(),
		})
		return
	}

	if len(tracks) == 0 && len(subTracks) > 0 {
		tracks = subTracks
	}

	var proxiedTracks []SubtitleTrack
	for _, t := range tracks {
		if t.File != "" {
			subToken, subErr := encryptToken(&TokenPayload{
				URL: t.File,
				Ref: "https://animesalt.cx/",
				Exp: time.Now().Add(6 * time.Hour).Unix(),
			})
			if subErr == nil {
				t.File = "/p/" + subToken
			}
		}
		proxiedTracks = append(proxiedTracks, t)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=1800")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"server":        "AnimeSalt Server 1 (Abyss)",
		"slug":          slug,
		"resolved_slug": resolvedSlug,
		"season":        season,
		"episode":       ep,
		"stream_url":    proxiedStreamURL,
		"type":          "mp4",
		"subtitles":     proxiedTracks,
		"default_audio": lang,
		"audio_options": audioOpts,
	})
}

// --- Zoko Server (zokoanime.video) Scraper & Clean Embed Handlers ---

type ZokoSubtitle struct {
	Lang    string `json:"lang"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
	Src     string `json:"src"`
}

type ZokoSkipTime struct {
	Start float64 `json:"start"`
	End   float64 `json:"end"`
}

type ZokoSkip struct {
	Intro *ZokoSkipTime `json:"intro,omitempty"`
	Outro *ZokoSkipTime `json:"outro,omitempty"`
}

type ZokoData struct {
	Src         string         `json:"src"`
	Subtitles   []ZokoSubtitle `json:"subtitles"`
	Skip        *ZokoSkip      `json:"skip,omitempty"`
	DownloadURL string         `json:"download_url,omitempty"`
}

const zokoObfKey = "otaku-embed-v1"

var (
	zokoCache  sync.Map
	zokoPRegex = regexp.MustCompile(`window\.__P\s*=\s*"([^"]+)"`)
)

func deobfuscateZokoPayload(blob string) (*ZokoData, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	for i := 0; i < len(raw); i++ {
		raw[i] ^= zokoObfKey[i%len(zokoObfKey)]
	}

	unescaped, err := url.QueryUnescape(string(raw))
	if err != nil {
		return nil, fmt.Errorf("url unescape error: %w", err)
	}

	var data ZokoData
	if err := json.Unmarshal([]byte(unescaped), &data); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}

	return &data, nil
}

func extractZokoHLS(ctx context.Context, malID int, ep int, track string) (string, []SubtitleTrack, *ZokoSkip, error) {
	if track != "dub" && track != "sub" {
		track = "sub"
	}
	if ep <= 0 {
		ep = 1
	}
	if malID <= 0 {
		return "", nil, nil, fmt.Errorf("invalid mal_id: %d", malID)
	}

	cacheKey := fmt.Sprintf("%d:%d:%s", malID, ep, track)
	if val, ok := zokoStreamCache.Load(cacheKey); ok {
		entry := val.(ZokoStreamCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			return entry.StreamFile, entry.Tracks, entry.Skip, nil
		}
	}

	targetURL := fmt.Sprintf("https://zokoanime.video/stream/mal/%d/%d/%s", malID, ep, track)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://zokoanime.video/")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := zokoHttpClient.Do(req)
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, nil, fmt.Errorf("zoko upstream returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, nil, err
	}

	m := zokoPRegex.FindSubmatch(body)
	if len(m) < 2 {
		return "", nil, nil, fmt.Errorf("zoko __P payload not found in upstream HTML")
	}

	data, err := deobfuscateZokoPayload(string(m[1]))
	if err != nil {
		return "", nil, nil, err
	}

	if data.Src == "" {
		return "", nil, nil, fmt.Errorf("zoko returned empty stream src")
	}

	var tracks []SubtitleTrack
	for _, sub := range data.Subtitles {
		if sub.Src != "" {
			label := sub.Label
			if label == "" {
				label = strings.ToUpper(sub.Lang)
			}
			tracks = append(tracks, SubtitleTrack{
				File:    sub.Src,
				Label:   label,
				Kind:    "captions",
				Default: sub.Default,
			})
		}
	}

	zokoStreamCache.Store(cacheKey, ZokoStreamCacheEntry{
		StreamFile: data.Src,
		Tracks:     tracks,
		Skip:       data.Skip,
		ExpiresAt:  time.Now().Add(3 * time.Hour),
	})

	return data.Src, tracks, data.Skip, nil
}

func handleZokoEmbed(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !isEmbedAllowed(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Embedding not allowed: domain is not authorized to embed this player."))
		return
	}

	rawPath := r.URL.Path
	rawPath = strings.TrimPrefix(rawPath, "/embed/zoko/")
	rawPath = strings.TrimPrefix(rawPath, "/embed/zoko")
	rawPath = strings.TrimPrefix(rawPath, "/player/zoko/")
	rawPath = strings.TrimPrefix(rawPath, "/player/zoko")
	rawPath = strings.TrimPrefix(rawPath, "/")

	parts := strings.Split(rawPath, "/")
	malID := 0
	anilistID := 0
	ep := 1
	lang := "sub"

	// 1. Check query parameters
	q := r.URL.Query()
	if m := q.Get("mal"); m != "" {
		malID, _ = strconv.Atoi(m)
	}
	if a := q.Get("ani"); a != "" {
		anilistID, _ = strconv.Atoi(a)
	}
	if e := q.Get("ep"); e != "" {
		if epVal, err := strconv.Atoi(e); err == nil && epVal > 0 {
			ep = epVal
		}
	}
	if l := q.Get("lang"); l != "" {
		lang = strings.ToLower(l)
	}

	// 2. Parse URL path if not fully provided via query
	if malID == 0 && anilistID == 0 {
		if len(parts) >= 2 && parts[0] == "ani" {
			anilistID, _ = strconv.Atoi(parts[1])
			if len(parts) > 2 && parts[2] != "" {
				ep, _ = strconv.Atoi(parts[2])
			}
			if len(parts) > 3 && parts[3] != "" {
				lang = parts[3]
			}
		} else if len(parts) >= 2 && parts[0] == "mal" {
			malID, _ = strconv.Atoi(parts[1])
			if len(parts) > 2 && parts[2] != "" {
				ep, _ = strconv.Atoi(parts[2])
			}
			if len(parts) > 3 && parts[3] != "" {
				lang = parts[3]
			}
		} else if len(parts) >= 1 && parts[0] != "" {
			if id, err := strconv.Atoi(parts[0]); err == nil && id > 0 {
				malID = id
				if len(parts) > 1 && parts[1] != "" {
					ep, _ = strconv.Atoi(parts[1])
				}
				if len(parts) > 2 && parts[2] != "" {
					lang = parts[2]
				}
			}
		}
	}

	if lang != "dub" && lang != "sub" {
		lang = "sub"
	}
	if ep <= 0 {
		ep = 1
	}

	// Resolve AniList ID to MAL ID if necessary
	if malID == 0 && anilistID > 0 {
		malID = resolveMalId(anilistID)
	}

	host := r.Host
	if host == "" {
		host = "yume-proxy-railway-production.up.railway.app"
	}
	frameAncestors := buildFrameAncestorsCSP(host)
	cspHeader := fmt.Sprintf("default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors %s;", frameAncestors)

	if malID <= 0 {
		errorHTML := renderCustomProxy404(r.URL.Path, "Invalid Anime ID. Please specify a valid MyAnimeList or AniList ID.")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(errorHTML))
		return
	}

	cacheKey := fmt.Sprintf("zoko_%d_%d_%s", malID, ep, lang)
	if val, ok := zokoCache.Load(cacheKey); ok {
		entry := val.(EmbedCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(entry.HTML))
			return
		}
	}

	streamFile, tracks, _, err := extractZokoHLS(r.Context(), malID, ep, lang)
	if err == nil && streamFile != "" {
		var proxiedTracks []SubtitleTrack
		for _, t := range tracks {
			if t.File != "" {
				subToken, subErr := encryptToken(&TokenPayload{
					URL: t.File,
					Ref: "https://zokoanime.video/",
					Exp: time.Now().Add(6 * time.Hour).Unix(),
				})
				if subErr == nil {
					t.File = "/p/" + subToken
				}
			}
			proxiedTracks = append(proxiedTracks, t)
		}

		streamToken, err := encryptToken(&TokenPayload{
			URL: streamFile,
			Ref: "https://zokoanime.video/",
			Exp: time.Now().Add(6 * time.Hour).Unix(),
		})
		if err == nil {
			proxiedStreamURL := "/p/" + streamToken
			html := renderCleanArtplayer(proxiedStreamURL, proxiedTracks, lang, fmt.Sprintf("zoko_%d_%d", malID, ep))

			zokoCache.Store(cacheKey, EmbedCacheEntry{
				HTML:      html,
				ExpiresAt: time.Now().Add(2 * time.Hour),
			})

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", cspHeader)
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(html))
			return
		}
	}

	errorHTML := renderCustomProxy404(r.URL.Path, "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(errorHTML))
}

func handleZokoSourceAPI(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	q := r.URL.Query()
	malID := 0
	anilistID := 0
	ep := 1
	lang := "sub"

	if m := q.Get("mal"); m != "" {
		malID, _ = strconv.Atoi(m)
	}
	if a := q.Get("ani"); a != "" {
		anilistID, _ = strconv.Atoi(a)
	}
	if e := q.Get("ep"); e != "" {
		if epVal, err := strconv.Atoi(e); err == nil && epVal > 0 {
			ep = epVal
		}
	}
	if l := q.Get("lang"); l != "" {
		lang = strings.ToLower(l)
	}

	if malID == 0 && anilistID > 0 {
		malID = resolveMalId(anilistID)
	}

	if malID <= 0 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   true,
			"message": "Invalid mal or ani parameter",
		})
		return
	}

	streamFile, tracks, skip, err := extractZokoHLS(r.Context(), malID, ep, lang)
	if err != nil || streamFile == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		msg := "Stream not found"
		if err != nil {
			msg = err.Error()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   true,
			"message": msg,
		})
		return
	}

	streamToken, _ := encryptToken(&TokenPayload{
		URL: streamFile,
		Ref: "https://zokoanime.video/",
		Exp: time.Now().Add(6 * time.Hour).Unix(),
	})

	var proxiedTracks []SubtitleTrack
	for _, t := range tracks {
		if t.File != "" {
			subToken, subErr := encryptToken(&TokenPayload{
				URL: t.File,
				Ref: "https://zokoanime.video/",
				Exp: time.Now().Add(6 * time.Hour).Unix(),
			})
			if subErr == nil {
				t.File = "/p/" + subToken
			}
		}
		proxiedTracks = append(proxiedTracks, t)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=1800")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"server":       "Zoko (zokoanime.video)",
		"mal_id":       malID,
		"anilist_id":   anilistID,
		"episode":      ep,
		"language":     lang,
		"stream_url":   streamFile,
		"proxied_m3u8": "/p/" + streamToken,
		"subtitles":    proxiedTracks,
		"skip":         skip,
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(fmt.Appendf(nil, `{"ok":true,"service":"yumezone-proxy-railway","version":"2.0.0","ts":%d}`, time.Now().UnixMilli()))
}

func handleDocs(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Check if client explicitly requests JSON health info (e.g. uptime monitors)
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") && r.URL.Path != "/docs" && r.URL.Path != "/api" {
		handleHealth(w, r)
		return
	}

	host := r.Host
	if host == "" {
		host = "yume-proxy-railway-production.up.railway.app"
	}

	scheme := "https"
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		scheme = "http"
	}

	frameAncestors := buildFrameAncestorsCSP(host)
	cspHeader := fmt.Sprintf("default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors %s;", frameAncestors)

	html := renderEmbedDocsHTML(scheme, host)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Del("X-Frame-Options")
	w.Header().Del("Cross-Origin-Opener-Policy")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func renderEmbedDocsHTML(scheme string, host string) string {
	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	html := docsHTMLTemplate
	html = strings.ReplaceAll(html, "{{BASE_URL}}", baseURL)
	html = strings.ReplaceAll(html, "{{HOST}}", host)
	return html
}

const docsHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>YumeZone Embed & Stream Proxy API — MegaPlay, AnimeSalt & Zoko</title>
    <meta name="description" content="Dedicated high-performance Go reverse proxy and ad-free embed sanitizer for MegaPlay, AnimeSalt Server 1, and Zoko (zokoanime.video). Features multi-audio switching, MyAnimeList & AniList resolution, HLS stream proxying, and custom OLED video player.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        :root {
            --bg: #000000;
            --bg-elevated: #050508;
            --bg-card: rgba(8, 8, 12, 0.88);
            --border: rgba(255, 255, 255, 0.08);
            --border-glow: rgba(99, 102, 241, 0.35);
            --text-main: #ffffff;
            --text-muted: #8e95a5;
            --accent: #6366f1;
            --accent-soft: #a5b4fc;
            --accent-dim: rgba(99, 102, 241, 0.12);
            --accent-glow: rgba(99, 102, 241, 0.28);
            --emerald: #10b981;
            --emerald-dim: rgba(16, 185, 129, 0.12);
            --mono: "JetBrains Mono", ui-monospace, monospace;
            --sans: "Plus Jakarta Sans", ui-sans-serif, system-ui, -apple-system, sans-serif;
            --radius-sm: 8px;
            --radius-md: 14px;
            --radius-lg: 20px;
            --shadow: 0 24px 60px rgba(0, 0, 0, 0.85);
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            font-family: var(--sans);
            background: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            background-image:
                radial-gradient(ellipse 850px 450px at 15% -10%, rgba(99, 102, 241, 0.2), transparent 60%),
                radial-gradient(ellipse 650px 400px at 90% 15%, rgba(139, 92, 246, 0.12), transparent 55%),
                radial-gradient(ellipse 800px 500px at 50% 120%, rgba(99, 102, 241, 0.06), transparent 50%);
            background-attachment: fixed;
        }

        a {
            color: var(--accent-soft);
            text-decoration: none;
            transition: color 0.15s ease;
        }

        a:hover {
            color: #ffffff;
            text-decoration: underline;
        }

        /* Top Navigation Strip */
        .doc-navbar {
            position: sticky;
            top: 0;
            z-index: 100;
            background: rgba(0, 0, 0, 0.88);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
        }

        .doc-nav-container {
            max-width: 1240px;
            margin: 0 auto;
            padding: 0.85rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
        }

        .doc-brand {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            font-size: 1.1rem;
            font-weight: 800;
            color: #ffffff;
            letter-spacing: -0.02em;
            text-decoration: none;
        }

        .doc-brand-icon {
            width: 32px;
            height: 32px;
            border-radius: 9px;
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-size: 0.95rem;
            box-shadow: 0 0 16px var(--accent-glow);
        }

        .doc-brand span {
            background: linear-gradient(135deg, #ffffff 30%, var(--accent-soft) 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .doc-nav-links {
            display: flex;
            align-items: center;
            gap: 1.25rem;
            list-style: none;
        }

        .doc-nav-links a {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-muted);
            transition: all 0.15s ease;
        }

        .doc-nav-links a:hover {
            color: #ffffff;
            text-decoration: none;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.35rem 0.85rem;
            background: var(--emerald-dim);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--emerald);
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            background: var(--emerald);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--emerald);
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.8); }
        }

        /* Hero Section */
        .doc-hero-section {
            max-width: 1240px;
            margin: 0 auto;
            padding: 2.5rem 1.5rem 1.25rem;
        }

        .doc-hero-card {
            position: relative;
            background: linear-gradient(155deg, rgba(12, 12, 18, 0.95), rgba(4, 4, 6, 0.98));
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 2.5rem 2.25rem;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .doc-hero-card::before {
            content: "";
            position: absolute;
            top: -50%;
            left: -20%;
            width: 80%;
            height: 150%;
            background: radial-gradient(circle, rgba(99, 102, 241, 0.14), transparent 60%);
            pointer-events: none;
        }

        .hero-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.75rem;
            font-weight: 800;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--accent-soft);
            background: var(--accent-dim);
            border: 1px solid rgba(162, 155, 254, 0.25);
            padding: 0.35rem 0.85rem;
            border-radius: 999px;
            margin-bottom: 1.15rem;
        }

        .doc-hero-card h1 {
            font-size: clamp(1.9rem, 4vw, 2.75rem);
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.18;
            margin-bottom: 0.85rem;
            background: linear-gradient(110deg, #ffffff 0%, #e2e8f0 45%, var(--accent-soft) 100%);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .doc-hero-lead {
            font-size: 1rem;
            color: var(--text-muted);
            max-width: 44rem;
            line-height: 1.68;
            margin-bottom: 1.5rem;
        }

        .hero-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 0.85rem;
            margin-bottom: 1.75rem;
        }

        .btn-primary {
            display: inline-flex;
            align-items: center;
            gap: 0.55rem;
            padding: 0.7rem 1.35rem;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            color: #ffffff;
            font-weight: 700;
            font-size: 0.875rem;
            border-radius: var(--radius-sm);
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 18px var(--accent-glow);
            transition: all 0.2s ease;
            text-decoration: none;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.45);
            color: #ffffff;
            text-decoration: none;
        }

        .btn-secondary {
            display: inline-flex;
            align-items: center;
            gap: 0.55rem;
            padding: 0.7rem 1.25rem;
            background: rgba(255, 255, 255, 0.04);
            color: var(--accent-soft);
            font-weight: 600;
            font-size: 0.875rem;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
        }

        .btn-secondary:hover {
            background: var(--accent-dim);
            border-color: var(--border-glow);
            color: #ffffff;
            text-decoration: none;
        }

        .hero-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 1rem;
            padding-top: 1.25rem;
            border-top: 1px solid var(--border);
        }

        .metric-box {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .metric-icon {
            width: 34px;
            height: 34px;
            border-radius: 8px;
            background: rgba(99, 102, 241, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--accent-soft);
            font-size: 0.9rem;
            flex-shrink: 0;
        }

        .metric-info h4 {
            font-size: 0.85rem;
            font-weight: 700;
            color: var(--text-main);
        }

        .metric-info p {
            font-size: 0.725rem;
            color: var(--text-muted);
        }

        /* Shell & Grid Layout */
        .doc-shell {
            max-width: 1240px;
            margin: 0 auto;
            padding: 1.25rem 1.5rem 4rem;
        }

        .doc-layout {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 420px;
            gap: 2rem;
            align-items: start;
        }

        @media (max-width: 1080px) {
            .doc-layout {
                grid-template-columns: 1fr;
            }
            .doc-nav-links {
                display: none;
            }
        }

        /* Editorial Main Content */
        .doc-content {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .doc-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 1.6rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.55);
            transition: border-color 0.2s ease;
        }

        .doc-card:hover {
            border-color: var(--border-glow);
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.85rem;
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 800;
            color: var(--accent-soft);
            display: flex;
            align-items: center;
            gap: 0.6rem;
            letter-spacing: -0.015em;
        }

        .card-title i {
            color: var(--accent);
        }

        .doc-card p {
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
            line-height: 1.65;
        }

        .doc-card h3 {
            font-size: 0.925rem;
            font-weight: 700;
            color: var(--text-main);
            margin: 1.25rem 0 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.45rem;
        }

        /* Endpoint Spec Panel */
        .ep-badge-row {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            margin-bottom: 0.65rem;
        }

        .method-badge {
            font-family: var(--mono);
            font-size: 0.7rem;
            font-weight: 800;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            background: var(--emerald-dim);
            border: 1px solid rgba(16, 185, 129, 0.35);
            color: var(--emerald);
            text-transform: uppercase;
        }

        .ep-path {
            font-family: var(--mono);
            font-size: 0.825rem;
            font-weight: 600;
            color: #ffffff;
            background: #000000;
            padding: 0.3rem 0.65rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            word-break: break-all;
        }

        /* Code Blocks & Pre */
        .code-box {
            position: relative;
            background: #020204;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 0.85rem 1rem;
            margin: 0.75rem 0;
            overflow-x: auto;
        }

        .code-box pre {
            font-family: var(--mono);
            font-size: 0.78rem;
            color: #c4b5fd;
            line-height: 1.55;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .btn-copy-code {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 6px;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .btn-copy-code:hover {
            color: #ffffff;
            background: var(--accent-dim);
            border-color: var(--border-glow);
        }

        /* Parameter Tables */
        .param-table-wrap {
            overflow-x: auto;
            margin: 0.85rem 0;
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
        }

        .param-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.825rem;
            text-align: left;
        }

        .param-table th {
            background: rgba(99, 102, 241, 0.12);
            color: var(--accent-soft);
            font-weight: 700;
            padding: 0.65rem 0.95rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        .param-table td {
            padding: 0.65rem 0.95rem;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
        }

        .param-table tr:last-child td {
            border-bottom: none;
        }

        .param-table td:first-child {
            font-family: var(--mono);
            color: #c084fc;
            font-weight: 600;
        }

        .req-tag {
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--emerald);
            text-transform: uppercase;
        }

        /* Sticky Interactive Tester Rail */
        .doc-rail {
            position: sticky;
            top: 76px;
        }

        .tester-card {
            background: linear-gradient(165deg, rgba(12, 12, 18, 0.95), rgba(4, 4, 6, 0.98));
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            box-shadow: var(--shadow);
        }

        .tester-title {
            font-size: 1.1rem;
            font-weight: 800;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.35rem;
        }

        .tester-sub {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 1.15rem;
            line-height: 1.5;
        }

        .form-group {
            margin-bottom: 0.85rem;
        }

        .form-group label {
            display: block;
            font-size: 0.7rem;
            font-weight: 800;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 0.35rem;
        }

        .form-input, .form-select {
            width: 100%;
            background: #020204;
            border: 1px solid var(--border);
            color: #ffffff;
            border-radius: 8px;
            padding: 0.65rem 0.85rem;
            font-family: var(--sans);
            font-size: 0.85rem;
            font-weight: 500;
            outline: none;
            transition: all 0.15s ease;
        }

        .form-input:focus, .form-select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 2px var(--accent-dim);
        }

        .form-select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23a5b4fc' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 0.85rem center;
            padding-right: 2.2rem;
            cursor: pointer;
        }

        .tester-btn-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.65rem;
            margin-top: 1rem;
        }

        .tester-out {
            display: none;
            margin-top: 1.15rem;
            padding-top: 1.15rem;
            border-top: 1px solid var(--border);
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .tester-preview-box {
            margin-top: 0.85rem;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border);
            background: #000000;
            aspect-ratio: 16 / 9;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.9);
        }

        .tester-preview-box iframe {
            width: 100%;
            height: 100%;
            border: none;
            display: block;
        }

        /* Footer */
        .doc-footer {
            border-top: 1px solid var(--border);
            background: #000000;
            padding: 2rem 1.5rem;
            margin-top: 3.5rem;
        }

        .footer-inner {
            max-width: 1240px;
            margin: 0 auto;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .footer-links {
            display: flex;
            gap: 1.25rem;
        }
    </style>
</head>
<body>
    <!-- Top Navigation Strip -->
    <header class="doc-navbar">
        <div class="doc-nav-container">
            <a href="/" class="doc-brand">
                <div class="doc-brand-icon"><i class="fas fa-play"></i></div>
                <div>YumeZone <span>Stream Proxy API</span></div>
            </a>
            <ul class="doc-nav-links">
                <li><a href="#overview">Overview</a></li>
                <li><a href="#endpoints">Endpoints</a></li>
                <li><a href="#guide">Integration</a></li>
                <li><a href="#events">Player Events</a></li>
                <li><a href="#test-embed">Live Tester</a></li>
            </ul>
            <a href="/health" target="_blank" class="status-badge">
                <span class="status-dot"></span>
                Proxy Active
            </a>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="doc-hero-section" id="overview">
        <div class="doc-hero-card">
            <div class="hero-chip"><i class="fas fa-shield-halved"></i> Dedicated MegaPlay, AnimeSalt & Zoko Proxy</div>
            <h1>YumeZone Video Embed & Stream Proxy API</h1>
            <p class="doc-hero-lead">
                A high-performance reverse proxy and player sanitizer for <strong>MegaPlay</strong>, <strong>AnimeSalt Server 1</strong>, and <strong>Zoko (zokoanime.video)</strong>. Extracts clean streams, proxies M3U8 video chunks with automated CDN referer spoofing and permissive CORS, and renders a 100% ad-free OLED video player with MyAnimeList & AniList catalog mapping.
            </p>
            <div class="hero-actions">
                <a href="#test-embed" class="btn-primary"><i class="fas fa-play-circle"></i> Test In Sandbox</a>
                <a href="#endpoints" class="btn-secondary"><i class="fas fa-code"></i> Endpoints List</a>
                <a href="#guide" class="btn-secondary"><i class="fas fa-book-open"></i> Integration Code</a>
            </div>
            <div class="hero-metrics">
                <div class="metric-box">
                    <div class="metric-icon"><i class="fas fa-ban"></i></div>
                    <div class="metric-info">
                        <h4>Zero Popups</h4>
                        <p>Strips ad scripts & trackers</p>
                    </div>
                </div>
                <div class="metric-box">
                    <div class="metric-icon"><i class="fas fa-lock"></i></div>
                    <div class="metric-info">
                        <h4>AES-GCM Proxy</h4>
                        <p>Encrypted <code>/p/{token}</code> streaming</p>
                    </div>
                </div>
                <div class="metric-box">
                    <div class="metric-icon"><i class="fas fa-arrows-split-up-and-left"></i></div>
                    <div class="metric-info">
                        <h4>Referer Spoofing</h4>
                        <p>Bypasses CDN hotlink locks</p>
                    </div>
                </div>
                <div class="metric-box">
                    <div class="metric-icon"><i class="fas fa-id-badge"></i></div>
                    <div class="metric-info">
                        <h4>AniList to MAL</h4>
                        <p>Auto-translates catalog IDs</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Main Content & Live Tester Layout -->
    <div class="doc-shell">
        <div class="doc-layout">
            <!-- Main Editorial Column -->
            <main class="doc-content">
                <!-- Endpoints Specification -->
                <div class="doc-card" id="endpoints">
                    <div class="card-header">
                        <h2 class="card-title"><i class="fas fa-server"></i> API Endpoints</h2>
                    </div>
                    <p>All proxy and embed routes available on this service:</p>

                    <!-- Endpoint 1: MAL Embed -->
                    <h3><i class="fas fa-play"></i> 1. MyAnimeList (MAL) Embed Player (MegaPlay)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/megaplay/mal/{mal_id}/{ep_num}/{language}</span>
                    </div>
                    <p>Embeds MegaPlay video stream using MyAnimeList ID with our clean player.</p>
                    <div class="param-table-wrap">
                        <table class="param-table">
                            <thead>
                                <tr>
                                    <th>Parameter</th>
                                    <th>Type</th>
                                    <th>Required</th>
                                    <th>Description</th>
                                    <th>Example</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>mal_id</td>
                                    <td>Integer</td>
                                    <td><span class="req-tag">Yes</span></td>
                                    <td>MyAnimeList anime ID</td>
                                    <td><code>5114</code> (FMA:B), <code>21</code> (One Piece), <code>52991</code> (Frieren)</td>
                                </tr>
                                <tr>
                                    <td>ep_num</td>
                                    <td>Integer</td>
                                    <td><span class="req-tag">Yes</span></td>
                                    <td>Episode number</td>
                                    <td><code>1</code>, <code>2</code>, <code>12</code></td>
                                </tr>
                                <tr>
                                    <td>language</td>
                                    <td>String</td>
                                    <td><span class="req-tag">Yes</span></td>
                                    <td>Audio track (sub or dub)</td>
                                    <td><code>sub</code> / <code>dub</code></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <!-- Endpoint 2: AnimeSalt Server 1 Embed (Hindi Dub Default) -->
                    <h3><i class="fas fa-language"></i> 2. AnimeSalt Server 1 Embed (Hindi Dub / Multi-Audio)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/animesalt/{slug}-{season}x{ep}?lang={hin|sub|dub}</span>
                    </div>
                    <div class="ep-badge-row" style="margin-top: 0.35rem;">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/animesalt/ani/{anilist_id}/{ep}/{lang}</span>
                    </div>
                    <p>Scrapes Server 1 (<code>as-cdn26.top</code>), extracts the multi-audio HLS master playlist, and plays <strong>Hindi Dub</strong> by default (with an in-player audio switcher for Japanese/English/Tamil/Telugu).</p>
                    <div class="code-box">
                        <button class="btn-copy-code" onclick="copySnippet(this)"><i class="far fa-copy"></i></button>
                        <pre>&lt;iframe src="{{BASE_URL}}/embed/animesalt/dan-da-dan-1x1?lang=hin" width="100%" height="100%" frameborder="0" scrolling="no" allowfullscreen&gt;&lt;/iframe&gt;</pre>
                    </div>

                    <!-- Endpoint 3: AnimeSalt JSON Stream API -->
                    <h3><i class="fas fa-bolt"></i> 3. AnimeSalt Direct Stream Source API (JSON)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/api/animesalt/source?slug={slug}&season={s}&ep={e}</span>
                    </div>
                    <p>Returns raw decrypted stream URL, proxied M3U8 endpoint, audio renditions, and subtitle tracks formatted as clean JSON.</p>

                    <!-- Endpoint 4: Zoko Server Embed -->
                    <h3><i class="fas fa-shield-halved"></i> 4. Zoko Server Embed Player (zokoanime.video)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/zoko/mal/{mal_id}/{ep}/{lang}</span>
                    </div>
                    <div class="ep-badge-row" style="margin-top: 0.35rem;">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/zoko/ani/{anilist_id}/{ep}/{lang}</span>
                    </div>
                    <p>Scrapes and decrypts <code>zokoanime.video</code> HLS streams, proxies M3U8 manifests and video segments with automatic referer spoofing, and renders in our clean OLED player with VTT subtitles.</p>
                    <div class="code-box">
                        <button class="btn-copy-code" onclick="copySnippet(this)"><i class="far fa-copy"></i></button>
                        <pre>&lt;iframe src="{{BASE_URL}}/embed/zoko/mal/21/1/sub" width="100%" height="100%" frameborder="0" scrolling="no" allowfullscreen&gt;&lt;/iframe&gt;</pre>
                    </div>

                    <!-- Endpoint 5: Zoko JSON Stream API -->
                    <h3><i class="fas fa-code-merge"></i> 5. Zoko Direct Stream Source API (JSON)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/api/zoko/source?mal={mal_id}&ani={anilist_id}&ep={ep}&lang={sub|dub}</span>
                    </div>
                    <p>Returns decrypted stream URL, proxied M3U8 link, VTT subtitles, and intro/outro skip timestamps as JSON for external players or mobile apps.</p>

                    <!-- Endpoint 4: AniList Embed -->
                    <h3><i class="fas fa-shuffle"></i> 4. AniList Embed Player (MegaPlay Auto-Mapped to MAL)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/megaplay/ani/{anilist_id}/{ep_num}/{language}</span>
                    </div>
                    <p>Automatically maps AniList ID to MAL ID on the fly (via AniZip / AniList GraphQL) for 100% catalog coverage on MegaPlay.</p>
                    <div class="code-box">
                        <button class="btn-copy-code" onclick="copySnippet(this)"><i class="far fa-copy"></i></button>
                        <pre>&lt;iframe src="{{BASE_URL}}/embed/megaplay/ani/154587/1/sub" width="100%" height="100%" frameborder="0" scrolling="no" allowfullscreen&gt;&lt;/iframe&gt;</pre>
                    </div>

                    <!-- Endpoint 5: Catalog Stream ID -->
                    <h3><i class="fas fa-hashtag"></i> 5. Direct Catalog Episode ID (s-2)</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/embed/megaplay/s-2/{episode_id}/{language}</span>
                    </div>
                    <p>Directly loads stream using Anikoto / MegaPlay catalog episode ID (e.g. <code>136197</code>).</p>

                    <!-- Endpoint 6: Encrypted Stream Proxy -->
                    <h3><i class="fas fa-lock"></i> 6. Encrypted Media & HLS Chunk Proxy</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/p/{encrypted_token}</span>
                    </div>
                    <p>Internal high-throughput proxy for <code>.m3u8</code> manifests, <code>.ts</code> video segments, and <code>.vtt</code> subtitle tracks with 64KB memory pool and automated CDN header spoofing.</p>

                    <!-- Endpoint 7: Health Check -->
                    <h3><i class="fas fa-heart-pulse"></i> 7. Health Check</h3>
                    <div class="ep-badge-row">
                        <span class="method-badge">GET</span>
                        <span class="ep-path">{{BASE_URL}}/health</span>
                    </div>
                    <p>Returns service JSON status: <code>{"ok":true,"service":"yumezone-proxy-railway","version":"2.0.0"}</code>.</p>
                </div>

                <!-- Integration Guide -->
                <div class="doc-card" id="guide">
                    <div class="card-header">
                        <h2 class="card-title"><i class="fas fa-code"></i> Integration Guide</h2>
                    </div>
                    <p>Standard responsive iframe code to embed on any anime website:</p>

                    <h3><i class="fas fa-display"></i> Responsive 16:9 Aspect Ratio Snippet</h3>
                    <div class="code-box">
                        <button class="btn-copy-code" onclick="copySnippet(this)"><i class="far fa-copy"></i></button>
                        <pre>&lt;!-- Responsive 16:9 Video Embed Container --&gt;
&lt;div style="position: relative; width: 100%; aspect-ratio: 16 / 9; background: #000; border-radius: 12px; overflow: hidden;"&gt;
  &lt;iframe 
    src="{{BASE_URL}}/embed/megaplay/mal/5114/1/sub"
    style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: none;"
    scrolling="no"
    allowfullscreen
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"&gt;
  &lt;/iframe&gt;
&lt;/div&gt;</pre>
                    </div>
                </div>

                <!-- Player Events & Telemetry API -->
                <div class="doc-card" id="events">
                    <div class="card-header">
                        <h2 class="card-title"><i class="fas fa-chart-line"></i> Player Events (postMessage API)</h2>
                    </div>
                    <p>
                        The embedded player sends real-time events via <code>window.postMessage</code>. You can listen from your parent web app to track watch progress, sync watch history, or trigger automatic next-episode navigation.
                    </p>

                    <div class="param-table-wrap">
                        <table class="param-table">
                            <thead>
                                <tr>
                                    <th>Event Name</th>
                                    <th>Payload Keys</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><code>time</code></td>
                                    <td><code>time</code>, <code>duration</code>, <code>percent</code></td>
                                    <td>Emitted during playback with current position, duration, and percentage.</td>
                                </tr>
                                <tr>
                                    <td><code>complete</code></td>
                                    <td><code>event: "complete"</code></td>
                                    <td>Emitted when the episode reaches the end (ideal for Auto-Next Episode).</td>
                                </tr>
                                <tr>
                                    <td><code>watching-log</code></td>
                                    <td><code>currentTime</code>, <code>duration</code></td>
                                    <td>Periodic watch-time logging event.</td>
                                </tr>
                                <tr>
                                    <td><code>YUME_SWITCH_SERVER</code></td>
                                    <td><code>server: string</code></td>
                                    <td>Emitted when the user chooses an alternate server from the fallback frame.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <h3><i class="fas fa-terminal"></i> JavaScript Event Listener Example</h3>
                    <div class="code-box">
                        <button class="btn-copy-code" onclick="copySnippet(this)"><i class="far fa-copy"></i></button>
                        <pre>window.addEventListener("message", function (event) {
  let data = event.data;
  if (typeof data === "string") {
    try { data = JSON.parse(data); } catch (e) { return; }
  }
  if (!data) return;

  // 1. Handle playback progress
  if (data.event === "time") {
    console.log("Current time:", data.time, "Duration:", data.duration, "Percent:", data.percent + "%");
  }

  // 2. Handle episode completion (Auto-Next Episode)
  if (data.event === "complete") {
    console.log("Episode finished! Triggering next episode...");
  }

  // 3. Handle server switch requests
  if (data.type === "YUME_SWITCH_SERVER") {
    console.log("User clicked fallback server:", data.server);
  }
});</pre>
                    </div>
                </div>
            </main>

            <!-- Sticky Interactive Embed Sandbox Rail -->
            <aside class="doc-rail" id="test-embed">
                <div class="tester-card">
                    <h3 class="tester-title"><i class="fas fa-vial"></i> Test Your Embed</h3>
                    <p class="tester-sub">Configure your anime ID, generate iframe code, and preview the live video player in real-time.</p>

                    <form id="embed-sandbox-form">
                        <div class="form-group">
                            <label for="sb-mode">Provider & ID Source</label>
                            <select class="form-select" id="sb-mode">
                                <option value="zoko-mal">Zoko Server (MAL ID + Episode)</option>
                                <option value="zoko-ani">Zoko Server (AniList ID + Episode)</option>
                                <option value="salt-slug">AnimeSalt Server 1 (Series Slug, e.g. dan-da-dan)</option>
                                <option value="salt-ani">AnimeSalt Server 1 (AniList ID, Auto-Resolve Slug)</option>
                                <option value="salt-mal">AnimeSalt Server 1 (MAL ID, Auto-Resolve Slug)</option>
                                <option value="salt-hash">AnimeSalt Server 1 (Direct Video Hash)</option>
                                <option value="mal">MegaPlay (MAL ID + Episode)</option>
                                <option value="ani">MegaPlay (AniList ID + Episode)</option>
                                <option value="s-2">MegaPlay (Catalog Episode ID s-2)</option>
                            </select>
                        </div>

                        <div class="form-group" id="group-series-id">
                            <label for="sb-series-id">Series Slug / ID</label>
                            <input type="text" class="form-input" id="sb-series-id" value="dan-da-dan" placeholder="e.g. dan-da-dan, solo-leveling" required />
                        </div>

                        <div class="form-group" id="group-ep-num">
                            <label for="sb-ep-num">Episode Number</label>
                            <input type="text" class="form-input" id="sb-ep-num" value="1" placeholder="e.g. 1" required inputmode="numeric" />
                        </div>

                        <div class="form-group">
                            <label for="sb-lang">Audio Preference</label>
                            <select class="form-select" id="sb-lang">
                                <option value="sub">Sub (Japanese Original Audio / Subtitles)</option>
                                <option value="dub">Dub (English Audio Track)</option>
                            </select>
                        </div>

                        <div class="tester-btn-row">
                            <button type="submit" class="btn-primary" style="justify-content: center;">
                                <i class="fas fa-play"></i> Generate & Test
                            </button>
                            <button type="button" class="btn-secondary" id="btn-gen-both" style="justify-content: center;">
                                <i class="fas fa-layer-group"></i> Multi-Track Snippets
                            </button>
                        </div>
                    </form>

                    <!-- Generated Outputs -->
                    <div class="tester-out" id="sb-output">
                        <div id="sb-boxes-container"></div>
                        <div class="tester-preview-box">
                            <iframe id="preview-frame" src="" allowfullscreen allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"></iframe>
                        </div>
                        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.65rem; text-align: center;">
                            <i class="fas fa-circle-info"></i> Click the copy button on any block to grab the iframe code.
                        </p>
                    </div>
                </div>
            </aside>
        </div>
    </div>

    <!-- Footer -->
    <footer class="doc-footer">
        <div class="footer-inner">
            <div>
                <strong>YumeZone Stream Reverse Proxy</strong> — MegaPlay & AnimeSalt Server 1 HLS Streaming Engine.
            </div>
            <div class="footer-links">
                <a href="#overview">Overview</a>
                <a href="#endpoints">Endpoints</a>
                <a href="#events">Events</a>
                <a href="#test-embed">Tester</a>
                <a href="/health" target="_blank">Health</a>
            </div>
        </div>
    </footer>

    <script>
        const BASE_ORIGIN = "{{BASE_URL}}";

        const $ = (id) => document.getElementById(id);

        function buildUrl(mode, id, ep, lang) {
            id = encodeURIComponent(String(id).trim());
            ep = encodeURIComponent(String(ep).trim());
            lang = encodeURIComponent(String(lang).trim().toLowerCase());
            const isSalt = mode.startsWith("salt");
            const safeLang = isSalt ? lang : (lang === "dub" ? "dub" : "sub");

            if (mode === "zoko-mal") return BASE_ORIGIN + "/embed/zoko/mal/" + id + "/" + ep + "/" + safeLang;
            if (mode === "zoko-ani") return BASE_ORIGIN + "/embed/zoko/ani/" + id + "/" + ep + "/" + safeLang;
            if (mode === "salt-slug") return BASE_ORIGIN + "/embed/animesalt/" + id + "-1x" + ep + "?lang=" + safeLang;
            if (mode === "salt-ani") return BASE_ORIGIN + "/embed/animesalt/ani/" + id + "/" + ep + "/" + safeLang;
            if (mode === "salt-mal") return BASE_ORIGIN + "/embed/animesalt/mal/" + id + "/" + ep + "/" + safeLang;
            if (mode === "salt-hash") return BASE_ORIGIN + "/embed/as-cdn/" + id + "?lang=" + safeLang;
            if (mode === "mal") return BASE_ORIGIN + "/embed/megaplay/mal/" + id + "/" + ep + "/" + safeLang;
            if (mode === "ani") return BASE_ORIGIN + "/embed/megaplay/ani/" + id + "/" + ep + "/" + safeLang;
            if (mode === "s-2") return BASE_ORIGIN + "/embed/megaplay/s-2/" + id + "/" + safeLang;
            return BASE_ORIGIN + "/embed/zoko/mal/" + id + "/" + ep + "/" + safeLang;
        }

        function buildIframe(url) {
            return '<iframe src="' + url + '" width="100%" height="100%" frameborder="0" scrolling="no" allowfullscreen allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"></iframe>';
        }

        async function copySnippet(btn) {
            const pre = btn.parentElement.querySelector('pre');
            if (!pre) return;
            const text = pre.innerText || pre.textContent;
            try {
                await navigator.clipboard.writeText(text);
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check" style="color: var(--emerald);"></i> Copied';
                setTimeout(() => { btn.innerHTML = originalHtml; }, 1600);
            } catch (err) {
                const r = document.createRange();
                r.selectNodeContents(pre);
                const s = window.getSelection();
                s.removeAllRanges();
                s.addRange(r);
            }
        }

        function renderOutputBoxes(items) {
            const container = $("sb-boxes-container");
            container.innerHTML = "";

            items.forEach(item => {
                const box = document.createElement("div");
                box.className = "code-box";
                box.style.marginBottom = "0.75rem";

                const label = document.createElement("div");
                label.style.fontSize = "0.7rem";
                label.style.fontWeight = "700";
                label.style.color = "var(--accent-soft)";
                label.style.textTransform = "uppercase";
                label.style.marginBottom = "0.4rem";
                label.textContent = item.label;

                const pre = document.createElement("pre");
                pre.textContent = item.code;

                const copyBtn = document.createElement("button");
                copyBtn.className = "btn-copy-code";
                copyBtn.type = "button";
                copyBtn.innerHTML = '<i class="far fa-copy"></i> Copy';
                copyBtn.onclick = function() { copySnippet(this); };

                box.appendChild(label);
                box.appendChild(copyBtn);
                box.appendChild(pre);
                container.appendChild(box);
            });

            $("sb-output").style.display = "block";
        }

        // Mode switch UI adjustments
        $("sb-mode").addEventListener("change", (e) => {
            const mode = e.target.value;
            const langSelect = $("sb-lang");
            if (mode.startsWith("salt")) {
                langSelect.innerHTML = '<option value="hin">Hindi (Default Dub Audio Track)</option><option value="sub">Sub (Japanese Original Audio)</option><option value="dub">Dub (English Audio Track)</option><option value="tam">Tamil</option><option value="tel">Telugu</option>';
            } else {
                langSelect.innerHTML = '<option value="sub">Sub (Japanese Original Audio / Subtitles)</option><option value="dub">Dub (English Audio Track)</option>';
            }

            if (mode === "zoko-mal") {
                $("group-series-id").querySelector("label").textContent = "Zoko (MyAnimeList MAL ID)";
                $("sb-series-id").placeholder = "e.g. 21 (One Piece), 5114 (FMA:B)";
                $("sb-series-id").value = "21";
                $("group-ep-num").style.display = "block";
            } else if (mode === "zoko-ani") {
                $("group-series-id").querySelector("label").textContent = "Zoko (AniList ID)";
                $("sb-series-id").placeholder = "e.g. 21 (One Piece), 16498 (AOT)";
                $("sb-series-id").value = "21";
                $("group-ep-num").style.display = "block";
            } else if (mode === "s-2") {
                $("group-series-id").querySelector("label").textContent = "Episode ID (s-2)";
                $("sb-series-id").placeholder = "e.g. 136197";
                $("sb-series-id").value = "136197";
                $("group-ep-num").style.display = "none";
            } else if (mode === "salt-slug") {
                $("group-series-id").querySelector("label").textContent = "AnimeSalt Series Slug";
                $("sb-series-id").placeholder = "e.g. dan-da-dan, solo-leveling";
                $("sb-series-id").value = "dan-da-dan";
                $("group-ep-num").style.display = "block";
            } else if (mode === "salt-hash") {
                $("group-series-id").querySelector("label").textContent = "Server 1 Hash (as-cdn26)";
                $("sb-series-id").placeholder = "e.g. d645920e395fedad7bbbed0eca3fe2e0";
                $("sb-series-id").value = "d645920e395fedad7bbbed0eca3fe2e0";
                $("group-ep-num").style.display = "none";
            } else if (mode === "salt-ani") {
                $("group-series-id").querySelector("label").textContent = "AniList ID (AnimeSalt Server 1)";
                $("sb-series-id").placeholder = "e.g. 171018 (Dan Da Dan), 154587 (Frieren)";
                $("sb-series-id").value = "171018";
                $("group-ep-num").style.display = "block";
            } else if (mode === "salt-mal") {
                $("group-series-id").querySelector("label").textContent = "MyAnimeList ID (AnimeSalt Server 1)";
                $("sb-series-id").placeholder = "e.g. 52991 (Dan Da Dan), 5114";
                $("sb-series-id").value = "52991";
                $("group-ep-num").style.display = "block";
            } else if (mode === "mal") {
                $("group-series-id").querySelector("label").textContent = "MyAnimeList (MAL ID)";
                $("sb-series-id").placeholder = "e.g. 5114 (FMA:B), 21 (One Piece)";
                $("sb-series-id").value = "5114";
                $("group-ep-num").style.display = "block";
            } else if (mode === "ani") {
                $("group-series-id").querySelector("label").textContent = "AniList ID";
                $("sb-series-id").placeholder = "e.g. 154587 (Frieren), 16498 (AOT)";
                $("sb-series-id").value = "154587";
                $("group-ep-num").style.display = "block";
            }
        });

        // Form Submit handler
        $("embed-sandbox-form").addEventListener("submit", (e) => {
            e.preventDefault();
            const mode = $("sb-mode").value;
            const id = $("sb-series-id").value.trim();
            const ep = $("sb-ep-num").value.trim() || "1";
            const lang = $("sb-lang").value;

            if (!id) return alert("Please enter a slug or ID.");

            const url = buildUrl(mode, id, ep, lang);
            renderOutputBoxes([
                { label: "Embed Iframe (" + lang.toUpperCase() + ")", code: buildIframe(url) },
                { label: "Direct Embed Player URL", code: url }
            ]);

            $("preview-frame").src = url;
            $("sb-output").scrollIntoView({ behavior: "smooth", block: "nearest" });
        });

        // Generate Both Sub + Dub handler
        $("btn-gen-both").addEventListener("click", () => {
            const mode = $("sb-mode").value;
            const id = $("sb-series-id").value.trim();
            const ep = $("sb-ep-num").value.trim() || "1";

            if (!id) return alert("Please enter a slug or ID.");

            if (mode.startsWith("salt")) {
                const hinUrl = buildUrl(mode, id, ep, "hin");
                const subUrl = buildUrl(mode, id, ep, "sub");
                const dubUrl = buildUrl(mode, id, ep, "dub");

                renderOutputBoxes([
                    { label: "Hindi Dub Iframe (Hindi Default Track)", code: buildIframe(hinUrl) },
                    { label: "Japanese Sub Iframe", code: buildIframe(subUrl) },
                    { label: "English Dub Iframe", code: buildIframe(dubUrl) },
                ]);

                $("preview-frame").src = hinUrl;
            } else {
                const subUrl = buildUrl(mode, id, ep, "sub");
                const dubUrl = buildUrl(mode, id, ep, "dub");

                renderOutputBoxes([
                    { label: "Japanese Sub Iframe (Default)", code: buildIframe(subUrl) },
                    { label: "English Dub Iframe", code: buildIframe(dubUrl) },
                ]);

                $("preview-frame").src = subUrl;
            }
            $("sb-output").scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
    </script>
</body>
</html>`

func main() {
	initConfig()

	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = "5001"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 5001
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/docs", handleDocs)
	mux.HandleFunc("/api", handleDocs)
	mux.HandleFunc("/embed/megaplay/", handleMegaplayEmbed)
	mux.HandleFunc("/embed/megaplay", handleMegaplayEmbed)
	mux.HandleFunc("/embed/animesalt/", handleAnimeSaltEmbed)
	mux.HandleFunc("/embed/animesalt", handleAnimeSaltEmbed)
	mux.HandleFunc("/embed/as-cdn/", handleAnimeSaltEmbed)
	mux.HandleFunc("/embed/as-cdn", handleAnimeSaltEmbed)
	mux.HandleFunc("/embed/zoko/", handleZokoEmbed)
	mux.HandleFunc("/embed/zoko", handleZokoEmbed)
	mux.HandleFunc("/player/zoko", handleZokoEmbed)
	mux.HandleFunc("/player/zoko/", handleZokoEmbed)
	mux.HandleFunc("/api/zoko/source", handleZokoSourceAPI)
	mux.HandleFunc("/api/zoko/", handleZokoSourceAPI)
	mux.HandleFunc("/api/zoko", handleZokoSourceAPI)
	mux.HandleFunc("/player/salt", handleCustomSaltPlayer)
	mux.HandleFunc("/player/as-cdn/", handleCustomSaltPlayer)
	mux.HandleFunc("/api/animesalt/source", handleAnimeSaltSourceAPI)
	mux.HandleFunc("/api/as-cdn/", handleAnimeSaltSourceAPI)
	mux.HandleFunc("/stream/getSources", handleMegaplaySources)
	mux.HandleFunc("/stream/getSourcesNew", handleMegaplaySources)
	mux.HandleFunc("/lib/", handleMegaplayLib)
	mux.HandleFunc("/images/", handleMegaplayLib)
	mux.HandleFunc("/p/", handleProxy)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" || r.URL.Path == "/docs" || r.URL.Path == "/api" {
			handleDocs(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/embed/megaplay") {
			handleMegaplayEmbed(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/embed/animesalt") || strings.HasPrefix(r.URL.Path, "/embed/as-cdn") {
			handleAnimeSaltEmbed(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/embed/zoko") || strings.HasPrefix(r.URL.Path, "/player/zoko") {
			handleZokoEmbed(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/player/salt") || strings.HasPrefix(r.URL.Path, "/player/as-cdn") {
			handleCustomSaltPlayer(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/animesalt") || strings.HasPrefix(r.URL.Path, "/api/as-cdn") {
			handleAnimeSaltSourceAPI(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/zoko") {
			handleZokoSourceAPI(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/stream/getSources") {
			handleMegaplaySources(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/lib/") || strings.HasPrefix(r.URL.Path, "/images/") {
			handleMegaplayLib(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/p") {
			handleProxy(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(renderCustomProxy404(r.URL.Path, "")))
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("🚀 MegaPlay, AnimeSalt & Zoko Stream & Clean Embed Proxy running on 0.0.0.0:%d", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
