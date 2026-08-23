package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	URL string `json:"url"`
	Ref string `json:"ref,omitempty"`
	Exp int64  `json:"exp"`
	IP  string `json:"ip,omitempty"`
	Key string `json:"key,omitempty"`
}

var (
	proxySecretKey []byte
	allowedOrigins []string
	httpClient     *http.Client
	// 64KB Buffer Pool for zero-copy high-throughput video segment streaming
	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 64*1024)
			return &b
		},
	}
	uriRegex = regexp.MustCompile(`URI="([^"]+)"`)
)

var cdnRules = []CDNRule{
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
		Matches: func(h string) bool { return h == "anidb.app" || strings.HasSuffix(h, ".anidb.app") },
		Referer: "https://anidb.app/", Origin: "https://anidb.app", SecSite: "cross-site",
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

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2000,
		MaxIdleConnsPerHost:   250,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   35 * time.Second,
	}
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
	return baseURL.ResolveReference(relURL).String()
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

	resp, err := httpClient.Do(upstreamReq)
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

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")

	w.WriteHeader(resp.StatusCode)

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	_, _ = io.CopyBuffer(w, resp.Body, *bufPtr)
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

	// 1. Try AniZip API
	reqURL := fmt.Sprintf("https://api.ani.zip/mappings?anilist_id=%d", idNum)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
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

	// 2. Fallback to AniList GraphQL API
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
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(gqlReq)
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

	resp, err := httpClient.Do(upstreamReq)
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

type MegaplaySourcesResponse struct {
	Sources struct {
		File string `json:"file"`
	} `json:"sources"`
	Tracks []SubtitleTrack `json:"tracks"`
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

	resp, err := httpClient.Do(upstreamReq)
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

	apiURL := fmt.Sprintf("https://megaplay.buzz/stream/getSources?id=%s&cid=%s&cidu=%s", dataId, cid, cidu)
	apiReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", nil, err
	}
	apiReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	apiReq.Header.Set("Referer", "https://megaplay.buzz/")
	apiReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	apiResp, err := httpClient.Do(apiReq)
	if err != nil {
		return "", nil, err
	}
	defer apiResp.Body.Close()

	if apiResp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("getSources status %d", apiResp.StatusCode)
	}

	var res MegaplaySourcesResponse
	if err := json.NewDecoder(apiResp.Body).Decode(&res); err != nil {
		return "", nil, err
	}

	if res.Sources.File == "" {
		return "", nil, fmt.Errorf("no video file in getSources response")
	}

	return res.Sources.File, res.Tracks, nil
}

func renderCleanArtplayer(streamURL string, subtitleTracks []SubtitleTrack) string {
	tracksJSON, _ := json.Marshal(subtitleTracks)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>YumeZone Player</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/artplayer/dist/artplayer.css">
    <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
    <script src="https://cdn.jsdelivr.net/npm/artplayer/dist/artplayer.js"></script>
    <style>
        * { box-sizing: border-box; }
        video, .art-video-player, .art-video, #player {
            filter: none !important;
            -webkit-filter: none !important;
            backdrop-filter: none !important;
            -webkit-backdrop-filter: none !important;
        }
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
        #player {
            width: 100%%;
            height: 100%%;
        }
        .art-video-player {
            font-family: inherit !important;
            --art-theme: #a855f7;
        }
        .art-video-player .art-bottom {
            background: linear-gradient(to top, rgba(9, 9, 11, 0.95) 0%%, rgba(9, 9, 11, 0.7) 40%%, rgba(9, 9, 11, 0) 100%%) !important;
            padding: 10px 16px 14px 16px !important;
        }
        .art-video-player .art-progress {
            height: 5px !important;
            transition: height 0.2s ease !important;
            border-radius: 4px;
        }
        .art-video-player .art-progress:hover {
            height: 8px !important;
        }
        .art-video-player .art-progress .art-control-progress-played {
            background: linear-gradient(90deg, #9333ea, #c084fc) !important;
            box-shadow: 0 0 12px rgba(168, 85, 247, 0.6) !important;
            border-radius: 4px;
        }
        .art-video-player .art-progress .art-control-progress-indicator {
            background: #ffffff !important;
            box-shadow: 0 0 10px rgba(192, 132, 252, 0.9) !important;
            border: 2px solid #a855f7 !important;
        }
        .art-video-player .art-control-progress-loaded {
            background: rgba(255, 255, 255, 0.25) !important;
            border-radius: 4px;
        }
        .art-video-player .art-control-time {
            font-family: 'Outfit', sans-serif !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            color: #e4e4e7 !important;
            letter-spacing: 0.5px;
        }
        .art-video-player .art-icon svg {
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.4));
            transition: transform 0.15s ease, fill 0.15s ease;
        }
        .art-video-player .art-icon:hover svg {
            transform: scale(1.1);
        }
        .art-video-player .art-state {
            pointer-events: none;
        }
        .art-video-player .art-state .art-icon-state {
            width: 72px;
            height: 72px;
            background: rgba(168, 85, 247, 0.85);
            border-radius: 50%%;
            box-shadow: 0 0 30px rgba(168, 85, 247, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        .art-video-player .art-state .art-icon-state svg {
            width: 32px;
            height: 32px;
            fill: #ffffff;
            margin-left: 3px;
        }
        .art-video-player .art-subtitle {
            font-family: 'Outfit', sans-serif !important;
            font-weight: 600 !important;
            font-size: 26px !important;
            color: #ffffff !important;
            text-shadow: 0 0 4px #000, 0 0 8px #000, 2px 2px 3px #000, -2px -2px 3px #000 !important;
            line-height: 1.4 !important;
            bottom: 60px !important;
        }
        @media (max-width: 768px) {
            .art-video-player .art-subtitle {
                font-size: 18px !important;
                bottom: 45px !important;
            }
            .art-video-player .art-bottom {
                padding: 6px 10px 10px 10px !important;
            }
        }
        .art-video-player .art-setting-panel {
            background: rgba(24, 24, 27, 0.95) !important;!important;
            border: 1px solid rgba(255, 255, 255, 0.1) !important;
            border-radius: 12px !important;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5) !important;
        }
        .art-video-player .art-setting-item:hover {
            background: rgba(168, 85, 247, 0.15) !important;
            color: #c084fc !important;
        }
        .art-video-player .art-setting-item.art-current {
            color: #a855f7 !important;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div id="player"></div>
    <script>
        const rawTracks = %s || [];
        let initialSubtitle = {};
        if (rawTracks.length > 0) {
            const eng = rawTracks.find(t => (t.label || '').toLowerCase().includes('eng')) || rawTracks[0];
            if (eng && eng.file) {
                initialSubtitle = {
                    url: eng.file,
                    type: 'vtt',
                    encoding: 'utf-8',
                    escape: false,
                    style: {
                        color: '#ffffff',
                        fontSize: window.innerWidth < 768 ? '18px' : '26px',
                    },
                };
            }
        }

        const art = new Artplayer({
            container: '#player',
            url: '%s',
            type: 'm3u8',
            customType: {
                m3u8: function (video, url, art) {
                    if (Hls.isSupported()) {
                        if (art.hls) art.hls.destroy();
                        const hls = new Hls({
                            maxBufferLength: 30,
                            maxMaxBufferLength: 60,
                            enableWorker: true,
                        });
                        hls.loadSource(url);
                        hls.attachMedia(video);
                        art.hls = hls;
                        art.on('destroy', () => hls.destroy());
                    } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                        video.src = url;
                    }
                },
            },
            subtitle: initialSubtitle.url ? initialSubtitle : undefined,
            autoplay: true,
            autoSize: true,
            autoMini: true,
            screenshot: true,
            setting: true,
            loop: false,
            flip: true,
            playbackRate: true,
            aspectRatio: true,
            fullscreen: true,
            fullscreenWeb: true,
            pip: true,
            theme: '#a855f7',
            lang: 'en',
            hotkey: true,
            airplay: true,
            lock: true,
            fastForward: true,
            autoPlayback: true,
            controls: [
                {
                    name: 'backward',
                    position: 'left',
                    index: 10,
                    html: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m11 17-5-5 5-5"/><path d="m18 17-5-5 5-5"/></svg>',
                    tooltip: 'Backward 10s',
                    click: function () {
                        art.currentTime = Math.max(0, art.currentTime - 10);
                    },
                },
                {
                    name: 'forward',
                    position: 'left',
                    index: 11,
                    html: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 17 5-5-5-5"/><path d="m13 17 5-5-5-5"/></svg>',
                    tooltip: 'Forward 10s',
                    click: function () {
                        art.currentTime = Math.min(art.duration || 9999, art.currentTime + 10);
                    },
                },
            ],
            settings: rawTracks.length > 0 ? [
                {
                    html: 'Subtitles',
                    tooltip: (rawTracks.find(t => (t.label || '').toLowerCase().includes('eng')) || rawTracks[0])?.label || 'Default',
                    selector: [
                        { html: 'Off', url: '' },
                        ...rawTracks.map(t => ({ html: t.label, url: t.file, default: Boolean(t.default) }))
                    ],
                    onSelect: function (item) {
                        if (!item.url) {
                            art.subtitle.show = false;
                        } else {
                            art.subtitle.show = true;
                            art.subtitle.switch(item.url, { name: item.html });
                        }
                        return item.html;
                    },
                }
            ] : []
        });
    </script>
</body>
</html>`, string(tracksJSON), streamURL)
}

func handleMegaplayEmbed(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
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

	// Check cache for instant load
	cacheKey := "megaplay:clean:" + targetPath
	if val, ok := embedCache.Load(cacheKey); ok {
		entry := val.(EmbedCacheEntry)
		if time.Now().Before(entry.ExpiresAt) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors *;")
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(entry.HTML))
			return
		}
	}

	// 1. Extract clean decrypted HLS stream directly from MegaPlay
	hlsFile, tracks, err := extractMegaplayHLS(r.Context(), targetPath)
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
			html := renderCleanArtplayer(proxiedStreamURL, proxiedTracks)

			embedCache.Store(cacheKey, EmbedCacheEntry{
				HTML:      html,
				ExpiresAt: time.Now().Add(2 * time.Hour),
			})

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
			w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; frame-ancestors *;")
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Del("X-Frame-Options")
			w.Header().Del("Cross-Origin-Opener-Policy")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(html))
			return
		}
	}

	// 2. Fallback to raw stream passthrough with base tag
	upstreamURL := "https://megaplay.buzz/stream/" + targetPath
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, `{"error":"Failed to build upstream request"}`, http.StatusInternalServerError)
		return
	}

	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	upstreamReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	upstreamReq.Header.Set("Referer", "https://anikoto.cz/")
	upstreamReq.Header.Set("Sec-Fetch-Dest", "iframe")
	upstreamReq.Header.Set("Sec-Fetch-Mode", "navigate")

	resp, err := httpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"Upstream fetch failed: %s"}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read upstream HTML"}`, http.StatusBadGateway)
		return
	}

	rawHtml := string(bodyBytes)
	noBlurStyle := `<style>
		video, iframe, #megaplay-player, .mg3-player, #fix-area, .fix-area, body, div, canvas, .content-center {
			filter: none !important;
			-webkit-filter: none !important;
			backdrop-filter: none !important;
			-webkit-backdrop-filter: none !important;
		}
	</style>`
	if strings.Contains(rawHtml, "<head>") {
		rawHtml = strings.Replace(rawHtml, "<head>", "<head>\n  <base href=\"https://megaplay.buzz/\">\n  "+noBlurStyle, 1)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Security-Policy", "frame-ancestors *")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Del("X-Frame-Options")
	w.Header().Del("Cross-Origin-Opener-Policy")
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(rawHtml))
}

func handleMegaplaySources(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, `{"error":"Failed to create upstream request"}`, http.StatusInternalServerError)
		return
	}

	upstreamReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	upstreamReq.Header.Set("Accept", "*/*")
	upstreamReq.Header.Set("Referer", "https://megaplay.buzz/")
	upstreamReq.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := httpClient.Do(upstreamReq)
	if err != nil {
		http.Error(w, `{"error":"Upstream fetch failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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

	resp, err := httpClient.Do(upstreamReq)
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

func handleHealth(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(fmt.Appendf(nil, `{"ok":true,"service":"yumezone-proxy-railway","version":"2.0.0","ts":%d}`, time.Now().UnixMilli()))
}

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
	mux.HandleFunc("/embed/megaplay/", handleMegaplayEmbed)
	mux.HandleFunc("/embed/megaplay", handleMegaplayEmbed)
	mux.HandleFunc("/stream/getSources", handleMegaplaySources)
	mux.HandleFunc("/stream/getSourcesNew", handleMegaplaySources)
	mux.HandleFunc("/lib/", handleMegaplayLib)
	mux.HandleFunc("/images/", handleMegaplayLib)
	mux.HandleFunc("/p/", handleProxy)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			handleHealth(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/embed/megaplay") {
			handleMegaplayEmbed(w, r)
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
		http.NotFound(w, r)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("ðŸš€ YumeZone Go Stream & Clean Embed Proxy running on 0.0.0.0:%d", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy server failed: %v", err)
	}
}


