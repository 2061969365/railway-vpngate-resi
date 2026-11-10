// Package server exposes the loopback-only HTTP API of vpngate-probe.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
)

const (
	maxRequestBody = 1 << 20
	maxTimeoutMS   = 120_000
	// maxConcurrency mirrors config.MaxConcurrency; server.New clamps again so
	// callers that build Options directly cannot bypass the bound.
	maxConcurrency = 64
	// maxTags bounds /v1/delay fan-out. The body cap alone allows ~100k short
	// tags, which would spawn as many goroutines.
	maxTags = 256
	// maxTagLength bounds one tag before it is embedded in a Clash path.
	maxTagLength = 256
	// maxProbeURLLength bounds the caller-supplied delay URL.
	maxProbeURLLength = 2048
	// delayFallbackBudget bounds the extra /version check after all delay
	// probes failed. A slow delay batch already proves the Clash data path is
	// unhealthy; spending the caller's remaining deadline on a second round
	// trip would lose the per-tag failure data it can still use.
	delayFallbackBudget = 500 * time.Millisecond
)

// ExitRunner is the real exit-IP measurement (implemented by *probe.Exiter).
type ExitRunner interface {
	ExitIP(ctx context.Context, host string, port int, username, password string) (probe.ExitResult, error)
}

// ClashRunner is the read-only Clash API surface (implemented by
// *probe.ClashClient).
type ClashRunner interface {
	Version(ctx context.Context) error
	Delays(ctx context.Context, tags []string, probeURL string, timeoutMS, concurrency int) []probe.DelayResult
}

// Options wires the server. Zero values fall back to the contract defaults.
type Options struct {
	Token             string
	Version           string
	DefaultTimeoutMS  int
	Concurrency       int
	ClashCheckTimeout time.Duration
	Exit              ExitRunner
	Clash             ClashRunner
}

// Server is the sidecar HTTP handler.
type Server struct {
	token             string
	version           string
	defaultTimeoutMS  int
	concurrency       int
	clashCheckTimeout time.Duration
	exit              ExitRunner
	clash             ClashRunner
}

// New builds the HTTP handler.
func New(options Options) *Server {
	version := options.Version
	if version == "" {
		version = "dev"
	}
	timeout := options.DefaultTimeoutMS
	if timeout <= 0 {
		timeout = 8000
	}
	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}
	clashTimeout := options.ClashCheckTimeout
	if clashTimeout <= 0 {
		clashTimeout = 2 * time.Second
	}
	return &Server{
		token:             options.Token,
		version:           version,
		defaultTimeoutMS:  timeout,
		concurrency:       concurrency,
		clashCheckTimeout: clashTimeout,
		exit:              options.Exit,
		clash:             options.Clash,
	}
}

type errorPayload struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type healthPayload struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Clash   bool   `json:"clash"`
}

type exitRequest struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	TimeoutMS int    `json:"timeout_ms"`
}

type exitPayload struct {
	OK     bool   `json:"ok"`
	ExitIP string `json:"exit_ip,omitempty"`
	MS     *int64 `json:"ms"`
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
}

type delayRequest struct {
	Tags      []string `json:"tags"`
	URL       string   `json:"url"`
	TimeoutMS int      `json:"timeout_ms"`
}

type delayResultPayload struct {
	Tag   string  `json:"tag"`
	Alive bool    `json:"alive"`
	MS    *int64  `json:"ms"`
	Error *string `json:"error"`
}

type delayPayload struct {
	OK      bool                 `json:"ok"`
	Results []delayResultPayload `json:"results"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") && s.token != "" && !tokenMatches(r.Header.Get("Authorization"), s.token) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, errorPayload{Error: "unauthorized"})
		return
	}
	switch r.URL.Path {
	case "/v1/health":
		s.handleHealth(w, r)
	case "/v1/exit":
		s.handleExit(w, r)
	case "/v1/delay":
		s.handleDelay(w, r)
	default:
		writeJSON(w, http.StatusNotFound, errorPayload{Error: "not found"})
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	clashOK := false
	if s.clash != nil {
		ctx, cancel := context.WithTimeout(r.Context(), s.clashCheckTimeout)
		clashOK = s.clash.Version(ctx) == nil
		cancel()
	}
	writeJSON(w, http.StatusOK, healthPayload{OK: true, Version: s.version, Clash: clashOK})
}

func (s *Server) handleExit(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var request exitRequest
	if !s.decode(w, r, &request) {
		return
	}
	host := strings.TrimSpace(request.Host)
	if host == "" || request.Port < 1 || request.Port > 65535 {
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid host or port"})
		return
	}
	if err := validateLoopbackHost(r.Context(), host); err != nil {
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid host or port"})
		return
	}
	timeoutMS := request.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = s.defaultTimeoutMS
	}
	if timeoutMS > maxTimeoutMS {
		timeoutMS = maxTimeoutMS
	}
	if s.exit == nil {
		writeJSON(w, http.StatusOK, exitPayload{Error: "no exit ip"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()
	result, err := s.exit.ExitIP(ctx, request.Host, request.Port, request.Username, request.Password)
	if err != nil {
		writeJSON(w, http.StatusOK, exitPayload{Error: "no exit ip"})
		return
	}
	ms := result.MS
	writeJSON(w, http.StatusOK, exitPayload{OK: true, ExitIP: result.ExitIP, MS: &ms, Target: result.Target})
}

func (s *Server) handleDelay(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var request delayRequest
	if !s.decode(w, r, &request) {
		return
	}
	if s.clash == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorPayload{Error: "clash unavailable"})
		return
	}
	if len(request.Tags) > maxTags {
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "too many tags"})
		return
	}
	tags, err := normalizeTags(request.Tags)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid tag"})
		return
	}
	probeURL := strings.TrimSpace(request.URL)
	if probeURL == "" {
		probeURL = probe.DefaultDelayURL
	} else {
		validated, err := validateProbeURL(probeURL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid url"})
			return
		}
		probeURL = validated
	}
	timeoutMS := request.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = s.defaultTimeoutMS
	}
	if timeoutMS > maxTimeoutMS {
		timeoutMS = maxTimeoutMS
	}
	started := time.Now()
	results := s.clash.Delays(r.Context(), tags, probeURL, timeoutMS, s.concurrency)
	if len(results) == 0 || allDelaysFailed(results) {
		if time.Since(started) < delayFallbackBudget && !s.clashReachable(r.Context()) {
			writeJSON(w, http.StatusServiceUnavailable, errorPayload{Error: "clash unavailable"})
			return
		}
	}
	payload := delayPayload{OK: true, Results: make([]delayResultPayload, 0, len(results))}
	for _, result := range results {
		payload.Results = append(payload.Results, delayResultPayload{
			Tag:   result.Tag,
			Alive: result.Alive,
			MS:    result.MS,
			Error: result.Error,
		})
	}
	writeJSON(w, http.StatusOK, payload)
}

// allDelaysFailed reports whether every delay attempt failed. The caller uses
// it to decide whether a Clash /version check is worth doing: a healthy API
// with a few dead tags still returns per-tag errors, while an unreachable API
// fails every attempt.
func allDelaysFailed(results []probe.DelayResult) bool {
	for _, result := range results {
		if result.Alive {
			return false
		}
	}
	return true
}

// clashReachable confirms the Clash API itself answers /version. It is only
// consulted after every delay attempt failed, so healthy /v1/delay calls pay
// no extra round trip.
func (s *Server) clashReachable(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, s.clashCheckTimeout)
	defer cancel()
	return s.clash.Version(checkCtx) == nil
}

// validateLoopbackHost restricts /v1/exit to the local mixed inbound. The
// endpoint dials whatever host it is given and issues a CONNECT through it, so
// accepting non-loopback addresses would turn the sidecar into a local port
// scanner. Domain names are resolved first and must resolve to loopback only.
func validateLoopbackHost(ctx context.Context, host string) error {
	if isLoopbackName(host) {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("host %q is not loopback", host)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("host %q cannot be resolved", host)
	}
	for _, address := range addresses {
		if !address.IsLoopback() {
			return fmt.Errorf("host %q resolves outside loopback", host)
		}
	}
	return nil
}

func isLoopbackName(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalizeTags trims, drops empty tags, and removes duplicates while keeping
// the caller's order. Duplicate tags would otherwise probe the same proxy twice
// and produce ambiguous results.
func normalizeTags(tags []string) ([]string, error) {
	normalized := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if len(tag) > maxTagLength {
			return nil, fmt.Errorf("tag exceeds %d bytes", maxTagLength)
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		normalized = append(normalized, tag)
	}
	return normalized, nil
}

// validateProbeURL keeps /v1/delay from becoming an arbitrary-URL fetcher
// through the Clash outbound. https is always allowed; http is allowed only for
// loopback test servers.
func validateProbeURL(raw string) (string, error) {
	if len(raw) > maxProbeURLLength {
		return "", fmt.Errorf("url exceeds %d bytes", maxProbeURLLength)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("url has no host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("url must not carry credentials")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !isLoopbackName(parsed.Hostname()) {
			return "", fmt.Errorf("http url must target loopback")
		}
	default:
		return "", fmt.Errorf("url must use https")
	}
	return parsed.String(), nil
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	if r.ContentLength > maxRequestBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorPayload{Error: "request body too large"})
		return false
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorPayload{Error: "request body too large"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid json"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorPayload{Error: "invalid json"})
		return false
	}
	return true
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, errorPayload{Error: "method not allowed"})
	return false
}

func tokenMatches(header, want string) bool {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	presented := header[len(prefix):]
	presentedHash := sha256.Sum256([]byte(presented))
	wantedHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(presentedHash[:], wantedHash[:]) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
