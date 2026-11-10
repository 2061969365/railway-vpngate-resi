package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultSidecarBaseURL is the loopback probe sidecar address.
	DefaultSidecarBaseURL = "http://127.0.0.1:39001"
	sidecarMaxBody        = 1 << 20
)

var disabledSidecarValues = map[string]struct{}{
	"0": {}, "false": {}, "no": {}, "off": {},
}

// Client is a fail-open HTTP client for the vpngate-probe sidecar. Every
// failure (transport error, timeout, non-2xx, malformed JSON, ok != true)
// returns false and feeds a short consecutive-failure breaker.
type Client struct {
	BaseURL          string
	Token            string
	HTTPClient       *http.Client
	Timeout          time.Duration
	BreakerThreshold int
	BreakerCooldown  time.Duration

	now func() time.Time

	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

// NewClient normalizes the base URL and fills defaults.
func NewClient(baseURL, token string) *Client {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		base = DefaultSidecarBaseURL
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return &Client{
		BaseURL:          strings.TrimRight(base, "/"),
		Token:            strings.TrimSpace(token),
		Timeout:          2 * time.Second,
		BreakerThreshold: 2,
		BreakerCooldown:  5 * time.Second,
	}
}

// NewClientFromEnv builds a client from PROBE_* variables, or nil when the
// sidecar is disabled (PROBE_SERVICE in 0/false/no/off).
func NewClientFromEnv(getenv func(string) string) *Client {
	if getenv == nil {
		return nil
	}
	service := strings.ToLower(strings.TrimSpace(getenv("PROBE_SERVICE")))
	if _, disabled := disabledSidecarValues[service]; disabled {
		return nil
	}
	listen := strings.TrimSpace(getenv("PROBE_LISTEN"))
	if listen == "" {
		listen = "127.0.0.1:39001"
	}
	return NewClient(listen, getenv("PROBE_TOKEN"))
}

// HealthResult is a validated /v1/health payload.
type HealthResult struct {
	OK      bool
	Version string
	Clash   bool
}

// Health reports whether the sidecar answers ok=true.
func (c *Client) Health(ctx context.Context) (HealthResult, bool) {
	raw, ok := c.call(ctx, http.MethodGet, "/v1/health", nil, c.requestTimeout())
	if !ok {
		return HealthResult{}, false
	}
	var payload struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
		Clash   *bool  `json:"clash"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || !payload.OK {
		return HealthResult{}, false
	}
	clash := payload.Clash != nil && *payload.Clash
	return HealthResult{OK: true, Version: payload.Version, Clash: clash}, true
}

// ExitIP asks the sidecar for one exit-IP measurement.
func (c *Client) ExitIP(ctx context.Context, host string, port int, username, password string, timeoutMS int) (ExitResult, bool) {
	payload := map[string]any{
		"host":       host,
		"port":       port,
		"username":   username,
		"password":   password,
		"timeout_ms": timeoutMS,
	}
	raw, ok := c.call(ctx, http.MethodPost, "/v1/exit", payload, c.payloadTimeout(timeoutMS))
	if !ok {
		return ExitResult{}, false
	}
	var response struct {
		OK     bool    `json:"ok"`
		ExitIP *string `json:"exit_ip"`
		MS     *int64  `json:"ms"`
		Target *string `json:"target"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || !response.OK {
		return ExitResult{}, false
	}
	if response.ExitIP == nil || *response.ExitIP == "" {
		return ExitResult{}, false
	}
	result := ExitResult{ExitIP: *response.ExitIP}
	if response.MS != nil {
		result.MS = *response.MS
	}
	if response.Target != nil {
		result.Target = *response.Target
	}
	return result, true
}

// Delays returns alive tag -> ms from /v1/delay.
func (c *Client) Delays(ctx context.Context, tags []string, timeoutMS int) (map[string]int64, bool) {
	return c.DelaysWithURL(ctx, tags, DefaultDelayURL, timeoutMS)
}

// DelaysWithURL is Delays with an explicit probe URL.
func (c *Client) DelaysWithURL(ctx context.Context, tags []string, url string, timeoutMS int) (map[string]int64, bool) {
	rows, ok := c.delayRows(ctx, tags, url, timeoutMS)
	if !ok {
		return nil, false
	}
	alive := make(map[string]int64, len(rows))
	for _, row := range rows {
		if row.Alive == nil || !*row.Alive || row.MS == nil {
			continue
		}
		alive[row.Tag] = *row.MS
	}
	return alive, true
}

// DelayStatus returns per-tag liveness; absent tags stay unknown.
func (c *Client) DelayStatus(ctx context.Context, tags []string, timeoutMS int) (map[string]bool, bool) {
	return c.DelayStatusWithURL(ctx, tags, DefaultDelayURL, timeoutMS)
}

// DelayStatusWithURL is DelayStatus with an explicit probe URL.
func (c *Client) DelayStatusWithURL(ctx context.Context, tags []string, url string, timeoutMS int) (map[string]bool, bool) {
	rows, ok := c.delayRows(ctx, tags, url, timeoutMS)
	if !ok {
		return nil, false
	}
	status := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.Alive == nil {
			continue
		}
		status[row.Tag] = *row.Alive
	}
	return status, true
}

type delayRow struct {
	Tag   string  `json:"tag"`
	Alive *bool   `json:"alive"`
	MS    *int64  `json:"ms"`
	Error *string `json:"error"`
}

func (c *Client) delayRows(ctx context.Context, tags []string, url string, timeoutMS int) ([]delayRow, bool) {
	if tags == nil {
		tags = []string{}
	}
	if url == "" {
		url = DefaultDelayURL
	}
	payload := map[string]any{
		"tags":       tags,
		"url":        url,
		"timeout_ms": timeoutMS,
	}
	raw, ok := c.call(ctx, http.MethodPost, "/v1/delay", payload, c.payloadTimeout(timeoutMS))
	if !ok {
		return nil, false
	}
	var response struct {
		OK      bool            `json:"ok"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || !response.OK {
		return nil, false
	}
	if len(response.Results) == 0 || string(response.Results) == "null" {
		return nil, false
	}
	var rows []delayRow
	if err := json.Unmarshal(response.Results, &rows); err != nil {
		return nil, false
	}
	return rows, true
}

func (c *Client) call(ctx context.Context, method, path string, payload any, timeout time.Duration) ([]byte, bool) {
	if !c.allow() {
		return nil, false
	}
	if timeout <= 0 {
		timeout = c.requestTimeout()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, false
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, false
	}
	request.Header.Set("Accept", "application/json")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		c.failure()
		return nil, false
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, sidecarMaxBody+1))
	if err != nil || len(raw) > sidecarMaxBody {
		c.failure()
		return nil, false
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		c.failure()
		return nil, false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		c.failure()
		return nil, false
	}
	c.success()
	return raw, true
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) requestTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 2 * time.Second
}

func (c *Client) payloadTimeout(timeoutMS int) time.Duration {
	if timeoutMS < 0 {
		timeoutMS = 0
	}
	value := time.Duration(timeoutMS)*time.Millisecond + 2*time.Second
	if value < time.Second {
		value = time.Second
	}
	return value
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Client) allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.clock().Before(c.openUntil)
}

func (c *Client) success() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openUntil = time.Time{}
}

func (c *Client) failure() {
	threshold := c.BreakerThreshold
	if threshold < 1 {
		threshold = 1
	}
	cooldown := c.BreakerCooldown
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= threshold {
		c.openUntil = c.clock().Add(cooldown)
		c.failures = 0
	}
}

// String makes logs readable without exposing the token.
func (c *Client) String() string {
	return fmt.Sprintf("probe.Client{%s}", c.BaseURL)
}
