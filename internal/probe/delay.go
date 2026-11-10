package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultDelayURL is the same bodyless endpoint the manager uses for a
// liveness check.
const DefaultDelayURL = "https://www.gstatic.com/generate_204"

const (
	maxClashBody = 64 << 10
	// maxDelayTags / maxDelayConcurrency are defensive caps. The server
	// enforces the same limits, but Delays is exported and may be called with
	// unvalidated input.
	maxDelayTags        = 256
	maxDelayConcurrency = 64
	// delayContextMarginMS must stay below the Python caller's fixed 2s
	// transport margin (timeout_ms/1000 + 2.0). Keeping 500ms of that margin
	// in reserve leaves room for the response to reach the caller.
	delayContextMarginMS = 1500
)

// DelayResult is one Clash API delay probe result. MS and Error are pointers
// so the JSON contract can spell an explicit null.
type DelayResult struct {
	Tag   string
	Alive bool
	MS    *int64
	Error *string
}

// ClashClient talks to the sing-box Clash API. It only ever issues GETs:
// /version and /proxies/{tag}/delay. It never selects or switches a proxy.
type ClashClient struct {
	BaseURL    string
	Secret     string
	HTTPClient *http.Client
}

func (c *ClashClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *ClashClient) request(ctx context.Context, path string) (*http.Response, error) {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("clash url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	return c.client().Do(req)
}

// Version reports whether GET {CLASH_URL}/version answers 200.
func (c *ClashClient) Version(ctx context.Context) error {
	resp, err := c.request(ctx, "/version")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxClashBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clash version status %d", resp.StatusCode)
	}
	return nil
}

// Delays probes every tag concurrently, bounded by concurrency. The returned
// slice is in the same order as tags.
func (c *ClashClient) Delays(ctx context.Context, tags []string, probeURL string, timeoutMS, concurrency int) []DelayResult {
	if len(tags) > maxDelayTags {
		tags = tags[:maxDelayTags]
	}
	results := make([]DelayResult, len(tags))
	if len(tags) == 0 {
		return results
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > maxDelayConcurrency {
		concurrency = maxDelayConcurrency
	}
	limit := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for index, tag := range tags {
		wg.Add(1)
		go func(index int, tag string) {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
				defer func() { <-limit }()
			case <-ctx.Done():
				results[index] = failureResult(tag, ctx.Err().Error())
				return
			}
			results[index] = c.delay(ctx, tag, probeURL, timeoutMS)
		}(index, tag)
	}
	wg.Wait()
	return results
}

func (c *ClashClient) delay(ctx context.Context, tag, probeURL string, timeoutMS int) DelayResult {
	if tag == "" {
		return failureResult(tag, "empty tag")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS+delayContextMarginMS)*time.Millisecond)
	defer cancel()

	path := "/proxies/" + url.PathEscape(tag) + "/delay?url=" + url.QueryEscape(probeURL) + "&timeout=" + strconv.Itoa(timeoutMS)
	resp, err := c.request(ctx, path)
	if err != nil {
		return failureResult(tag, err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxClashBody))
	if err != nil {
		return failureResult(tag, err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		message := clashMessage(body)
		if message == "" {
			message = fmt.Sprintf("http %d", resp.StatusCode)
		}
		return failureResult(tag, message)
	}
	var payload struct {
		Delay   *int64  `json:"delay"`
		Message *string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return failureResult(tag, "invalid clash response")
	}
	if payload.Delay == nil {
		message := "no delay"
		if payload.Message != nil && *payload.Message != "" {
			message = *payload.Message
		}
		return failureResult(tag, message)
	}
	ms := *payload.Delay
	if ms < 0 {
		ms = 0
	}
	return DelayResult{Tag: tag, Alive: true, MS: &ms}
}

func clashMessage(body []byte) string {
	var payload struct {
		Message *string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Message == nil {
		return ""
	}
	return strings.TrimSpace(*payload.Message)
}

func failureResult(tag, message string) DelayResult {
	if message == "" {
		message = "probe failed"
	}
	return DelayResult{Tag: tag, Alive: false, Error: &message}
}
