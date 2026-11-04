package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type clashRecorder struct {
	mu        sync.Mutex
	methods   []string
	paths     []string
	active    int
	maxActive int
}

func (r *clashRecorder) note(method, path string) {
	r.mu.Lock()
	r.methods = append(r.methods, method)
	r.paths = append(r.paths, path)
	r.mu.Unlock()
}

func (r *clashRecorder) enter() {
	r.mu.Lock()
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	r.mu.Unlock()
}

func (r *clashRecorder) leave() {
	r.mu.Lock()
	r.active--
	r.mu.Unlock()
}

func (r *clashRecorder) snapshot() ([]string, []string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.methods...), append([]string(nil), r.paths...), r.maxActive
}

func newFakeClash(t *testing.T, versionStatus int) (*httptest.Server, *clashRecorder) {
	t.Helper()
	if versionStatus == 0 {
		versionStatus = http.StatusOK
	}
	recorder := &clashRecorder{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.note(r.Method, r.URL.RequestURI())
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/version":
			w.WriteHeader(versionStatus)
			if versionStatus == http.StatusOK {
				_, _ = io.WriteString(w, `{"version":"1.15.0"}`)
			}
		case strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay"):
			recorder.enter()
			defer recorder.leave()
			time.Sleep(20 * time.Millisecond)
			tag := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
			switch tag {
			case "ok":
				_, _ = io.WriteString(w, `{"delay":180}`)
			case "slow":
				w.WriteHeader(http.StatusGatewayTimeout)
				_, _ = io.WriteString(w, `{"message":"timeout"}`)
			case "bad":
				_, _ = io.WriteString(w, `{"delay":"nope"}`)
			case "empty":
				_, _ = io.WriteString(w, `{"message":"no delay"}`)
			default:
				http.Error(w, "no such proxy", http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, recorder
}

func TestDelaysParseResultsAndStayReadOnly(t *testing.T) {
	server, recorder := newFakeClash(t, http.StatusOK)
	client := &ClashClient{BaseURL: server.URL, Secret: "secret"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Version(ctx); err != nil {
		t.Fatalf("Version: %v", err)
	}
	tags := []string{"ok", "slow", "bad", "empty", "space tag"}
	results := client.Delays(ctx, tags, DefaultDelayURL, 500, 2)
	if len(results) != len(tags) {
		t.Fatalf("got %d results, want %d", len(results), len(tags))
	}
	if !results[0].Alive || results[0].MS == nil || *results[0].MS != 180 || results[0].Error != nil {
		t.Fatalf("ok result = %+v", results[0])
	}
	if results[1].Alive || results[1].MS != nil || results[1].Error == nil || *results[1].Error != "timeout" {
		t.Fatalf("slow result = %+v", results[1])
	}
	if results[2].Alive || results[2].Error == nil || *results[2].Error != "invalid clash response" {
		t.Fatalf("bad result = %+v", results[2])
	}
	if results[3].Alive || results[3].Error == nil || *results[3].Error != "no delay" {
		t.Fatalf("empty result = %+v", results[3])
	}
	if results[4].Alive || results[4].Tag != "space tag" {
		t.Fatalf("space tag result = %+v", results[4])
	}
	methods, paths, maxActive := recorder.snapshot()
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("Clash API received %s; only GET is allowed", method)
		}
	}
	for _, path := range paths {
		if strings.Contains(path, "/select") {
			t.Fatalf("Clash API received a selection request: %s", path)
		}
	}
	foundEscapedTag := false
	for _, path := range paths {
		if strings.Contains(path, "/proxies/space%20tag/delay") {
			foundEscapedTag = true
		}
	}
	if !foundEscapedTag {
		t.Fatalf("tag was not path-escaped: %v", paths)
	}
	if maxActive > 2 {
		t.Fatalf("delay concurrency exceeded the bound: %d", maxActive)
	}
}

func TestDelaysUsesConfiguredURLAndTimeout(t *testing.T) {
	server, recorder := newFakeClash(t, http.StatusOK)
	client := &ClashClient{BaseURL: server.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probeURL := "https://example.com/generate_204"
	results := client.Delays(ctx, []string{"ok"}, probeURL, 1234, 1)
	if !results[0].Alive {
		t.Fatalf("result = %+v", results[0])
	}
	expected := fmt.Sprintf("/proxies/ok/delay?url=%s&timeout=1234",
		"https%3A%2F%2Fexample.com%2Fgenerate_204")
	methods, paths, _ := recorder.snapshot()
	if len(methods) != 1 || methods[0] != http.MethodGet {
		t.Fatalf("methods = %v", methods)
	}
	if paths[0] != expected {
		t.Fatalf("path = %q, want %q", paths[0], expected)
	}
}

func TestVersionUnavailable(t *testing.T) {
	server, _ := newFakeClash(t, http.StatusInternalServerError)
	client := &ClashClient{BaseURL: server.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Version(ctx); err == nil {
		t.Fatal("Version succeeded against a 500 response")
	}
}

func TestVersionEmptyBaseURL(t *testing.T) {
	client := &ClashClient{}
	if err := client.Version(context.Background()); err == nil {
		t.Fatal("Version succeeded without a base URL")
	}
}
