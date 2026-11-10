package contract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
)

func TestNewClientFromEnv(t *testing.T) {
	if client := probe.NewClientFromEnv(func(string) string { return "off" }); client != nil {
		t.Fatal("PROBE_SERVICE=off must disable the client")
	}
	client := probe.NewClientFromEnv(func(name string) string {
		switch name {
		case "PROBE_LISTEN":
			return "127.0.0.1:39002"
		case "PROBE_TOKEN":
			return " secret "
		}
		return ""
	})
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.BaseURL != "http://127.0.0.1:39002" {
		t.Fatalf("base url = %q", client.BaseURL)
	}
	if client.Token != "secret" {
		t.Fatalf("token = %q", client.Token)
	}
	defaulted := probe.NewClientFromEnv(func(string) string { return "" })
	if defaulted.BaseURL != probe.DefaultSidecarBaseURL {
		t.Fatalf("default base = %q", defaulted.BaseURL)
	}
}

func TestNewClientNormalizesBaseURL(t *testing.T) {
	client := probe.NewClient("127.0.0.1:39001/", "")
	if client.BaseURL != "http://127.0.0.1:39001" {
		t.Fatalf("base = %q", client.BaseURL)
	}
}

func TestClientHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"version":"1.2.3","clash":true}`))
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "token")
	result, ok := client.Health(context.Background())
	if !ok || !result.OK || result.Version != "1.2.3" || !result.Clash {
		t.Fatalf("health = %+v ok=%v", result, ok)
	}
}

func TestClientExitIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/exit" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["host"] != "127.0.0.1" || payload["timeout_ms"].(float64) != 8000 {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"exit_ip":"203.0.113.7","ms":12,"target":"api.ipify.org"}`))
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	result, ok := client.ExitIP(context.Background(), "127.0.0.1", 40000, "u", "p", 8000)
	if !ok || result.ExitIP != "203.0.113.7" || result.MS != 12 || result.Target != "api.ipify.org" {
		t.Fatalf("exit = %+v ok=%v", result, ok)
	}
}

func TestClientDelays(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"results":[
			{"tag":"a","alive":true,"ms":25},
			{"tag":"b","alive":false,"ms":null},
			{"tag":"c","alive":true,"ms":null},
			{"bad":1}
		]}`))
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	alive, ok := client.Delays(context.Background(), []string{"a", "b", "c"}, 5000)
	if !ok || len(alive) != 1 || alive["a"] != 25 {
		t.Fatalf("delays = %#v ok=%v", alive, ok)
	}
	status, ok := client.DelayStatus(context.Background(), []string{"a", "b", "c", "d"}, 5000)
	if !ok || status["a"] != true || status["b"] != false || status["c"] != true {
		t.Fatalf("status = %#v ok=%v", status, ok)
	}
	if _, present := status["d"]; present {
		t.Fatalf("unknown tag must stay absent: %#v", status)
	}
}

func TestClientFailOpen(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		call    func(*probe.Client) bool
	}{
		{
			name: "non-ok payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"ok":false}`))
			},
			call: func(c *probe.Client) bool { _, ok := c.Health(context.Background()); return ok },
		},
		{
			name: "malformed json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`not-json`))
			},
			call: func(c *probe.Client) bool { _, ok := c.Health(context.Background()); return ok },
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			},
			call: func(c *probe.Client) bool { _, ok := c.Health(context.Background()); return ok },
		},
		{
			name: "missing results",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"ok":true}`))
			},
			call: func(c *probe.Client) bool { _, ok := c.Delays(context.Background(), []string{"a"}, 1000); return ok },
		},
		{
			name: "exit without exit_ip",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"ok":true,"ms":5}`))
			},
			call: func(c *probe.Client) bool { _, ok := c.ExitIP(context.Background(), "h", 1, "", "", 1000); return ok },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			client := probe.NewClient(server.URL, "")
			if tc.call(client) {
				t.Fatal("expected fail-open false")
			}
		})
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	if _, ok := client.Health(context.Background()); ok {
		t.Fatal("redirect must not be followed")
	}
}

func TestClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	client.Timeout = 20 * time.Millisecond
	start := time.Now()
	if _, ok := client.Health(context.Background()); ok {
		t.Fatal("expected timeout failure")
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("timeout not honored: %s", elapsed)
	}
}

func TestClientBreaker(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	client.BreakerCooldown = 100 * time.Millisecond

	if _, ok := client.Health(context.Background()); ok {
		t.Fatal("first failure must be reported")
	}
	if _, ok := client.Health(context.Background()); ok {
		t.Fatal("second failure must be reported")
	}
	if _, ok := client.Health(context.Background()); ok {
		t.Fatal("breaker must short-circuit")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("breaker did not short-circuit: calls = %d", got)
	}
	time.Sleep(150 * time.Millisecond)
	if _, ok := client.Health(context.Background()); !ok {
		t.Fatal("breaker must close after cooldown")
	}
}

func TestClientDisablesEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := probe.NewClient(server.URL, "")
	if _, ok := client.Health(context.Background()); !ok {
		t.Fatal("local request must not use HTTP_PROXY")
	}
}
