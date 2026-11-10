package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testHandler(t *testing.T) (http.Handler, Config) {
	t.Helper()
	cfg := baseConfig(t)
	return NewHTTPHandler(NewManager(cfg), cfg.AdminToken), cfg
}

func TestHealthz(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != "not ready" {
		t.Fatalf("healthz = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
	if recorder.Header().Get("Connection") != "close" {
		t.Fatal("Connection: close missing")
	}

	request = httptest.NewRequest(http.MethodPost, "/healthz", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST healthz = %d", recorder.Code)
	}
}

func TestStatusRequiresAuth(t *testing.T) {
	handler, cfg := testHandler(t)
	for _, authorization := range []string{"", "Bearer wrong", cfg.AdminToken} {
		request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if authorization != "Bearer "+cfg.AdminToken {
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("auth %q = %d", authorization, recorder.Code)
			}
			if recorder.Body.String() != "missing or invalid admin token" {
				t.Fatalf("body = %q", recorder.Body.String())
			}
		}
	}
}

func TestStatusSnapshotHTTP(t *testing.T) {
	handler, cfg := testHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d %q", recorder.Code, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("content type = %q", contentType)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := payload["endpoints"]; !ok {
		t.Fatal("endpoints missing")
	}
	if payload["started_at"] == nil {
		t.Fatal("started_at missing")
	}
}

func TestStatusMethodAndUnknownPaths(t *testing.T) {
	handler, cfg := testHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/api/status", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/refresh", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("api refresh = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "skeleton") {
		t.Fatalf("body = %q", recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/refresh", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE api refresh = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/nope", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unknown without token = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/nope", nil)
	request.Header.Set("Authorization", "Bearer "+cfg.AdminToken)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown with token = %d", recorder.Code)
	}
}
