package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// HTTPHandler serves the stage 0-2 read-only API. Everything outside
// /healthz and /api/status is intentionally absent (501/404).
type HTTPHandler struct {
	manager *Manager
	token   string
}

// NewHTTPHandler builds the read-only handler.
func NewHTTPHandler(manager *Manager, token string) http.Handler {
	return &HTTPHandler{manager: manager, token: token}
}

func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Connection", "close")

	path := request.URL.Path
	if path == "/healthz" {
		if request.Method != http.MethodGet {
			writeText(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if h.manager.Ready() {
			writeText(writer, http.StatusOK, "ok")
		} else {
			writeText(writer, http.StatusServiceUnavailable, "not ready")
		}
		return
	}
	if !h.authorized(request) {
		writeText(writer, http.StatusUnauthorized, "missing or invalid admin token")
		return
	}
	if path == "/api/status" {
		if request.Method != http.MethodGet {
			writeText(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		payload, err := json.Marshal(h.manager.StatusSnapshot())
		if err != nil {
			writeText(writer, http.StatusInternalServerError, "status unavailable")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(payload)
		return
	}
	if strings.HasPrefix(path, "/api/") {
		if request.Method != http.MethodGet && request.Method != http.MethodPost {
			writeText(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeText(writer, http.StatusNotImplemented, "not implemented in the go manager skeleton")
		return
	}
	writeText(writer, http.StatusNotFound, "not found")
}

func (h *HTTPHandler) authorized(request *http.Request) bool {
	if h.token == "" {
		return false
	}
	provided := request.Header.Get("Authorization")
	expected := "Bearer " + h.token
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func writeText(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}
