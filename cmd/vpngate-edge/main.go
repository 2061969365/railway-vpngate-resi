// Command vpngate-edge is the public data-plane front proxy.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/edge"
)

func main() {
	logger := log.New(os.Stderr, "vpngate-edge: ", log.LstdFlags|log.Lmicroseconds)
	cfg := edge.LoadConfig()
	if err := edge.ValidateMetricsListen(cfg.MetricsListen); err != nil {
		logger.Fatalf("%v", err)
	}
	proxy, err := edge.New(cfg, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	publicServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	metricsServer := &http.Server{
		Addr:              cfg.MetricsListen,
		Handler:           proxy.Metrics(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serveErrors := make(chan error, 2)
	go func() {
		logger.Printf("public listener %s (admin %s, node %s, chain %s)",
			cfg.Listen, cfg.AdminURL, cfg.NodeAddr, cfg.ChainAddr)
		serveErrors <- publicServer.ListenAndServe()
	}()
	go func() {
		logger.Printf("metrics listener %s", cfg.MetricsListen)
		serveErrors <- metricsServer.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Printf("shutdown signal received")
	case serveErr := <-serveErrors:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Printf("server failed: %v", serveErr)
			exitCode = 1
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := publicServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("public shutdown: %v", err)
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("metrics shutdown: %v", err)
	}
	logger.Printf("stopped")
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
