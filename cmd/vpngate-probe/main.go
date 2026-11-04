// Command vpngate-probe runs the loopback-only probe sidecar.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/config"
	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
	"github.com/2061969365/railway-vpngate-combined/probe/internal/server"
)

func main() {
	cfg := config.FromEnv()
	if err := config.ValidateLoopback(cfg.Listen); err != nil {
		log.Fatalf("vpngate-probe: %v", err)
	}

	clash := &probe.ClashClient{BaseURL: cfg.ClashURL, Secret: cfg.ClashSecret}
	handler := server.New(server.Options{
		Token:            cfg.Token,
		Version:          "dev",
		DefaultTimeoutMS: cfg.DefaultTimeoutMS,
		Concurrency:      cfg.Concurrency,
		Exit:             &probe.Exiter{},
		Clash:            clash,
	})

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("vpngate-probe: listen %s: %v", cfg.Listen, err)
	}
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serveError := make(chan error, 1)
	go func() {
		serveError <- httpServer.Serve(listener)
	}()
	log.Printf("vpngate-probe listening on %s", listener.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		log.Printf("vpngate-probe shutting down")
	case err := <-serveError:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("vpngate-probe: serve: %v", err)
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("vpngate-probe: shutdown: %v", err)
	}
}
