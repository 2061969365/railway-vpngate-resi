package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Printf("vpngate-manager: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := LoadConfigLookup(os.LookupEnv)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "vpngate-manager: ", log.LstdFlags)
	logger.Printf("MANAGER_IMPL=go stage 0-2 skeleton (production default stays py)")
	if cfg.PasswordGenerated {
		logger.Printf("PROXY_PASS not set, generated a random one")
	}
	if cfg.AdminTokenGenerated {
		logger.Printf("ADMIN_TOKEN not set, generated: %s", cfg.AdminToken)
	}
	if cfg.AdminTokenInsecure {
		logger.Printf("warning: weak ADMIN_TOKEN allowed by ALLOW_INSECURE_ADMIN=1")
	}
	for _, warning := range cfg.Warnings {
		logger.Printf("warning: %s", warning)
	}

	manager := NewManager(cfg)
	handler := NewHTTPHandler(manager, cfg.AdminToken)
	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.AdminPort)),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Printf("listening on %s (healthz stays 503 until phase 4 loads endpoints)", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
