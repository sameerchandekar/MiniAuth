package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/server"
)

func main() {
	// 1. Load Configuration
	cfg := config.Load()

	// 2. Initialize Structured Logger
	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("initializing MiniAuth Protected Resource Server...",
		slog.String("port", cfg.Address()),
		slog.String("issuer_url", cfg.IssuerURL),
		slog.String("jwks_url", cfg.JWKSURL),
		slog.String("swagger_url", "http://localhost:"+os.Getenv("PORT")+"/swagger"),
	)

	// 3. Initialize HTTP Server
	srv := server.New(cfg, nil, logger)

	// 4. Start server in background
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// 5. Listen for termination signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("resource server fatal error", slog.String("error", err.Error()))
		os.Exit(1)
	case sig := <-shutdown:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("forced shutdown error", slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("resource server stopped gracefully")
	}
}

func setupLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.IsDevelopment() {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
