package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/database"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/server"
)

func main() {
	// 1. Load Configuration
	cfg := config.Load()

	// 2. Initialize Structured Logger
	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("initializing MiniAuth Client Service...",
		slog.String("port", cfg.Address()),
		slog.String("auth_server_url", cfg.AuthServerURL),
		slog.String("auth_server_internal_url", cfg.AuthServerInternalURL),
		slog.String("client_id", cfg.ClientID),
		slog.String("redirect_uri", cfg.RedirectURI),
	)

	// 3. Connect to Redis for State & PKCE storage
	rdb, err := database.ConnectRedis(cfg.Redis, logger)
	if err != nil {
		logger.Warn("failed to connect to redis, falling back to in-memory state store", slog.String("error", err.Error()))
	} else {
		defer func() {
			if err := rdb.Close(); err != nil {
				logger.Error("error closing redis connection", slog.String("error", err.Error()))
			}
		}()
	}

	// 4. Initialize HTTP Server
	srv := server.New(cfg, rdb, logger)

	// 5. Start server in background
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// 6. Graceful shutdown on OS signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("server fatal error", slog.String("error", err.Error()))
		os.Exit(1)
	case sig := <-shutdown:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("forced shutdown error", slog.String("error", err.Error()))
			os.Exit(1)
		}
		logger.Info("client service stopped gracefully")
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
