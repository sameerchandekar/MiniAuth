package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/config"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/database"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/server"
)

func main() {
	// 1. Load configuration
	cfg := config.Load()

	// 2. Initialize logger
	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("initializing MiniAuth UserService...",
		slog.String("env", cfg.Environment),
		slog.String("port", cfg.Address()),
	)

	// 3. Connect to Database
	var db *sql.DB
	var err error
	db, err = database.Connect(cfg.DB, logger)
	if err != nil {
		logger.Error("failed to connect to postgresql", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("error closing database connection", slog.String("error", err.Error()))
		}
	}()

	// 4. Initialize HTTP Server
	srv := server.New(cfg, db, logger)

	// 5. Start Server in Goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// 6. Listen for OS Signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)

	case sig := <-shutdown:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", slog.String("error", err.Error()))
			os.Exit(1)
		}

		logger.Info("UserService exited cleanly")
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
