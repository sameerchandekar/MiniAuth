package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/database"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/server"
)

func main() {
	// 1. Load configuration
	cfg := config.Load()

	// 2. Initialize structured logger
	logger := setupLogger(cfg)
	slog.SetDefault(logger)

	logger.Info("initializing MiniAuth Authorization Server...",
		slog.String("env", cfg.Environment),
		slog.String("port", cfg.Address()),
		slog.String("issuer_url", cfg.IssuerURL),
	)

	// 3. Connect to PostgreSQL Database
	var db *sql.DB
	var err error
	db, err = database.Connect(cfg.DB, logger)
	if err != nil {
		logger.Error("failed to connect to postgresql database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("error closing database connection", slog.String("error", err.Error()))
		}
	}()

	// 4. Run database migrations on startup if enabled
	if cfg.DB.AutoMigrate {
		migrationCtx, migrationCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer migrationCancel()

		if err := database.RunMigrations(migrationCtx, db, logger); err != nil {
			logger.Error("database migration failed on startup", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	// 5. Initialize HTTP server
	srv := server.New(cfg, logger)

	// 6. Start server in background goroutine
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.Start()
	}()

	// 7. Listen for termination signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("server failed to start", slog.String("error", err.Error()))
		os.Exit(1)

	case sig := <-shutdown:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed, forcing exit", slog.String("error", err.Error()))
			os.Exit(1)
		}

		logger.Info("server exited cleanly")
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
