package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

// Connect creates and validates a connection to the PostgreSQL database.
func Connect(cfg config.DatabaseConfig, logger *slog.Logger) (*sql.DB, error) {
	dsn := cfg.DSN()

	if cfg.DatabaseURL != "" {
		logger.Info("connecting to postgresql database via DATABASE_URL...")
	} else {
		logger.Info("connecting to postgresql database...",
			slog.String("host", cfg.Host),
			slog.Int("port", cfg.Port),
			slog.String("database", cfg.DBName),
			slog.String("user", cfg.User),
			slog.String("sslmode", cfg.SSLMode),
		)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database handle: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify connectivity with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to postgresql database: %w", err)
	}

	logger.Info("connected to postgresql successfully")
	return db, nil
}
