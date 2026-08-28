package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/config"
)

// Connect establishes a connection pool to PostgreSQL.
func Connect(cfg config.DatabaseConfig, logger *slog.Logger) (*sql.DB, error) {
	dsn := cfg.DSN()

	if cfg.DatabaseURL != "" {
		logger.Info("connecting to PostgreSQL via DATABASE_URL...")
	} else {
		logger.Info("connecting to PostgreSQL...",
			slog.String("host", cfg.Host),
			slog.Int("port", cfg.Port),
			slog.String("database", cfg.DBName),
			slog.String("user", cfg.User),
		)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database handle: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	logger.Info("connected to PostgreSQL successfully")
	return db, nil
}
