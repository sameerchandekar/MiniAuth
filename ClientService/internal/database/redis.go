package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
)

// ConnectRedis creates and validates a connection to Redis using the provided configuration.
func ConnectRedis(cfg config.RedisConfig, logger *slog.Logger) (*redis.Client, error) {
	opts, err := cfg.ClientOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis options: %w", err)
	}

	if cfg.URL != "" {
		logger.Info("connecting to redis via REDIS_URL...")
	} else {
		logger.Info("connecting to redis...",
			slog.String("addr", opts.Addr),
			slog.String("username", opts.Username),
			slog.Int("db", opts.DB),
		)
	}

	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("failed to connect to redis at %s: %w", opts.Addr, err)
	}

	logger.Info("connected to redis successfully", slog.String("addr", opts.Addr))
	return rdb, nil
}

// NewRedisClient initializes a Redis client without an immediate ping check.
func NewRedisClient(cfg config.RedisConfig) (*redis.Client, error) {
	opts, err := cfg.ClientOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis options: %w", err)
	}

	return redis.NewClient(opts), nil
}
