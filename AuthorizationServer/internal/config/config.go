package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds all server configuration settings.
type Config struct {
	// Server settings
	Host         string
	Port         int
	Environment  string // development, staging, production
	LogLevel     string // debug, info, warn, error
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// OAuth 2.0 / OIDC Identity Provider settings
	IssuerURL string

	// Database settings
	DB DatabaseConfig

	// Redis settings
	Redis RedisConfig

	// JWT settings
	JWT JWTConfig
}

// JWTConfig holds JWT signing and expiration settings (RSA RS256 / HMAC HS256).
type JWTConfig struct {
	PrivateKeyPath string        // Path to RSA private key PEM file (e.g. "keys/private_key.pem")
	PublicKeyPath  string        // Path to RSA public key PEM file (e.g. "keys/public_key.pem")
	PrivateKeyPEM  string        // Inline RSA private key PEM string
	PublicKeyPEM   string        // Inline RSA public key PEM string
	KeyID          string        // Key ID for JWKS and JWT header (e.g. "miniauth-key-1")
	Secret         string        // Fallback symmetric HMAC secret
	TTL            time.Duration // JWT access token expiration (default: 1 hour)
}

// DatabaseConfig holds PostgreSQL connection and migration settings.
type DatabaseConfig struct {
	DatabaseURL     string // Full connection string (e.g. Neon, Supabase, Heroku)
	Host            string
	Port            int
	User            string
	Password        string
	DBName          string
	SSLMode         string
	AutoMigrate     bool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN returns the PostgreSQL connection URL string.
// If DatabaseURL is specified (e.g. from Neon, Supabase, or Heroku), it is used directly.
func (d *DatabaseConfig) DSN() string {
	if d.DatabaseURL != "" {
		return d.DatabaseURL
	}

	encodedUser := url.QueryEscape(d.User)
	encodedPassword := url.QueryEscape(d.Password)

	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		encodedUser, encodedPassword, d.Host, d.Port, d.DBName, d.SSLMode)
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	URL      string // Full redis:// or rediss:// connection string (e.g. Upstash, Redis Cloud)
	Addr     string // host:port address (e.g. "localhost:6379" or "fulgent-jump-maroon-88822.db.redis.io:14418")
	Username string
	Password string
	DB       int
}

// ClientOptions creates *redis.Options configured according to the RedisConfig.
func (r *RedisConfig) ClientOptions() (*redis.Options, error) {
	if r.URL != "" {
		opts, err := redis.ParseURL(r.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
		}
		if r.Username != "" && opts.Username == "" {
			opts.Username = r.Username
		}
		if r.Password != "" && opts.Password == "" {
			opts.Password = r.Password
		}
		if r.DB != 0 && opts.DB == 0 {
			opts.DB = r.DB
		}
		return opts, nil
	}

	addr := r.Addr
	if addr == "" {
		addr = "localhost:6379"
	}

	return &redis.Options{
		Addr:     addr,
		Username: r.Username,
		Password: r.Password,
		DB:       r.DB,
	}, nil
}

// Load loads configuration from environment variables (and optional .env file) with sensible defaults.
func Load() *Config {
	// Automatically load .env file if it exists
	loadDotEnv(".env")
	loadDotEnv("AuthorizationServer/.env")
	loadDotEnv("../.env")

	dbURL := getEnv("DATABASE_URL", getEnv("DB_URL", ""))
	redisURL := getEnv("REDIS_URL", "")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")

	return &Config{
		Host:         getEnv("HOST", "0.0.0.0"),
		Port:         getEnvAsInt("PORT", 8080),
		Environment:  getEnv("APP_ENV", "development"),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
		ReadTimeout:  getEnvAsDuration("READ_TIMEOUT", 15*time.Second),
		WriteTimeout: getEnvAsDuration("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:  getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),
		IssuerURL:    getEnv("ISSUER_URL", "http://localhost:8080"),

		DB: DatabaseConfig{
			DatabaseURL:     dbURL,
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", "postgres"),
			DBName:          getEnv("DB_NAME", "miniauth"),
			SSLMode:         getEnv("DB_SSLMODE", "disable"),
			AutoMigrate:     getEnvAsBool("DB_AUTO_MIGRATE", true),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},

		Redis: RedisConfig{
			URL:      redisURL,
			Addr:     redisAddr,
			Username: getEnv("REDIS_USERNAME", getEnv("REDIS_USER", "")),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},

		JWT: JWTConfig{
			PrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "keys/private_key.pem"),
			PublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "keys/public_key.pem"),
			PrivateKeyPEM:  getEnv("JWT_PRIVATE_KEY", ""),
			PublicKeyPEM:   getEnv("JWT_PUBLIC_KEY", ""),
			KeyID:          getEnv("JWT_KEY_ID", "miniauth-key-1"),
			Secret:         getEnv("JWT_SECRET", "miniauth-default-jwt-secret-key-32bytes-long"),
			TTL:            getEnvAsDuration("JWT_TTL", 1*time.Hour),
		},
	}
}

// Address returns the combined host:port string for the HTTP server.
func (c *Config) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// loadDotEnv parses a standard .env file if present and sets environment variables if not already set.
func loadDotEnv(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// Strip surrounding quotes if present
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}

		// Only set if not already present in the OS environment
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	valStr := getEnv(key, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return fallback
}

func getEnvAsBool(key string, fallback bool) bool {
	valStr := getEnv(key, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return fallback
}

func getEnvAsDuration(key string, fallback time.Duration) time.Duration {
	valStr := getEnv(key, "")
	if val, err := time.ParseDuration(valStr); err == nil {
		return val
	}
	return fallback
}
