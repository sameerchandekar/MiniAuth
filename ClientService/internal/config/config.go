package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config holds configuration settings for the ClientService.
type Config struct {
	// Server settings
	Host         string
	Port         int
	Environment  string
	LogLevel     string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// OAuth 2.0 Client Settings
	AuthServerURL string // e.g. "http://localhost:8080"
	ClientID      string // e.g. "client-id-001"
	ClientSecret  string // e.g. "mock_client_secret"
	RedirectURI   string // e.g. "http://localhost:9000/oauth/callback"
	Scopes        string // e.g. "openid profile email"

	// Redis settings
	Redis RedisConfig
}

// RedisConfig holds Redis connection settings for state and session storage.
type RedisConfig struct {
	URL      string // Full redis:// connection string
	Addr     string // host:port address (e.g. "localhost:6379" or "fulgent-jump-maroon-88822.db.redis.io:14418")
	Username string
	Password string
	DB       int
}

// ClientOptions creates *redis.Options configured according to the RedisConfig.
func (r *RedisConfig) ClientOptions() (*redis.Options, error) {
	if r.URL != "" {
		return redis.ParseURL(r.URL)
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

// Load loads configuration from environment variables and optional .env file.
func Load() *Config {
	loadDotEnv(".env")
	loadDotEnv("ClientService/.env")
	loadDotEnv("../ClientService/.env")
	loadDotEnv("../.env")

	redisURL := getEnv("REDIS_URL", "")
	redisAddr := getEnv("REDIS_ADDR", "localhost:6379")

	return &Config{
		Host:         getEnv("HOST", "0.0.0.0"),
		Port:         getEnvAsInt("PORT", 9000),
		Environment:  getEnv("APP_ENV", "development"),
		LogLevel:     getEnv("LOG_LEVEL", "debug"),
		ReadTimeout:  getEnvAsDuration("READ_TIMEOUT", 15*time.Second),
		WriteTimeout: getEnvAsDuration("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:  getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),

		AuthServerURL: getEnv("AUTH_SERVER_URL", "http://localhost:8080"),
		ClientID:      getEnv("CLIENT_ID", "client-id-001"),
		ClientSecret:  getEnv("CLIENT_SECRET", ""),
		RedirectURI:   getEnv("REDIRECT_URI", "http://localhost:9000/oauth/callback"),
		Scopes:        getEnv("SCOPES", "openid profile email"),

		Redis: RedisConfig{
			URL:      redisURL,
			Addr:     redisAddr,
			Username: getEnv("REDIS_USERNAME", getEnv("REDIS_USER", "")),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
	}
}

// Address returns host:port for the HTTP server.
func (c *Config) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

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

		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}

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

func getEnvAsDuration(key string, fallback time.Duration) time.Duration {
	valStr := getEnv(key, "")
	if val, err := time.ParseDuration(valStr); err == nil {
		return val
	}
	return fallback
}
