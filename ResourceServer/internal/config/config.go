package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds configuration settings for the ResourceServer.
type Config struct {
	Host         string
	Port         int
	Environment  string
	LogLevel     string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// JWT Verification Settings
	IssuerURL      string        // Expected token issuer (e.g. "http://localhost:8080")
	Audience       string        // Expected token audience (e.g. "client-id-001")
	JWKSURL        string        // JWKS public keys endpoint (e.g. "http://localhost:8080/.well-known/jwks.json")
	PublicKeyPath  string        // Local RSA public key PEM path (e.g. "keys/public_key.pem")
	PublicKeyPEM   string        // Inline RSA public key PEM string
	JWKSCacheTTL   time.Duration // Cache duration for remote JWKS (default: 1 hour)
}

// Load loads configuration from environment variables and optional .env file.
func Load() *Config {
	loadDotEnv(".env")
	loadDotEnv("ResourceServer/.env")
	loadDotEnv("../ResourceServer/.env")
	loadDotEnv("../.env")

	return &Config{
		Host:         getEnv("HOST", "0.0.0.0"),
		Port:         getEnvAsInt("PORT", 8082),
		Environment:  getEnv("APP_ENV", "development"),
		LogLevel:     getEnv("LOG_LEVEL", "debug"),
		ReadTimeout:  getEnvAsDuration("READ_TIMEOUT", 15*time.Second),
		WriteTimeout: getEnvAsDuration("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:  getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),

		IssuerURL:     getEnv("ISSUER_URL", "http://localhost:8080"),
		Audience:      getEnv("AUDIENCE", ""),
		JWKSURL:       getEnv("JWKS_URL", "http://localhost:8080/.well-known/jwks.json"),
		PublicKeyPath: getEnv("JWT_PUBLIC_KEY_PATH", "keys/public_key.pem"),
		PublicKeyPEM:  getEnv("JWT_PUBLIC_KEY", ""),
		JWKSCacheTTL:  getEnvAsDuration("JWKS_CACHE_TTL", 1*time.Hour),
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
