package server

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/handler"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

// SetupRouter initializes the chi router with middlewares, repositories, services, and route handlers.
func SetupRouter(cfg *config.Config, db *sql.DB, rdb *redis.Client, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(structuredLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration for OAuth clients and SPAs
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // 5 minutes
	}))

	// Dependency Injection: Repositories & Services
	var clientRepo repository.ClientRepository
	if db != nil {
		clientRepo = repository.NewPostgresClientRepository(db)
	} else {
		clientRepo = repository.NewMemoryClientRepository()
	}

	var authCodeRepo repository.AuthCodeRepository
	if rdb != nil {
		authCodeRepo = repository.NewRedisAuthCodeRepository(rdb)
	} else {
		authCodeRepo = repository.NewMemoryAuthCodeRepository()
	}
	oauthService := service.NewOAuthService(clientRepo, authCodeRepo)

	// Handlers
	healthHandler := handler.NewHealthHandler(cfg)
	oauthHandler := handler.NewOAuthHandler(oauthService)

	// Health and Status Handlers
	r.Get("/", healthHandler.Root)
	r.Get("/healthz", healthHandler.Healthz)
	r.Get("/readyz", healthHandler.Readyz)

	// OAuth 2.0 / OIDC Authorize Endpoint (Standard & subrouted)
	r.Get("/authorize", oauthHandler.Authorize)

	// Subrouter structure for OAuth & OIDC endpoints
	r.Route("/oauth", func(r chi.Router) {
		r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"oauth service ready"}`))
		})
		r.Get("/authorize", oauthHandler.Authorize)
		// Future OAuth endpoints:
		// r.Post("/token", oauthHandler.Token)
		// r.Post("/revoke", oauthHandler.Revoke)
	})

	r.Route("/.well-known", func(r chi.Router) {
		// Future OIDC endpoints:
		// r.Get("/openid-configuration", oidcHandler.Discovery)
		// r.Get("/jwks.json", jwksHandler.JWKS)
	})

	return r
}

// structuredLogger returns a chi middleware that logs HTTP requests using log/slog.
func structuredLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()

			defer func() {
				logger.Info("http request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Duration("duration", time.Since(t1)),
					slog.String("req_id", middleware.GetReqID(r.Context())),
					slog.String("remote_addr", r.RemoteAddr),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
