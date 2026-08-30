package server

import (
	"crypto/rsa"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/handler"
	appMiddleware "github.com/sameerchandekar/MiniAuth/ResourceServer/internal/middleware"
)

// SetupRouter initializes routes and middleware for the ResourceServer.
func SetupRouter(cfg *config.Config, staticPubKey *rsa.PublicKey, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(structuredLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	// Auth Middleware & Handlers
	authMw := appMiddleware.NewAuthMiddleware(cfg, staticPubKey, logger)
	emailHandler := handler.NewEmailHandler()
	swaggerHandler := handler.NewSwaggerHandler()

	// Public Health Liveness Probe
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"resource-server"}`))
	})

	// Swagger UI & OpenAPI Specification
	r.Get("/swagger", swaggerHandler.UI)
	r.Get("/swagger/", swaggerHandler.UI)
	r.Get("/docs", swaggerHandler.UI)
	r.Get("/swagger/openapi.yaml", swaggerHandler.Spec)

	// Protected Resource Endpoints (Require RS256 JWT Bearer Authentication)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authMw.Authenticate)

		// GET /api/v1/emails -> Requires 'read' or 'email' scope
		r.With(appMiddleware.RequireScope("read", "email", "read:email")).Get("/emails", emailHandler.ListEmails)

		// POST /api/v1/emails -> Requires 'write' scope (Denied if token only has 'read')
		r.With(appMiddleware.RequireScope("write", "write:email")).Post("/emails", emailHandler.SendEmail)

		// GET /api/v1/userinfo -> Returns caller subject & claims
		r.Get("/userinfo", emailHandler.UserInfo)
	})

	return r
}

func structuredLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()

			defer func() {
				if logger != nil {
					logger.Info("http request",
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.Int("status", ww.Status()),
						slog.Int("bytes", ww.BytesWritten()),
						slog.Duration("duration", time.Since(t1)),
						slog.String("remote_addr", r.RemoteAddr),
					)
				}
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
