package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/handler"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/service"
)

// SetupRouter initializes the chi router for ClientService with handlers and middlewares.
func SetupRouter(cfg *config.Config, rdb *redis.Client, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(structuredLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	// Services & Handlers
	var stateStore service.StateStore
	if rdb != nil {
		stateStore = service.NewRedisStateStore(rdb)
	} else {
		stateStore = service.NewMemoryStateStore()
	}

	oauthClientSvc := service.NewOAuthClientService(cfg, stateStore, nil)
	oauthClientHandler := handler.NewOAuthClientHandler(oauthClientSvc)

	// Routes
	r.Get("/", oauthClientHandler.Index)
	r.Get("/login", oauthClientHandler.Login)
	r.Get("/oauth/callback", oauthClientHandler.Callback)

	// Liveness Probe
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy","service":"client-service"}`))
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
