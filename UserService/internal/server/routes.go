package server

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/sameerchandekar/MiniAuth/UserService/api"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/config"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/handler"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/repository"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/service"
)

// SetupRouter initializes the Chi HTTP router with middlewares and route handlers.
func SetupRouter(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// Base middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(structuredLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Repositories
	permRepo := repository.NewPermissionRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	userRepo := repository.NewUserRepository(db, roleRepo)
	clientRepo := repository.NewClientRepository(db)

	// Services
	permService := service.NewPermissionService(permRepo)
	roleService := service.NewRoleService(roleRepo, permRepo)
	userService := service.NewUserService(userRepo, roleRepo)
	clientService := service.NewClientService(clientRepo)

	// Handlers
	permHandler := handler.NewPermissionHandler(permService)
	roleHandler := handler.NewRoleHandler(roleService)
	userHandler := handler.NewUserHandler(userService)
	clientHandler := handler.NewClientHandler(clientService)
	healthHandler := handler.NewHealthHandler(db)

	// Probes & Swagger Docs
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/swagger", http.StatusMovedPermanently)
	})
	r.Get("/healthz", healthHandler.Healthz)
	r.Get("/readyz", healthHandler.Readyz)

	// Swagger UI Endpoints
	r.Get("/swagger", api.SwaggerUIHandler)
	r.Get("/swagger/", api.SwaggerUIHandler)
	r.Get("/swagger/doc.json", api.SwaggerJSONHandler)

	// API v1 Subrouter
	r.Route("/api/v1", func(r chi.Router) {
		// User Management
		r.Route("/users", func(r chi.Router) {
			r.Post("/", userHandler.Create)
			r.Get("/", userHandler.List)
			r.Get("/{id}", userHandler.Get)
			r.Post("/{id}/roles", userHandler.AssignRole)
			r.Delete("/{id}/roles/{roleId}", userHandler.RemoveRole)
		})

		// Role Management
		r.Route("/roles", func(r chi.Router) {
			r.Post("/", roleHandler.Create)
			r.Get("/", roleHandler.List)
			r.Get("/{id}", roleHandler.Get)
			r.Post("/{id}/permissions", roleHandler.AssignPermission)
			r.Delete("/{id}/permissions/{permissionId}", roleHandler.RemovePermission)
		})

		// Permission Management
		r.Route("/permissions", func(r chi.Router) {
			r.Post("/", permHandler.Create)
			r.Get("/", permHandler.List)
			r.Get("/{id}", permHandler.Get)
		})

		// OAuth 2.0 Client Management
		r.Route("/clients", func(r chi.Router) {
			r.Post("/", clientHandler.Register)
			r.Get("/", clientHandler.List)
			r.Get("/{clientId}", clientHandler.Get)
			r.Delete("/{clientId}", clientHandler.Delete)

			// Scopes
			r.Post("/{clientId}/scopes", clientHandler.AddScope)
			r.Put("/{clientId}/scopes", clientHandler.SetScopes)
			r.Delete("/{clientId}/scopes/{scope}", clientHandler.RemoveScope)

			// Redirect URIs
			r.Post("/{clientId}/redirect-uris", clientHandler.AddRedirectURI)
			r.Put("/{clientId}/redirect-uris", clientHandler.SetRedirectURIs)
			r.Delete("/{clientId}/redirect-uris", clientHandler.RemoveRedirectURI)
		})
	})

	return r
}

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
