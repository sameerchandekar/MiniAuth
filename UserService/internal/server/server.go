package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/config"
)

// Server wraps http.Server with graceful lifecycle controls.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	cfg        *config.Config
}

// New creates and configures a new Server instance.
func New(cfg *config.Config, db *sql.DB, logger *slog.Logger) *Server {
	router := SetupRouter(cfg, db, logger)

	httpSrv := &http.Server{
		Addr:         cfg.Address(),
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return &Server{
		httpServer: httpSrv,
		logger:     logger,
		cfg:        cfg,
	}
}

// Start runs the HTTP server.
func (s *Server) Start() error {
	s.logger.Info("starting UserService HTTP server",
		slog.String("addr", s.httpServer.Addr),
		slog.String("environment", s.cfg.Environment),
		slog.String("swagger_url", fmt.Sprintf("http://localhost:%d/swagger", s.cfg.Port)),
	)

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// Shutdown performs a graceful shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down UserService gracefully...")
	return s.httpServer.Shutdown(ctx)
}
