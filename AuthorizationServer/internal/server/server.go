package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

// Server wraps the standard http.Server with graceful lifecycle controls.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	cfg        *config.Config
}

// New creates and configures a new Server instance.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	router := SetupRouter(cfg, logger)

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

// Start runs the HTTP server in a blocking call.
func (s *Server) Start() error {
	s.logger.Info("starting authorization server",
		slog.String("addr", s.httpServer.Addr),
		slog.String("environment", s.cfg.Environment),
		slog.String("issuer_url", s.cfg.IssuerURL),
	)

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server without interrupting active connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down HTTP server gracefully...")
	return s.httpServer.Shutdown(ctx)
}
