package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/redis/go-redis/v9"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
)

// Server wraps http.Server with graceful lifecycle controls.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	cfg        *config.Config
}

// New creates and configures a new Server instance.
func New(cfg *config.Config, rdb *redis.Client, logger *slog.Logger) *Server {
	router := SetupRouter(cfg, rdb, logger)

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
	s.logger.Info("starting client service",
		slog.String("addr", s.httpServer.Addr),
		slog.String("auth_server_url", s.cfg.AuthServerURL),
		slog.String("client_id", s.cfg.ClientID),
		slog.String("redirect_uri", s.cfg.RedirectURI),
	)

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down client service gracefully...")
	return s.httpServer.Shutdown(ctx)
}
