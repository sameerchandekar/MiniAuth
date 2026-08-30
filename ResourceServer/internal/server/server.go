package server

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
)

// Server wraps http.Server with graceful lifecycle controls.
type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	cfg        *config.Config
}

// New creates and configures a new Server instance.
func New(cfg *config.Config, staticPubKey *rsa.PublicKey, logger *slog.Logger) *Server {
	router := SetupRouter(cfg, staticPubKey, logger)

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
	s.logger.Info("starting resource server",
		slog.String("addr", s.httpServer.Addr),
		slog.String("issuer_url", s.cfg.IssuerURL),
		slog.String("jwks_url", s.cfg.JWKSURL),
	)

	err := s.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down resource server gracefully...")
	return s.httpServer.Shutdown(ctx)
}
