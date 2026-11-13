// Package server runs a service's HTTP servers and shuts them down in the order the gateway
// needs, so no request is cut off during a deploy:
//
//  1. SIGTERM (ctx cancelled): /readyz turns 503 and every answer tells Envoy to stop
//     sending new requests here (health.Probes.Drain),
//  2. wait Drain for that to reach the gateway,
//  3. stop every server, letting in-flight requests finish within ShutdownTimeout,
//  4. return; the caller then closes its database and broker connections.
//
// If a server fails (its port is taken), Run returns that error at once.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// Defaults suited to the gateway's health checks (every 2-5 s, healthy_threshold 1).
const (
	DefaultDrain           = 5 * time.Second
	DefaultShutdownTimeout = 20 * time.Second
)

// New is an http.Server with timeouts every service should have: slow or idle clients
// can't hold connections open, and headers are capped at 32 KiB.
func New(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Drainer is what Run tells to stop taking new traffic (health.Probes).
type Drainer interface{ Drain() }

// Config for Run. Zero durations take the defaults.
type Config struct {
	Servers         []*http.Server
	Drainer         Drainer       // usually the service's health.Probes
	Drain           time.Duration // between "stop sending me traffic" and stopping
	ShutdownTimeout time.Duration // for in-flight requests to finish
	// Background tasks run until shutdown begins; their ctx is cancelled after the drain.
	// A task returning an error stops the service.
	Background []func(ctx context.Context) error
}

// Run serves until ctx is cancelled, then shuts down as described above.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if len(cfg.Servers) == 0 {
		return errors.New("server: nothing to run")
	}
	if cfg.Drain == 0 {
		cfg.Drain = DefaultDrain
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = DefaultShutdownTimeout
	}

	// Bind every port first, so a taken port fails start-up before anything is served.
	lns := make([]net.Listener, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return fmt.Errorf("server: listen %s: %w", srv.Addr, err)
		}
		lns = append(lns, ln)
	}

	// serveCtx ends only after the drain, so servers keep answering meanwhile.
	serveCtx, stopServing := context.WithCancel(context.Background())
	defer stopServing()
	g, gctx := errgroup.WithContext(serveCtx)
	for i, srv := range cfg.Servers {
		g.Go(func() error { return serve(gctx, srv, lns[i], cfg.ShutdownTimeout) })
	}
	for _, task := range cfg.Background {
		g.Go(func() error { return task(gctx) })
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down", "drain", cfg.Drain.String())
		if cfg.Drainer != nil {
			cfg.Drainer.Drain()
		}
		select {
		case <-time.After(cfg.Drain):
		case <-gctx.Done(): // something failed meanwhile: no point waiting
		}
		stopServing()
	case <-gctx.Done(): // a server or task failed
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("stopped")
	return nil
}

func serve(ctx context.Context, srv *http.Server, ln net.Listener, timeout time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
