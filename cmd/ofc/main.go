package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/auth"
	"github.com/lucasdillmann/open-folio-connect/internal/blobs"
	"github.com/lucasdillmann/open-folio-connect/internal/bootstrap"
	"github.com/lucasdillmann/open-folio-connect/internal/config"
	"github.com/lucasdillmann/open-folio-connect/internal/connect"
	"github.com/lucasdillmann/open-folio-connect/internal/db"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("open-folio-connect", version)
			return nil
		case "code":
			return bootstrap.Command(context.Background(), argAt(2))
		case "set-password":
			return bootstrap.SetPassword(context.Background(), argAt(2), argAt(3))
		default:
			return fmt.Errorf("unknown command %q (try `ofc version`, `ofc code <email>`, "+
				"`ofc set-password <email> <password>`)", os.Args[1])
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)
	warnTransferBaseURL(cfg.BaseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}

	st := store.New(pool)
	if err := bootstrap.Ensure(ctx, st, cfg); err != nil {
		return err
	}

	blobStore, err := blobs.New(cfg.DataDir)
	if err != nil {
		return err
	}

	issuer := auth.NewIssuer(cfg.JWTSecret, cfg.AccessTokenTTL, cfg.BaseURL,
		func(userID uuid.UUID) (uuid.UUID, error) {
			membership, err := st.MembershipForUser(context.Background(), userID)
			if err != nil {
				return uuid.Nil, err
			}
			return membership.TeamID, nil
		})

	mux := http.NewServeMux()
	auth.NewHandler(st, issuer, cfg).Register(mux)
	connect.NewHandler(st, issuer, blobStore, cfg).Register(mux)
	registerOperationalRoutes(mux, pool)

	cors := httpx.NewCORS(cfg.AllowedOrigins.Origins, cfg.AllowedOrigins.All)
	switch {
	case cors.Enabled() && cfg.AllowedOrigins.All:
		slog.Warn("CORS allows every origin; set OFC_ALLOWED_ORIGINS to a list " +
			"once the deployment is reachable from outside a trusted network")
	case cors.Enabled():
		slog.Info("CORS enabled", "origins", cfg.AllowedOrigins.Origins)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           withMiddleware(cors, mux),
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening",
			"addr", cfg.Addr, "baseUrl", cfg.BaseURL, "dataDir", cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func registerOperationalRoutes(mux *http.ServeMux, pool *db.Pool) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
}

func withMiddleware(cors *httpx.CORS, next http.Handler) http.Handler {
	return cors.Middleware(
		httpx.RequestIDMiddleware(recoverer(logRequests(next))))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Debug("request",
			"method", r.Method, "path", r.URL.Path,
			"status", rec.status, "durationMs", time.Since(start).Milliseconds(),
			"requestId", w.Header().Get(httpx.RequestIDHeader))
	})
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic serving request",
					"panic", rec, "path", r.URL.Path,
					"requestId", w.Header().Get(httpx.RequestIDHeader))
				httpx.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func warnTransferBaseURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Port() != "" {
		slog.Warn("OFC_BASE_URL should be an https URL without an explicit port; "+
			"Wealthfolio rejects snapshot transfer destinations that are not https "+
			"on the default port", "baseUrl", raw)
	}
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func argAt(i int) string {
	if i < len(os.Args) {
		return os.Args[i]
	}
	return ""
}
