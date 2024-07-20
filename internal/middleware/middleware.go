package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/A-ndrey/oneid/internal/auth"
)

type AppAuthenticator interface {
	Auth(ctx context.Context, appID string, secretKey string) error
}

type Link func(http.Handler) http.Handler

func Attach(handler http.Handler, middlewares ...Link) http.Handler {
	m := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		m = middlewares[i](m)
	}
	return m
}

func Logging(logger *slog.Logger) Link {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			handler.ServeHTTP(w, r)

			logger.Info("", slog.String("method", r.Method), slog.String("path", r.URL.EscapedPath()), slog.Duration("dur", time.Since(start)))
		})
	}
}

func HTMXFilter() Link {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && r.Header.Get("HX-Request") != "true" {
				http.NotFound(w, r)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}
}

func AppAuth(aa AppAuthenticator) Link {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			appID := r.Header.Get("X-App-Id")
			secretKey := r.Header.Get("X-App-Secret")

			if err := aa.Auth(r.Context(), appID, secretKey); err != nil {
				if errors.Is(err, auth.ErrUnauthorized) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}
}
