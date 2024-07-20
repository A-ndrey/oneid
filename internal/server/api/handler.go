package api

import (
	"log/slog"
	"net/http"

	"github.com/A-ndrey/oneid/internal/middleware"
)

type KeyProvider interface {
	VerificationKey() ([]byte, error)
}

type Handler struct {
	inner       http.Handler
	keyProvider KeyProvider
}

func NewHandler(logger *slog.Logger, keyProvider KeyProvider) *Handler {
	h := Handler{
		keyProvider: keyProvider,
	}

	mx := http.NewServeMux()
	mx.HandleFunc("GET /api/jwks", h.jwks)

	h.inner = middleware.Attach(mx, middleware.Logging(logger))

	return &h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.inner.ServeHTTP(w, r)
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	key, err := h.keyProvider.VerificationKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
