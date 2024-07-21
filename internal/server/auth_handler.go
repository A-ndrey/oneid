package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/A-ndrey/oneid/internal/auth"
	"github.com/A-ndrey/oneid/internal/server/middleware"
)

type userCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type KeyProvider interface {
	VerificationKey() ([]byte, error)
}

type AuthHandler struct {
	userAuth    *auth.UserService
	keyProvider KeyProvider
	logger      *slog.Logger
}

func NewAuthHandler(logger *slog.Logger, userAuth *auth.UserService, keyProvider KeyProvider) *AuthHandler {
	return &AuthHandler{
		userAuth:    userAuth,
		keyProvider: keyProvider,
		logger:      logger,
	}
}

func (h *AuthHandler) Run(ctx context.Context, addr string) {
	mx := http.NewServeMux()
	mx.HandleFunc("GET /jwks", h.jwks)
	mx.HandleFunc("POST /signup", h.signup)
	mx.HandleFunc("POST /login", h.login)
	mx.HandleFunc("POST /mfa/enable", h.enableMFA)
	mx.HandleFunc("POST /mfa/disable", h.disableMFA)

	handler := middleware.Attach(mx, middleware.Logging(h.logger))

	srv := http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.logger.Error(err.Error())
		}
	}()

	<-ctx.Done()

	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(timeout); err != nil {
		h.logger.Error(err.Error())
	}
}

func (h *AuthHandler) signup(w http.ResponseWriter, r *http.Request) {
	var credentials userCredentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err := h.userAuth.SignUp(r.Context(), credentials.Email, credentials.Password)
	if errors.Is(err, auth.ErrUserExists) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) login(w http.ResponseWriter, r *http.Request) {
	var credentials userCredentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := h.userAuth.Login(r.Context(), credentials.Email, credentials.Password)
	if errors.Is(err, auth.ErrUserNotFound) || errors.Is(err, auth.ErrIncorrectPassword) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jwt, err := h.userAuth.GenerateAccessToken(r.Context(), user, 0)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{Token: jwt})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) enableMFA(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

func (h *AuthHandler) disableMFA(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

func (h *AuthHandler) jwks(w http.ResponseWriter, _ *http.Request) {
	key, err := h.keyProvider.VerificationKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
