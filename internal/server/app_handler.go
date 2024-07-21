package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/A-ndrey/oneid/internal/auth"
)

type AppHandler struct {
	service *auth.AppService
	logger  *slog.Logger
}

func NewAppHandler(logger *slog.Logger, service *auth.AppService) *AppHandler {
	return &AppHandler{
		service: service,
		logger:  logger,
	}
}

func (m *AppHandler) Run(ctx context.Context, addr string) {
	mx := http.NewServeMux()
	mx.HandleFunc("POST /app", m.register)
	mx.HandleFunc("DELETE /app", m.delete)

	srv := http.Server{
		Addr:    addr,
		Handler: mx,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logger.Error(err.Error())
		}
	}()

	<-ctx.Done()

	timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(timeout); err != nil {
		m.logger.Error(err.Error())
	}
}

func (m *AppHandler) register(w http.ResponseWriter, r *http.Request) {
	inputData := struct {
		Name string `json:"name"`
	}{}

	if err := json.NewDecoder(r.Body).Decode(&inputData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	appID, secretKey, err := m.service.RegisterApp(r.Context(), inputData.Name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	outputData := struct {
		AppID     string `json:"appId"`
		SecretKey string `json:"secretKey"`
	}{
		AppID:     appID,
		SecretKey: secretKey,
	}

	if err := json.NewEncoder(w).Encode(outputData); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (m *AppHandler) delete(w http.ResponseWriter, r *http.Request) {
	inputData := struct {
		AppID string `json:"appId"`
	}{}

	if err := json.NewDecoder(r.Body).Decode(&inputData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := m.service.DeleteApp(r.Context(), inputData.AppID); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
