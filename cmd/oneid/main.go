package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/A-ndrey/oneid/internal/auth"
	"github.com/A-ndrey/oneid/internal/auth/mfa/totp"
	"github.com/A-ndrey/oneid/internal/auth/token"
	"github.com/A-ndrey/oneid/internal/driver"
	"github.com/A-ndrey/oneid/internal/migrations"
	"github.com/A-ndrey/oneid/internal/server/web"
	"github.com/A-ndrey/oneid/internal/storage"
)

func main() {
	cfg := must(readConfig())

	logger := initLogger(cfg.Environment)

	keyBytes := must(base64.StdEncoding.DecodeString(cfg.SigningKey))
	signingKey := must(jwt.ParseEdPrivateKeyFromPEM(keyBytes))

	db := initDB(cfg)
	defer db.Close()

	userStorage := storage.NewUser(db)

	sessionStorage := storage.NewSession(db)
	sessionSvc := token.NewSessionService(sessionStorage)

	jwtSvc := token.NewJWTService(cfg.AppName, jwt.SigningMethodEdDSA, signingKey.(ed25519.PrivateKey))

	userAuthServ := auth.NewUserService(logger, userStorage, jwtSvc, sessionSvc, totp.DefaultConfig)

	handler := must(web.NewHandler(cfg.AppName, userAuthServ, totp.DefaultConfig, logger))

	if err := http.ListenAndServe(net.JoinHostPort(cfg.Server.Host, cfg.Server.Port), handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}

	return val
}

func initLogger(env string) *slog.Logger {
	if env == "dev" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func initDB(cfg Config) *sql.DB {
	var db *sql.DB
	var dialect string
	if cfg.Environment == "dev" {
		db = must(driver.NewSQLite(cfg.Database.Name))
		dialect = "sqlite"
	} else {
		db = must(driver.NewPostgres())
		dialect = "postgres"
	}

	migrations.Migrate(context.Background(), db, dialect)

	return db
}
