package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/golang-jwt/jwt/v5"

	"github.com/A-ndrey/oneid/internal/auth"
	"github.com/A-ndrey/oneid/internal/auth/mfa/totp"
	"github.com/A-ndrey/oneid/internal/auth/token"
	"github.com/A-ndrey/oneid/internal/driver"
	"github.com/A-ndrey/oneid/internal/migrations"
	"github.com/A-ndrey/oneid/internal/server"
	"github.com/A-ndrey/oneid/internal/storage"
)

func main() {
	cfg := must(readConfig())

	logger := initLogger(cfg.Environment)

	keyBytes := must(base64.StdEncoding.DecodeString(cfg.SigningKey))
	signingKey := must(jwt.ParseEdPrivateKeyFromPEM(keyBytes))

	db := initDB(cfg)
	defer db.Close()

	jwtSvc := token.NewJWTService(cfg.AppName, jwt.SigningMethodEdDSA, signingKey.(ed25519.PrivateKey))

	userStorage := storage.NewUser(db)
	userAuthServ := auth.NewUserService(logger, userStorage, jwtSvc, totp.DefaultConfig)

	appStorage := storage.NewApp(db)
	appService := auth.NewAppService(appStorage)

	authHandler := server.NewAuthHandler(logger, userAuthServ, jwtSvc)
	appHandler := server.NewAppHandler(logger, appService)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		authHandler.Run(ctx, net.JoinHostPort(cfg.AuthServer.Host, cfg.AuthServer.Port))
	}()
	go func() {
		defer wg.Done()
		appHandler.Run(ctx, net.JoinHostPort(cfg.AppServer.Host, cfg.AppServer.Port))
	}()

	wg.Wait()
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
