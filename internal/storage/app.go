package storage

import (
	"context"
	"database/sql"
	"errors"
)

type App struct {
	db *sql.DB
}

func NewApp(db *sql.DB) *App {
	a := App{db: db}

	return &a
}

func (a *App) SecretByID(ctx context.Context, appID string) (string, error) {
	row := a.db.QueryRowContext(ctx, "select hashed_secret from apps where id = ?", appID)
	if errors.Is(row.Err(), sql.ErrNoRows) {
		return "", ErrNotFound
	}

	if row.Err() != nil {
		return "", row.Err()
	}

	var hashedSecret string
	if err := row.Scan(&hashedSecret); err != nil {
		return "", err
	}

	return hashedSecret, nil
}

func (a *App) Save(ctx context.Context, appID string, name string, hashedSecret string) error {
	_, err := a.db.ExecContext(ctx, "insert into apps (id, name, hashed_secret) values (?, ?, ?)", appID, name, hashedSecret)

	return err
}

func (a *App) UpdateSecret(ctx context.Context, appID string, hashedSecret string) error {
	_, err := a.db.ExecContext(ctx, "update apps set hashed_secret = ? where id = ?", hashedSecret, appID)

	return err
}

func (a *App) Delete(ctx context.Context, appID string) error {
	_, err := a.db.ExecContext(ctx, "delete from apps where id = ?", appID)

	return err
}
