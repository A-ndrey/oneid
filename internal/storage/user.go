package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/A-ndrey/oneid/internal/model"
)

type User struct {
	db *sql.DB
}

func NewUser(db *sql.DB) *User {
	us := User{db: db}

	return &us
}

func (u *User) FindByEmail(ctx context.Context, email string) (model.User, error) {
	r := u.db.QueryRowContext(ctx, "select id, email, email_confirmed, first_name, last_name, mfa, role from users where email = ?", email)
	if r.Err() != nil {
		return model.User{}, r.Err()
	}

	var usr model.User
	err := r.Scan(&usr.ID, &usr.Email, &usr.EmailConfirmed, &usr.FirstName, &usr.LastName, &usr.MFA, &usr.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}

	return usr, nil
}

func (u *User) FindByID(ctx context.Context, userID string) (model.User, error) {
	r := u.db.QueryRowContext(ctx, "select id, email, email_confirmed, first_name, last_name, mfa, role from users where id == ?", userID)
	if r.Err() != nil {
		return model.User{}, r.Err()
	}

	var usr model.User
	err := r.Scan(&usr.ID, &usr.Email, &usr.EmailConfirmed, &usr.FirstName, &usr.LastName, &usr.MFA, &usr.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}

	return usr, nil
}

func (u *User) GetHashedPassword(ctx context.Context, email string) (string, error) {
	r := u.db.QueryRowContext(ctx, "select password from users where email = ?", email)
	if r.Err() != nil {
		return "", r.Err()
	}

	var hashedPassword string
	err := r.Scan(&hashedPassword)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}

	return hashedPassword, nil
}

func (u *User) Create(ctx context.Context, user model.User, hashedPassword string) error {
	_, err := u.db.ExecContext(ctx, "insert into users (id, email, password) values (?, ?, ?)", user.ID, user.Email, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) GetMFASharedSecret(ctx context.Context, userID string) (string, error) {
	r := u.db.QueryRowContext(ctx, "select mfa_shared_secret from users where id = ?", userID)
	if r.Err() != nil {
		return "", r.Err()
	}

	var secret string
	err := r.Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}

	return secret, nil
}

func (u *User) SaveMFA(ctx context.Context, userID string, mfa string) error {
	_, err := u.db.ExecContext(ctx, "update users set mfa = ? where id = ?", mfa, userID)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) SaveMFASharedSecret(ctx context.Context, userID string, secret string) error {
	_, err := u.db.ExecContext(ctx, "update users set mfa = '', mfa_shared_secret = ? where id = ?", secret, userID)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) ResetMFA(ctx context.Context, userID string) error {
	_, err := u.db.ExecContext(ctx, "update users set mfa = '', mfa_shared_secret = '' where id = ?", userID)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) SaveRestoreKey(ctx context.Context, email string, restoreKey string, ttl time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (u *User) GetRestoreKey(ctx context.Context, email string) (string, time.Time, error) {
	// TODO implement me
	panic("implement me")
}
