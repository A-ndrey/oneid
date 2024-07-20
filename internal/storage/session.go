package storage

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"
)

type Session struct {
	db *sql.DB
}

func NewSession(db *sql.DB) *Session {
	return &Session{
		db: db,
	}
}

func (r *Session) Save(ctx context.Context, userID, userAgent, hashedToken string, expDate time.Time) error {
	result, err := r.db.ExecContext(ctx, "update sessions set hashed_token = ?, exp_date = ? where user_id = ? and user_agent = ?", hashedToken, expDate, userID, userAgent)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows > 0 {
		return nil
	}

	_, err = r.db.ExecContext(ctx, "insert into sessions (user_id, user_agent, hashed_token, exp_date) values (?, ?, ?, ?)", userID, userAgent, hashedToken, expDate)
	if err != nil {
		return err
	}

	return nil
}

func (r *Session) GetToken(ctx context.Context, userID string, userAgent string) (string, time.Time, error) {
	row := r.db.QueryRowContext(ctx, "select hashed_token, exp_date from sessions where user_id = ? and user_agent = ?", userID, userAgent)
	if row.Err() != nil {
		return "", time.Time{}, row.Err()
	}

	var expDate time.Time
	var rToken string
	err := row.Scan(&rToken, &expDate)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}

	return rToken, expDate, nil
}

func (r *Session) GetAllUserAgents(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, "select user_agent from sessions where user_id = ?", userID)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if rows.Err() != nil {
		log.Println(err)
		return nil, rows.Err()
	}

	var userAgents []string
	for rows.Next() {
		var userAgent string
		if err := rows.Scan(&userAgent); err != nil {
			return nil, err
		}

		userAgents = append(userAgents, userAgent)
	}

	return userAgents, nil
}

func (r *Session) Delete(ctx context.Context, userID string, userAgent string) error {
	_, err := r.db.ExecContext(ctx, "delete from sessions where user_id = ? and user_agent = ?", userID, userAgent)

	return err
}
