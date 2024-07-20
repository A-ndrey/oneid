package token

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/A-ndrey/oneid/internal/auth/secret"
)

const secretSize = 25

type SessionStorage interface {
	Save(ctx context.Context, userID, userAgent, hashedToken string, expDate time.Time) error
	GetToken(ctx context.Context, userID string, userAgent string) (string, time.Time, error)
	Delete(ctx context.Context, userID string, userAgent string) error
	GetAllUserAgents(ctx context.Context, userID string) ([]string, error)
}

type SessionService struct {
	storage SessionStorage
}

func NewSessionService(rtStorage SessionStorage) *SessionService {
	return &SessionService{
		storage: rtStorage,
	}
}

func (s *SessionService) Issue(ctx context.Context, userID string, userAgent string, validFor time.Duration) (string, error) {
	rToken, err := secret.New(secretSize)
	if err != nil {
		return "", err
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(rToken), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	if err := s.storage.Save(ctx, userID, userAgent, string(hashedToken), time.Now().Add(validFor)); err != nil {
		return "", err
	}

	return rToken, nil
}

func (s *SessionService) Verify(ctx context.Context, userID string, userAgent string, rToken string) error {
	hashedToken, expDate, err := s.storage.GetToken(ctx, userID, userAgent)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(rToken)); err != nil {
		return err
	}

	if expDate.Before(time.Now()) {
		return errors.New("session token has expired")
	}

	return nil
}

func (s *SessionService) UserSessions(ctx context.Context, userID string) ([]string, error) {
	return s.storage.GetAllUserAgents(ctx, userID)
}

func (s *SessionService) Delete(ctx context.Context, userID string, userAgent string) error {
	return s.storage.Delete(ctx, userID, userAgent)
}
