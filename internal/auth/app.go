package auth

import (
	"context"
	"errors"

	"github.com/rs/xid"

	"github.com/A-ndrey/oneid/internal/auth/secret"
)

const secretSize = 29

var (
	ErrUnauthorized = errors.New("unauthorized")
)

type AppStorage interface {
	SecretByID(ctx context.Context, appID string) (string, error)
	Save(ctx context.Context, appID string, name string, hashedSecret string) error
	UpdateSecret(ctx context.Context, appID string, hashedSecret string) error
	Delete(ctx context.Context, appID string) error
}

type AppService struct {
	storage AppStorage
}

func NewAppService(storage AppStorage) *AppService {
	as := AppService{
		storage: storage,
	}

	return &as
}

func (a *AppService) Auth(ctx context.Context, appID string, secretKey string) error {
	hashedSecret, err := a.storage.SecretByID(ctx, appID)
	if err != nil {
		return err
	}

	ok, err := secret.Compare(secretKey, hashedSecret)
	if err != nil {
		return err
	}

	if !ok {
		return ErrUnauthorized
	}

	return nil
}

func (a *AppService) RegisterApp(ctx context.Context, name string) (string, string, error) {
	appID := xid.New().String()
	secretKey, err := secret.New(secretSize)
	if err != nil {
		return "", "", err
	}

	hashedSecret, err := secret.Hash(secretKey)
	if err != nil {
		return "", "", err
	}

	if err := a.storage.Save(ctx, appID, name, hashedSecret); err != nil {
		return "", "", err
	}

	return appID, secretKey, nil
}

func (a *AppService) RenewSecret(ctx context.Context, appID string) (string, error) {
	secretKey, err := secret.New(secretSize)
	if err != nil {
		return "", err
	}

	hashedSecret, err := secret.Hash(secretKey)
	if err != nil {
		return "", err
	}

	if err := a.storage.UpdateSecret(ctx, appID, hashedSecret); err != nil {
		return "", err
	}

	return secretKey, nil
}

func (a *AppService) DeleteApp(ctx context.Context, appID string) error {
	return a.storage.Delete(ctx, appID)
}
