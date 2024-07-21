package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rs/xid"

	"github.com/A-ndrey/oneid/internal/auth/mfa/totp"
	"github.com/A-ndrey/oneid/internal/auth/secret"
	"github.com/A-ndrey/oneid/internal/auth/token"
	"github.com/A-ndrey/oneid/internal/model"
	"github.com/A-ndrey/oneid/internal/storage"
)

var (
	ErrUserExists        = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrIncorrectPassword = errors.New("incorrect password")
)

const mfaSecretSize = 20

const (
	userTokenDuration = 24 * time.Hour
)

type UserStorage interface {
	FindByEmail(ctx context.Context, email string) (model.User, error)
	FindByID(ctx context.Context, userID string) (model.User, error)
	GetHashedPassword(ctx context.Context, email string) (string, error)
	Create(ctx context.Context, user model.User, hashedPassword string) error
	SaveRestoreKey(ctx context.Context, email string, restoreKey string, ttl time.Time) error
	GetRestoreKey(ctx context.Context, email string) (string, time.Time, error)
	GetMFASharedSecret(ctx context.Context, userID string) (string, error)
	SaveMFA(ctx context.Context, userID string, mfa string) error
	SaveMFASharedSecret(ctx context.Context, userID string, mfaSecret string) error
	ResetMFA(ctx context.Context, userID string) error
	GetAllowedApps(ctx context.Context, userID string) ([]string, error)
}

type UserService struct {
	logger     *slog.Logger
	storage    UserStorage
	jwt        *token.JWTService
	totpConfig totp.Config
}

func NewUserService(logger *slog.Logger, storage UserStorage, jwt *token.JWTService, totpConfig totp.Config) *UserService {
	return &UserService{
		logger:     logger,
		storage:    storage,
		jwt:        jwt,
		totpConfig: totpConfig,
	}
}

func (s *UserService) Login(ctx context.Context, email, password string) (model.User, error) {
	s.logger.Debug("login", slog.String("email", email))

	ok, err := s.CheckPassword(ctx, email, password)
	if err != nil {
		return model.User{}, err
	}
	if !ok {
		return model.User{}, ErrIncorrectPassword
	}

	u, err := s.storage.FindByEmail(ctx, email)
	if errors.Is(err, storage.ErrNotFound) {
		return model.User{}, ErrUserNotFound
	}
	if err != nil {
		return model.User{}, err
	}

	s.logger.Debug("login", slog.Any("user", u))

	return u, nil
}

func (s *UserService) SignUp(ctx context.Context, email, password string) (model.User, error) {
	ok, err := s.EmailExists(ctx, email)
	if err != nil {
		return model.User{}, err
	}
	if ok {
		return model.User{}, ErrUserExists
	}

	u, err := s.createTempProfile(ctx, email, password)
	if err != nil {
		return model.User{}, err
	}

	return u, nil
}

func (s *UserService) CreateTOTPKey(ctx context.Context, userID string) (totp.Key, error) {
	mfaSecret, err := secret.New(mfaSecretSize)
	if err != nil {
		return nil, err
	}

	totpKey := totp.Key(mfaSecret)
	if err := totpKey.Check(); err != nil {
		return nil, err
	}

	if err := s.storage.SaveMFASharedSecret(ctx, userID, mfaSecret); err != nil {
		return nil, err
	}

	return totpKey, nil
}

func (s *UserService) CheckTOTPCode(ctx context.Context, userID string, code string) error {
	mfaSecret, err := s.storage.GetMFASharedSecret(ctx, userID)
	if err != nil {
		return err
	}

	if err := totp.Verify(totp.Key(mfaSecret), code, s.totpConfig); err != nil {
		return err
	}

	return nil
}

func (s *UserService) SetMFAMethodTOTP(ctx context.Context, userID string) error {
	return s.storage.SaveMFA(ctx, userID, "TOTP")
}

func (s *UserService) DisableMFA(ctx context.Context, userID string) error {
	return s.storage.ResetMFA(ctx, userID)
}

func (s *UserService) GenerateAccessToken(_ context.Context, user model.User, tokenDuration time.Duration) (string, error) {
	if tokenDuration == 0 {
		tokenDuration = userTokenDuration
	}

	jwt, err := s.jwt.Issue(user.ID, tokenDuration)
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func (s *UserService) Validate(ctx context.Context) error {
	panic("not implemented")
}

func (s *UserService) EmailExists(ctx context.Context, email string) (bool, error) {
	_, err := s.storage.FindByEmail(ctx, email)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s *UserService) CheckPassword(ctx context.Context, email, password string) (bool, error) {
	hashedPassword, err := s.storage.GetHashedPassword(ctx, email)
	if err != nil {
		return false, err
	}

	return secret.Compare(password, hashedPassword)
}

func (s *UserService) HasBoundExternalServices(ctx context.Context) bool {
	panic("not implemented")
}

func (s *UserService) SendEmailConfirmation(ctx context.Context) error {
	panic("not implemented")
}

func (s *UserService) createTempProfile(ctx context.Context, email, password string) (model.User, error) {
	u := model.User{
		ID:    xid.New().String(),
		Email: email,
	}

	hashedPassword, err := secret.Hash(password)
	if err != nil {
		return model.User{}, err
	}

	err = s.storage.Create(ctx, u, hashedPassword)
	if err != nil {
		return model.User{}, err
	}

	return u, nil
}
