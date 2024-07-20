package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/rs/xid"

	"github.com/A-ndrey/oneid/internal/auth/mfa/totp"
	"github.com/A-ndrey/oneid/internal/auth/secret"
	"github.com/A-ndrey/oneid/internal/auth/token"
	"github.com/A-ndrey/oneid/internal/model"
	"github.com/A-ndrey/oneid/internal/storage"
)

const mfaSecretSize = 20

const (
	sessionTokenDuration = 24 * time.Hour
	mfaTokenDuration     = 10 * time.Minute
	userTokenDuration    = 24 * time.Hour
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
}

type UserService struct {
	logger     *slog.Logger
	storage    UserStorage
	jwt        *token.JWTService
	session    *token.SessionService
	totpConfig totp.Config
}

func NewUserService(logger *slog.Logger, storage UserStorage, jwt *token.JWTService, session *token.SessionService, totpConfig totp.Config) *UserService {
	return &UserService{
		logger:     logger,
		storage:    storage,
		jwt:        jwt,
		session:    session,
		totpConfig: totpConfig,
	}
}

func (s *UserService) Login(ctx context.Context, email, password string, userAgent string) (model.User, string, error) {
	s.logger.Debug("login", slog.String("email", email), slog.String("userAgent", userAgent))

	ok, err := s.CheckPassword(ctx, email, password)
	if err != nil {
		return model.User{}, "", err
	}
	if !ok {
		return model.User{}, "", errors.New("password mismatch")
	}

	u, err := s.storage.FindByEmail(ctx, email)
	if err != nil {
		return model.User{}, "", err
	}
	s.logger.Debug("login", slog.Any("user", u))

	if u.MFA != "" {
		mfaToken, err := s.jwt.Issue(u.ID, mfaTokenDuration)
		if err != nil {
			return model.User{}, "", err
		}

		return u, mfaToken, nil
	}

	sessionToken, err := s.session.Issue(ctx, u.ID, userAgent, sessionTokenDuration)
	if err != nil {
		return model.User{}, "", err
	}

	return u, sessionToken, nil
}

func (s *UserService) LoginWithMFA(ctx context.Context, mfaToken string, code string, userAgent string) (model.User, string, error) {
	s.logger.Debug("login with mfa", slog.String("mfaToken", mfaToken), slog.String("code", code), slog.String("userAgent", userAgent))

	userID, err := s.jwt.VerifyAndGetID(mfaToken)
	if err != nil {
		return model.User{}, "", err
	}
	s.logger.Debug("login with mfa", slog.String("userID", userID))

	u, err := s.storage.FindByID(ctx, userID)
	if err != nil {
		return model.User{}, "", err
	}
	s.logger.Debug("login with mfa", slog.Any("user", u))

	if u.MFA == model.MFATOTP {
		if err := s.CheckTOTPCode(ctx, userID, code); err != nil {
			return model.User{}, "", err
		}

		sessionToken, err := s.session.Issue(ctx, u.ID, userAgent, sessionTokenDuration)
		if err != nil {
			return model.User{}, "", err
		}

		return u, sessionToken, nil
	}

	return model.User{}, "", fmt.Errorf("unknown mfa type: %s", u.MFA)
}

func (s *UserService) Logout(ctx context.Context, userID, userAgent, rToken string) error {
	if err := s.session.Verify(ctx, userID, userAgent, rToken); err != nil {
		return err
	}

	if err := s.session.Delete(ctx, userID, userAgent); err != nil {
		return err
	}

	return nil
}

func (s *UserService) SignUp(ctx context.Context, email, password string, userAgent string) (model.User, string, error) {
	ok, err := s.EmailExists(ctx, email)
	if err != nil {
		return model.User{}, "", err
	}
	if ok {
		return model.User{}, "", errors.New("email already exists")
	}

	u, err := s.createTempProfile(ctx, email, password)
	if err != nil {
		return model.User{}, "", err
	}

	rToken, err := s.session.Issue(ctx, u.ID, userAgent, sessionTokenDuration)
	if err != nil {
		return model.User{}, "", err
	}

	return u, rToken, nil
}

func (s *UserService) User(ctx context.Context, userID string, rToken string, userAgent string) (model.User, error) {
	if err := s.session.Verify(ctx, userID, userAgent, rToken); err != nil {
		return model.User{}, err
	}

	u, err := s.storage.FindByID(ctx, userID)
	if err != nil {
		return model.User{}, err
	}

	return u, nil
}

func (s *UserService) EmailByID(ctx context.Context, userID string) (string, error) {
	user, err := s.storage.FindByID(ctx, userID)
	if err != nil {
		return "", err
	}

	return user.Email, nil
}

func (s *UserService) Sessions(ctx context.Context, userID string, rToken string, userAgent string) ([]string, error) {
	if err := s.session.Verify(ctx, userID, userAgent, rToken); err != nil {
		return nil, err
	}

	return s.session.UserSessions(ctx, userID)
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

func (s *UserService) GenerateJWT(ctx context.Context, user model.User) (string, error) {
	jwt, err := s.jwt.Issue(user.ID, userTokenDuration)
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
