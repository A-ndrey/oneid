package token

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	ID string `json:"id,omitempty"`
}

type JWTService struct {
	signingMethod   jwt.SigningMethod
	signingKey      crypto.Signer
	verificationKey crypto.PublicKey
	issuer          string
	parser          *jwt.Parser
}

func NewJWTService(issuer string, signingMethod jwt.SigningMethod, key crypto.Signer) *JWTService {
	return &JWTService{
		signingMethod:   signingMethod,
		issuer:          issuer,
		signingKey:      key,
		verificationKey: key.Public(),
		parser: jwt.NewParser(
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{signingMethod.Alg()}),
		),
	}
}

func (j *JWTService) Issue(id string, validFor time.Duration) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(validFor)),
		},
		ID: id,
	}

	jwtToken := jwt.NewWithClaims(j.signingMethod, claims)

	return jwtToken.SignedString(j.signingKey)
}

func (j *JWTService) VerifyAndGetID(jwtToken string) (string, error) {
	var claims Claims
	_, err := j.parser.ParseWithClaims(jwtToken, &claims, j.keyFunc)
	if err != nil {
		return "", err
	}

	return claims.ID, nil
}

func (j *JWTService) VerificationKey() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(j.verificationKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func (j *JWTService) keyFunc(_ *jwt.Token) (any, error) {
	return j.verificationKey, nil
}
