package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"hash"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	HmacSHA1 Algorithm = iota
	HmacSHA256
	HmacSHA512
)

const periodSeconds = 30

var (
	ErrInvalidCode   = errors.New("invalid code")
	ErrInvalidConfig = errors.New("invalid config")
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

var digitsPower = [...]int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

var DefaultConfig = Config{
	algo:         HmacSHA1,
	currTimeFunc: time.Now,
	digits:       6,
	steps:        2,
}

type Algorithm uint8

func (a Algorithm) hashFunc() (func() hash.Hash, error) {
	switch a {
	case HmacSHA1:
		return sha1.New, nil
	case HmacSHA256:
		return sha256.New, nil
	case HmacSHA512:
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func (a Algorithm) String() (string, error) {
	switch a {
	case HmacSHA1:
		return "SHA1", nil
	case HmacSHA256:
		return "SHA256", nil
	case HmacSHA512:
		return "SHA512", nil
	default:
		return "", errors.New("unsupported algorithm")
	}
}

type Config struct {
	algo         Algorithm
	currTimeFunc func() time.Time
	digits       int
	steps        int
}

func NewConfig(algo Algorithm, currTimeFunc func() time.Time, digits int, validationSteps int) (Config, error) {
	_, err := algo.String()
	if err != nil {
		return Config{}, err
	}

	if digits >= len(digitsPower) || digits < 0 {
		return Config{}, errors.New("unsupported digits number")
	}

	if currTimeFunc == nil {
		currTimeFunc = time.Now
	}

	if validationSteps == 0 {
		validationSteps = 1
	}

	return Config{
		algo:         algo,
		currTimeFunc: currTimeFunc,
		digits:       digits,
		steps:        validationSteps,
	}, nil
}

func (c Config) isValid() bool {
	return c.currTimeFunc != nil && c.digits < len(digitsPower) && c.digits >= 0 && c.steps > 0
}

type Key []byte

func (k Key) Check() error {
	if len(k) < 10 {
		return errors.New("invalid key length")
	}

	return nil
}

func (k Key) Encode() []byte {
	encKey := make([]byte, encoding.EncodedLen(len(k)))
	encoding.Encode(encKey, k)

	return encKey
}

func Generate(key Key, t time.Time, conf Config) (string, error) {
	if !conf.isValid() {
		return "", ErrInvalidConfig
	}

	h, err := conf.algo.hashFunc()
	if err != nil {
		return "", err
	}

	if err := key.Check(); err != nil {
		return "", err
	}

	thm := t.UTC().Unix() / periodSeconds
	buf := make([]byte, 8)
	big.NewInt(thm).FillBytes(buf)

	mac := hmac.New(h, key)
	mac.Write(buf)
	res := mac.Sum(nil)

	offset := res[len(res)-1] & 0xf
	bin := ((int(res[offset]) & 0x7f) << 24) | ((int(res[offset+1]) & 0xff) << 16) | ((int(res[offset+2]) & 0xff) << 8) | (int(res[offset+3]) & 0xff)
	otp := bin % digitsPower[conf.digits]

	code := strconv.Itoa(otp)
	return strings.Repeat("0", conf.digits-len(code)) + code, nil
}

func Verify(key Key, code string, conf Config) error {
	if !conf.isValid() {
		return ErrInvalidConfig
	}

	currTime := conf.currTimeFunc()
	for i := range conf.steps {
		t := currTime.Add(time.Duration(-i*periodSeconds) * time.Second)
		gCode, err := Generate(key, t, conf)
		if err != nil {
			return err
		}
		if gCode == code {
			return nil
		}
	}

	return ErrInvalidCode
}

func GenerateURL(key Key, issuer string, userName string, conf Config) (string, error) {
	if err := key.Check(); err != nil {
		return "", err
	}

	if !conf.isValid() {
		return "", ErrInvalidConfig
	}

	h, err := conf.algo.String()
	if err != nil {
		return "", err
	}

	label := issuer + ":" + userName

	params := make(url.Values)
	params.Set("secret", string(key.Encode()))
	params.Set("issuer", issuer)
	params.Set("algorithm", h)
	params.Set("digits", strconv.Itoa(conf.digits))
	params.Set("period", strconv.Itoa(periodSeconds))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     url.PathEscape(label),
		RawQuery: params.Encode(),
	}

	return u.String(), nil
}
