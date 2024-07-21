package model

const (
	MFATOTP = "TOTP"
)

type User struct {
	ID             string
	Email          string
	EmailConfirmed bool
	MFA            string
	FirstName      string
	LastName       string
	Role           string
	AllowedApps    []string
}
