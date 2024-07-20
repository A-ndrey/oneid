package htmx

type Profile struct {
	Email       string
	MFA         string
	RedirectURL string
}

type TOTP struct {
	Secret string
	URL    string
}
