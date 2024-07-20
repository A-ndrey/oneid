package web

import (
	_ "embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/A-ndrey/oneid/internal/auth"
	"github.com/A-ndrey/oneid/internal/auth/mfa/totp"
	"github.com/A-ndrey/oneid/internal/middleware"
	"github.com/A-ndrey/oneid/internal/model"
	"github.com/A-ndrey/oneid/internal/server/web/htmx"
)

var (
	//go:embed htmx/template.html
	templateHTMX []byte
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrBadRequest   = errors.New("bad request")
)

type Handler struct {
	appName    string
	auth       *auth.UserService
	inner      http.Handler
	totpConfig totp.Config
	template   *template.Template
}

func NewHandler(appName string, auth *auth.UserService, totpConfig totp.Config, logger *slog.Logger) (*Handler, error) {
	h := Handler{
		appName:    appName,
		auth:       auth,
		totpConfig: totpConfig,
	}

	handleWithErr := func(mx *http.ServeMux, pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mx.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			err := handler(w, r)
			if errors.Is(err, ErrUnauthorized) {
				logger.Debug(err.Error())
				err = h.getLogin(w, r)
				return
			}
			if errors.Is(err, ErrBadRequest) {
				logger.Debug(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err != nil {
				logger.Debug(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		})
	}

	mx := http.NewServeMux()
	handleWithErr(mx, "GET /", h.getIndex)
	handleWithErr(mx, "GET /login", h.getLogin)
	handleWithErr(mx, "POST /login", h.postLogin)
	handleWithErr(mx, "GET /signup", h.getSignUp)
	handleWithErr(mx, "POST /signup", h.postSignUp)
	handleWithErr(mx, "GET /profile", h.getProfile)
	handleWithErr(mx, "POST /logout", h.postLogout)
	handleWithErr(mx, "POST /enable-mfa", h.enableMFA)
	handleWithErr(mx, "POST /disable-mfa", h.disableMFA)
	handleWithErr(mx, "POST /confirm-mfa", h.confirmMFA)
	handleWithErr(mx, "POST /login-mfa", h.postLoginMFA)
	handleWithErr(mx, "GET /redirect", h.redirect)

	h.inner = middleware.Attach(mx, middleware.Logging(logger), middleware.HTMXFilter())

	mainTemplate, err := template.New("template").Parse(string(templateHTMX))
	if err != nil {
		return nil, err
	}
	h.template = mainTemplate

	return &h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.inner.ServeHTTP(w, r)
}

func (h *Handler) getIndex(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return nil
	}

	err := h.template.ExecuteTemplate(w, "index", h.appName)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) error {
	var email string
	userToken, err := parseCookies(r)
	if err == nil {
		userID, _ := parseUserToken(userToken)
		email, _ = h.auth.EmailByID(r.Context(), userID)
	}

	if err := h.template.ExecuteTemplate(w, "login", email); err != nil {
		return err
	}

	return nil
}

func (h *Handler) getSignUp(w http.ResponseWriter, _ *http.Request) error {
	if err := h.template.ExecuteTemplate(w, "signup", nil); err != nil {
		return err
	}

	return nil
}

func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) error {
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	userAgent := r.Header.Get("User-Agent")

	u, sessionToken, err := h.auth.Login(r.Context(), email, password, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	if u.MFA != "" {
		if err := h.template.ExecuteTemplate(w, "login-mfa", sessionToken); err != nil {
			return err
		}
		return nil
	}

	writeCookies(w, joinUserToken(u.ID, sessionToken))

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) postSignUp(w http.ResponseWriter, r *http.Request) error {
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	userAgent := r.Header.Get("User-Agent")

	u, sessionToken, err := h.auth.SignUp(r.Context(), email, password, userAgent)
	if err != nil {
		return err
	}

	writeCookies(w, joinUserToken(u.ID, sessionToken))

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	if err := h.auth.Logout(r.Context(), userID, userAgent, sessionToken); err != nil {
		return err
	}

	w.Header().Add("HX-Refresh", "true")

	return nil
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	u, err := h.auth.User(r.Context(), userID, sessionToken, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) enableMFA(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	u, err := h.auth.User(r.Context(), userID, sessionToken, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	totpKey, err := h.auth.CreateTOTPKey(r.Context(), u.ID)
	if err != nil {
		return err
	}

	totpURL, err := totp.GenerateURL(totpKey, h.appName, u.Email, h.totpConfig)
	if err != nil {
		return err
	}

	mfa := htmx.TOTP{
		Secret: string(totpKey.Encode()),
		URL:    totpURL,
	}
	if err := h.template.ExecuteTemplate(w, "mfa", mfa); err != nil {
		return err
	}

	return nil
}

func (h *Handler) disableMFA(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	u, err := h.auth.User(r.Context(), userID, sessionToken, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	if err := h.auth.DisableMFA(r.Context(), u.ID); err != nil {
		return err
	}

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) confirmMFA(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	u, err := h.auth.User(r.Context(), userID, sessionToken, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	totpCode := r.PostFormValue("code")
	if err := h.auth.CheckTOTPCode(r.Context(), u.ID, totpCode); err != nil {
		return errors.Join(ErrBadRequest, err)
	}

	if err := h.auth.SetMFAMethodTOTP(r.Context(), u.ID); err != nil {
		return err
	}

	u.MFA = "TOTP"

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) postLoginMFA(w http.ResponseWriter, r *http.Request) error {
	userAgent := r.Header.Get("User-Agent")

	mfaToken := r.PostFormValue("mfa-token")
	totpCode := r.PostFormValue("code")
	u, sessionToken, err := h.auth.LoginWithMFA(r.Context(), mfaToken, totpCode, userAgent)
	if err != nil {
		return errors.Join(ErrBadRequest, err)
	}

	writeCookies(w, joinUserToken(u.ID, sessionToken))

	if err := h.renderProfile(w, r, u); err != nil {
		return err
	}

	return nil
}

func (h *Handler) renderProfile(w http.ResponseWriter, r *http.Request, user model.User) error {
	profile := htmx.Profile{
		Email: user.Email,
		MFA:   user.MFA,
	}

	p := parseHXCurrentURLParams(r)
	if !p.isEmpty() {
		profile.RedirectURL = p.RedirectURL
	}

	if err := h.template.ExecuteTemplate(w, "profile", profile); err != nil {
		return err
	}

	return nil
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request) error {
	userToken, err := parseCookies(r)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	userID, sessionToken := parseUserToken(userToken)
	userAgent := r.Header.Get("User-Agent")

	u, err := h.auth.User(r.Context(), userID, sessionToken, userAgent)
	if err != nil {
		return errors.Join(ErrUnauthorized, err)
	}

	p := parseHXCurrentURLParams(r)
	if !p.isEmpty() {
		jwt, err := h.auth.GenerateJWT(r.Context(), u)
		if err != nil {
			return err
		}
		if redirectURL, err := p.makeRedirectURL(jwt); err == nil {
			w.Header().Add("HX-Redirect", redirectURL)
		}
	}

	return nil
}

func writeCookies(w http.ResponseWriter, accessToken string) {
	accessCookie := http.Cookie{
		Name:     "access",
		Value:    accessToken,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}

	http.SetCookie(w, &accessCookie)
}

func parseCookies(r *http.Request) (string, error) {
	c, err := r.Cookie("access")
	if err != nil {
		return "", err
	}

	if err := c.Valid(); err != nil {
		return "", err
	}

	accessToken := c.Value

	return accessToken, nil
}

func parseUserToken(userToken string) (string, string) {
	t := strings.SplitN(userToken, "@", 2)

	return t[0], t[1]
}

func joinUserToken(userID string, sessionToken string) string {
	return userID + "@" + sessionToken
}

type params struct {
	RedirectURL string
	TokenParam  string
}

func parseHXCurrentURLParams(r *http.Request) params {
	parsedURL, err := url.Parse(r.Header.Get("HX-Current-URL"))
	if err != nil {
		return params{}
	}
	q := parsedURL.Query()
	var p params
	p.RedirectURL = q.Get("redirect_url")
	p.TokenParam = q.Get("token_param")

	return p
}

func (p params) isEmpty() bool {
	return p == (params{})
}

func (p params) makeRedirectURL(token string) (string, error) {
	parsedURL, err := url.Parse(p.RedirectURL)
	if err != nil {
		return "", err
	}

	q := parsedURL.Query()
	q.Add(p.TokenParam, token)
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String(), nil
}
