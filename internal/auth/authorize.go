package auth

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

var authorizeTemplate = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in &middot; Open Folio Connect</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
         display: grid; place-items: center; min-height: 100vh; margin: 0;
         background: Canvas; color: CanvasText; }
  main { width: min(26rem, 92vw); }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  p  { margin: 0 0 1.25rem; opacity: .7; font-size: .9rem; }
  label { display: block; font-size: .8rem; margin-bottom: .35rem; opacity: .8; }
  input { width: 100%; padding: .65rem .75rem; font-size: 1rem;
          border: 1px solid color-mix(in srgb, CanvasText 25%, transparent);
          border-radius: .5rem; background: Field; color: FieldText; box-sizing: border-box; }
  button { margin-top: 1rem; width: 100%; padding: .7rem; font-size: 1rem;
           border: 0; border-radius: .5rem; background: AccentColor; color: AccentColorText;
           cursor: pointer; }
  .error { margin: 0 0 1rem; padding: .6rem .75rem; font-size: .85rem;
           border-radius: .5rem; background: color-mix(in srgb, red 15%, transparent);
           border: 1px solid color-mix(in srgb, red 40%, transparent); }
  .muted { margin-top: 1rem; font-size: .8rem; opacity: .6; }
</style>
</head>
<body>
<main>
  <h1>Open Folio Connect</h1>
  <p>Sign in to sync your devices.</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="post" action="/auth/v1/authorize/callback">
    <input type="hidden" name="redirect_to" value="{{.RedirectTo}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" value="{{.Email}}" required autofocus autocomplete="username">
    <label for="code" style="margin-top:.75rem">6-digit code</label>
    <input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
    <button type="submit">Sign in</button>
  </form>
  {{if .Notice}}<p class="muted">{{.Notice}}</p>{{end}}
</main>
</body>
</html>`))

func (h *Handler) renderAuthorize(w http.ResponseWriter, view authorizeView, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := authorizeTemplate.Execute(w, view); err != nil {
		slog.Error("render authorize page", "error", err)
	}
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	redirectTo := firstNonEmpty(
		r.URL.Query().Get("redirect_to"),
		r.URL.Query().Get("redirect_uri"),
	)
	if !h.allowedRedirect(redirectTo) {
		h.renderAuthorize(w, authorizeView{
			RedirectTo: redirectTo,
			Error:      "This sign-in link is missing a valid return address.",
		}, http.StatusBadRequest)
		return
	}

	challenge := r.URL.Query().Get("code_challenge")

	notice := ""
	if h.cfg.DevOTP {
		notice = "Sign-in codes are returned by the API for this build."
	} else {
		notice = "Sign-in codes are written to the server log. Run `ofc code <email>` " +
			"on the server to print one."
	}
	h.renderAuthorize(w, authorizeView{
		RedirectTo:    redirectTo,
		CodeChallenge: challenge,
		Notice:        notice,
	}, http.StatusOK)
}

func (h *Handler) authorizeCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderAuthorize(
			w,
			authorizeView{Error: "Malformed form submission."},
			http.StatusBadRequest,
		)
		return
	}
	redirectTo := r.PostForm.Get("redirect_to")
	email := normalizeEmail(r.PostForm.Get("email"))
	code := strings.TrimSpace(r.PostForm.Get("code"))

	challenge := r.PostForm.Get("code_challenge")

	if !h.allowedRedirect(redirectTo) {
		h.renderAuthorize(
			w,
			authorizeView{Email: email, Error: "Invalid return address."},
			http.StatusBadRequest,
		)
		return
	}
	if email == "" || code == "" {
		h.renderAuthorize(w, authorizeView{
			Email: email, RedirectTo: redirectTo, CodeChallenge: challenge,
			Error: "Enter both your email and the 6-digit code.",
		}, http.StatusBadRequest)
		return
	}

	otp, err := h.store.PendingLoginOTP(r.Context(), email)
	if err != nil || store.HashToken(code) != otp.CodeHash {
		h.renderAuthorize(w, authorizeView{
			Email: email, RedirectTo: redirectTo, CodeChallenge: challenge,
			Error: "That code is not valid. Codes come from the email address you signed up with.",
		}, http.StatusUnauthorized)
		return
	}
	consumeErr := h.store.ConsumeLoginOTP(r.Context(), otp.ID)
	if consumeErr != nil {
		h.renderAuthorize(w, authorizeView{
			Email: email, RedirectTo: redirectTo, CodeChallenge: challenge,
			Error: "That code has already been used.",
		}, http.StatusUnauthorized)
		return
	}

	user, err := h.store.UserByEmail(r.Context(), email)
	if err != nil {
		h.internal(w, "load user for authorize callback", err)
		return
	}

	authCode, err := NewOpaqueToken(32)
	if err != nil {
		h.internal(w, "generate auth code", err)
		return
	}
	if err := h.store.CreateAuthCode(
		r.Context(),
		authCode,
		challenge,
		redirectTo,
		user.ID,
		h.cfg.AuthCodeTTL,
	); err != nil {
		h.internal(w, "store auth code", err)
		return
	}

	sep := "?"
	if strings.Contains(redirectTo, "?") {
		sep = "&"
	}
	target := redirectTo + sep + url.Values{"code": {authCode}}.Encode()

	w.Header().Set("Cache-Control", "no-store")
	//nolint:gosec
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *Handler) allowedRedirect(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "wealthfolio" && u.Host == "auth" && u.Path == "/callback" {
		return true
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	if origin == "http://tauri.localhost" || origin == "http://localhost" {
		return true
	}
	if !h.cfg.AllowedOrigins.All && len(h.cfg.AllowedOrigins.Origins) == 0 {
		return false
	}
	if h.cfg.AllowedOrigins.All {
		return u.Scheme == "http" || u.Scheme == "https"
	}
	for _, allowed := range h.cfg.AllowedOrigins.Origins {
		if origin == strings.ToLower(allowed) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
