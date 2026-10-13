package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/lucasdillmann/open-folio-connect/internal/config"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

type Handler struct {
	store  *store.Store
	issuer *Issuer
	cfg    config.Config
}

func NewHandler(s *store.Store, issuer *Issuer, cfg config.Config) *Handler {
	return &Handler{store: s, issuer: issuer, cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/v1/otp", h.sendOTP)
	mux.HandleFunc("POST /auth/v1/verify", h.verifyOTP)
	mux.HandleFunc("POST /auth/v1/token", h.token)
	mux.HandleFunc("POST /auth/v1/signup", h.signUp)
	mux.HandleFunc("GET /auth/v1/user", h.currentUser)
	mux.HandleFunc("POST /auth/v1/logout", h.logout)
	mux.HandleFunc("GET /auth/v1/authorize", h.authorize)
	mux.HandleFunc("POST /auth/v1/authorize/callback", h.authorizeCallback)
	mux.HandleFunc("GET /auth/v1/settings", h.settings)
}

func writeGoTrueError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(GoTrueError{ErrorCode: code, ErrorDescription: desc})
}

func (h *Handler) sendOTP(w http.ResponseWriter, r *http.Request) {
	var req otpRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if email == "" {
		writeGoTrueError(w, http.StatusBadRequest, "validation_failed", "a valid email is required")
		return
	}

	user, err := h.store.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}
	if err != nil {
		h.internal(w, "load user for otp", err)
		return
	}

	code, err := NewNumericCode(6)
	if err != nil {
		h.internal(w, "generate otp", err)
		return
	}
	if err := h.store.CreateLoginOTP(
		r.Context(),
		user.Email,
		code,
		req.CodeChallenge,
		h.cfg.OTPCodeTTL,
	); err != nil {
		h.internal(w, "store otp", err)
		return
	}

	requestID := httpx.RequestID(r)
	logLoginCode(user.Email, code, requestID)

	body := map[string]any{}
	if h.cfg.DevOTP {
		body["dev_code"] = code
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func (h *Handler) verifyOTP(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	token := strings.TrimSpace(req.Token)
	requestID := httpx.RequestID(r)

	otp, err := h.store.PendingLoginOTP(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		logOTPResult(email, token, "no_pending_otp", requestID)
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"otp_expired",
			"the code is invalid or has expired",
		)
		return
	}
	if err != nil {
		h.internal(w, "load otp for verification", err)
		logOTPResult(email, token, "load_otp_error", requestID)
		return
	}

	if store.HashToken(token) != otp.CodeHash {
		logOTPResult(email, token, "code_mismatch", requestID)
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"otp_expired",
			"the code is invalid or has expired",
		)
		return
	}

	user, err := h.store.UserByEmail(r.Context(), otp.Email)
	if err != nil {
		h.internal(w, "load user for otp verification", err)
		logOTPResult(email, token, "load_user_error", requestID)
		return
	}
	consumeErr := h.store.ConsumeLoginOTP(r.Context(), otp.ID)
	if consumeErr != nil {
		logOTPResult(email, token, "consume_error", requestID)
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"otp_expired",
			"the code is invalid or has expired",
		)
		return
	}

	session, err := h.issueSession(r.Context(), user)
	if err != nil {
		h.internal(w, "issue session", err)
		logOTPResult(email, token, "issue_session_error", requestID)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, session)
	logOTPResult(email, token, "success", requestID)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("grant_type") {
	case "refresh_token":
		h.grantRefresh(w, r)
	case "pkce":
		h.grantPKCE(w, r)
	case "password":
		h.grantPassword(w, r)
	default:
		writeGoTrueError(w, http.StatusBadRequest, "unsupported_grant_type",
			"supported grants: refresh_token, pkce, password")
	}
}

func (h *Handler) grantRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.RefreshToken)
	if token == "" {
		writeGoTrueError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is required")
		return
	}

	rt, err := h.store.ConsumeRefreshToken(r.Context(), token)
	if errors.Is(err, store.ErrNotFound) {
		writeGoTrueError(w, http.StatusBadRequest, "invalid_grant", "refresh token not found")
		return
	}
	if err != nil {
		h.internal(w, "consume refresh token", err)
		return
	}

	user, err := h.store.UserByID(r.Context(), rt.UserID)
	if err != nil {
		h.internal(w, "load user for refresh", err)
		return
	}
	session, err := h.issueSession(r.Context(), user)
	if err != nil {
		h.internal(w, "issue session", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, session)
}

func (h *Handler) grantPKCE(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthCode     string `json:"auth_code"`
		CodeVerifier string `json:"code_verifier"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	code := strings.TrimSpace(req.AuthCode)
	if code == "" {
		writeGoTrueError(w, http.StatusBadRequest, "invalid_grant", "auth_code is required")
		return
	}

	expected, err := h.store.AuthCodeChallenge(r.Context(), code)
	if errors.Is(err, store.ErrNotFound) {
		writeGoTrueError(w, http.StatusBadRequest, "invalid_grant", "authorization code not found")
		return
	}
	if err != nil {
		h.internal(w, "load auth code", err)
		return
	}

	if expected == "" || S256Challenge(req.CodeVerifier) != expected {
		writeGoTrueError(w, http.StatusBadRequest, "invalid_grant", "pkce verification failed")
		return
	}

	ac, err := h.store.ConsumeAuthCode(r.Context(), code)
	if errors.Is(err, store.ErrNotFound) {
		writeGoTrueError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"authorization code is invalid or expired",
		)
		return
	}
	if err != nil {
		h.internal(w, "consume auth code", err)
		return
	}

	user, err := h.store.UserByID(r.Context(), ac.UserID)
	if err != nil {
		h.internal(w, "load user for pkce", err)
		return
	}
	session, err := h.issueSession(r.Context(), user)
	if err != nil {
		h.internal(w, "issue session", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, session)
}

func (h *Handler) grantPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	user, err := h.store.UserByEmail(r.Context(), normalizeEmail(req.Email))
	if errors.Is(err, store.ErrNotFound) {
		writeGoTrueError(
			w,
			http.StatusBadRequest,
			"invalid_credentials",
			"invalid login credentials",
		)
		return
	}
	if err != nil {
		h.internal(w, "load user for password grant", err)
		return
	}
	if !h.checkPassword(user, req.Password) {
		writeGoTrueError(
			w,
			http.StatusBadRequest,
			"invalid_credentials",
			"invalid login credentials",
		)
		return
	}
	session, err := h.issueSession(r.Context(), user)
	if err != nil {
		h.internal(w, "issue session", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, session)
}

func (h *Handler) signUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if email == "" {
		writeGoTrueError(w, http.StatusBadRequest, "validation_failed", "a valid email is required")
		return
	}

	existing, err := h.store.UserByEmail(r.Context(), email)
	if err == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"id":                 existing.ID.String(),
			"email":              existing.Email,
			"email_confirmed_at": existing.CreatedAt,
		})
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		h.internal(w, "look up user for signup", err)
		return
	}

	var hash []byte
	if req.Password != "" {
		if hash, err = bcrypt.GenerateFromPassword(
			[]byte(req.Password),
			bcrypt.DefaultCost,
		); err != nil {
			h.internal(w, "hash password", err)
			return
		}
	}
	user, err := h.store.CreateUser(r.Context(), uuid.New(), email, string(hash))
	if err != nil {
		h.internal(w, "create user", err)
		return
	}

	team, err := h.ensureTeam(r.Context(), user.ID)
	if err != nil {
		h.internal(w, "ensure team membership", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":                 user.ID.String(),
		"email":              user.Email,
		"email_confirmed_at": user.CreatedAt,
		"team_id":            team.ID.String(),
	})
}

func (h *Handler) currentUser(w http.ResponseWriter, r *http.Request) {
	identity, err := h.authenticate(w, r)
	if err != nil {
		return
	}
	user, err := h.store.UserByID(r.Context(), identity.UserID)
	if err != nil {
		h.internal(w, "load current user", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NewUserObject(user, identity.TeamID))
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	raw, err := httpx.BearerToken(r)
	if err != nil {
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"invalid_token",
			"a valid access token is required",
		)
		return
	}
	if _, err := h.issuer.Verify(raw); err != nil {
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"invalid_token",
			"a valid access token is required",
		)
		return
	}
	_ = h.store.RevokeAllRefreshTokens(r.Context(), h.subjectOf(raw))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) settings(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"external":           map[string]any{"email": true, "phone": false, "google": false},
		"disable_signup":     false,
		"mailer_autoconfirm": true,
	})
}

func (h *Handler) issueSession(ctx context.Context, user store.User) (Session, error) {
	access, exp, err := h.issuer.MintAccessToken(user.ID, user.Email)
	if err != nil {
		return Session{}, err
	}
	refresh, err := NewRefreshToken()
	if err != nil {
		return Session{}, err
	}
	_, issueErr := h.store.IssueRefreshToken(
		ctx,
		user.ID,
		refresh,
		h.cfg.RefreshTokenTTL,
	)
	if issueErr != nil {
		return Session{}, issueErr
	}
	membership, err := h.store.MembershipForUser(ctx, user.ID)
	if err != nil {
		return Session{}, err
	}

	return Session{
		AccessToken:  access,
		TokenType:    "bearer",
		ExpiresIn:    int64(h.cfg.AccessTokenTTL.Seconds()),
		ExpiresAt:    exp.Unix(),
		RefreshToken: refresh,
		User:         NewUserObject(user, membership.TeamID),
	}, nil
}

func (h *Handler) checkPassword(user store.User, password string) bool {
	if !user.HasPassword() || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)) == nil
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (UserIdentity, error) {
	raw, err := httpx.BearerToken(r)
	if err != nil {
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"invalid_token",
			"a valid access token is required",
		)
		return UserIdentity{}, err
	}
	identity, err := h.issuer.Verify(raw)
	if err != nil {
		writeGoTrueError(
			w,
			http.StatusUnauthorized,
			"invalid_token",
			"a valid access token is required",
		)
		return UserIdentity{}, err
	}
	return identity, nil
}

func (h *Handler) subjectOf(raw string) uuid.UUID {
	identity, err := h.issuer.Verify(raw)
	if err != nil {
		return uuid.Nil
	}
	return identity.UserID
}

func (h *Handler) ensureTeam(ctx context.Context, userID uuid.UUID) (store.Team, error) {
	team, err := h.store.Team(ctx)
	if err != nil {
		return store.Team{}, err
	}
	if err := h.store.AddMember(ctx, team.ID, userID, "owner"); err != nil {
		return store.Team{}, err
	}
	return team, nil
}

func (h *Handler) internal(w http.ResponseWriter, what string, err error) {
	slog.Error("auth handler failed", "op", what, "error", err)
	writeGoTrueError(w, http.StatusInternalServerError, "unexpected_failure", what+" failed")
}

func normalizeEmail(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
