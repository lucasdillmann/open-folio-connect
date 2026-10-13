package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

type authorizeView struct {
	Email         string
	RedirectTo    string
	CodeChallenge string
	Error         string
	Notice        string
}

type otpRequest struct {
	Email               string         `json:"email"`
	Data                map[string]any `json:"data"`
	CodeChallenge       string         `json:"code_challenge"`
	CodeChallengeMethod string         `json:"code_challenge_method"`
}

type verifyRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
	Type  string `json:"type"`
}

type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Role  string `json:"role"`
}

type UserIdentity struct {
	Email  string
	Role   string
	UserID uuid.UUID
	TeamID uuid.UUID
}

type UserObject struct {
	AppMetadata     map[string]any `json:"app_metadata"`
	UserMetadata    map[string]any `json:"user_metadata"`
	Email           string         `json:"email"`
	ID              string         `json:"id"`
	EmailVerifiedAt string         `json:"email_confirmed_at"`
	Phone           string         `json:"phone"`
	ConfirmedAt     string         `json:"confirmed_at"`
	LastSignInAt    string         `json:"last_sign_in_at"`
	Role            string         `json:"role"`
	Aud             string         `json:"aud"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
	Identities      []any          `json:"identities"`
	IsAnonymous     bool           `json:"is_anonymous"`
}

func NewUserObject(u store.User, teamID uuid.UUID) UserObject {
	created := u.CreatedAt.UTC().Format(time.RFC3339)
	return UserObject{
		ID:              u.ID.String(),
		Aud:             RoleAuthenticated,
		Role:            RoleAuthenticated,
		Email:           u.Email,
		EmailVerifiedAt: created,
		Phone:           "",
		ConfirmedAt:     created,
		LastSignInAt:    created,
		AppMetadata: map[string]any{
			"provider":  "email",
			"providers": []string{"email"},
			"team_id":   teamID.String(),
		},
		UserMetadata: map[string]any{},
		Identities:   []any{},
		CreatedAt:    created,
		UpdatedAt:    created,
	}
}

type Session struct {
	AccessToken  string     `json:"access_token"`
	TokenType    string     `json:"token_type"`
	RefreshToken string     `json:"refresh_token"`
	User         UserObject `json:"user"`
	ExpiresIn    int64      `json:"expires_in"`
	ExpiresAt    int64      `json:"expires_at"`
}

type GoTrueError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
