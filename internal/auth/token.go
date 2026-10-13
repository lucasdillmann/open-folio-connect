package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Issuer struct {
	teamOf    func(userID uuid.UUID) (uuid.UUID, error)
	issuerURL string
	secret    []byte
	accessTTL time.Duration
}

func NewIssuer(secret []byte, accessTTL time.Duration, issuerURL string,
	teamOf func(userID uuid.UUID) (uuid.UUID, error),
) *Issuer {
	return &Issuer{secret: secret, accessTTL: accessTTL, issuerURL: issuerURL, teamOf: teamOf}
}

func (i *Issuer) MintAccessToken(userID uuid.UUID, email string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(i.accessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    i.issuerURL + "/auth/v1",
			Audience:  jwt.ClaimStrings{RoleAuthenticated},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
		Email: email,
		Role:  RoleAuthenticated,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, exp, nil
}

func (i *Issuer) Verify(raw string) (UserIdentity, error) {
	claims := &Claims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithAudience(RoleAuthenticated), jwt.WithExpirationRequired()); err != nil {
		return UserIdentity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return UserIdentity{}, fmt.Errorf("%w: malformed subject", ErrInvalidToken)
	}

	teamID, err := i.teamOf(userID)
	if err != nil {
		return UserIdentity{}, fmt.Errorf("%w: user is not a member of any team", ErrInvalidToken)
	}

	return UserIdentity{
		UserID: userID,
		Email:  claims.Email,
		TeamID: teamID,
		Role:   claims.Role,
	}, nil
}

func NewRefreshToken() (string, error) {
	return randomToken(32)
}

func NewOpaqueToken(n int) (string, error) {
	return randomToken(n)
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func NewNumericCode(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var out []byte
	for _, b := range buf {
		out = append(out, '0'+b%10)
	}
	return string(out), nil
}

func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
