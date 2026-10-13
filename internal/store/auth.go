package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) IssueRefreshToken(
	ctx context.Context,
	userID uuid.UUID,
	token string,
	ttl time.Duration,
) (RefreshToken, error) {
	id := uuid.New()
	const q = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)
		RETURNING id, user_id, rotated_to, expires_at, revoked_at`
	var rt RefreshToken
	err := s.pool.QueryRow(ctx, q, id, userID, HashToken(token), ttl.String()).Scan(
		&rt.ID, &rt.UserID, &rt.RotatedTo, &rt.ExpiresAt, &rt.RevokedAt)
	return rt, err
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	const q = `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		RETURNING id, user_id, rotated_to, expires_at, revoked_at`
	var rt RefreshToken
	err := s.pool.QueryRow(ctx, q, HashToken(token)).Scan(
		&rt.ID, &rt.UserID, &rt.RotatedTo, &rt.ExpiresAt, &rt.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	return rt, err
}

func (s *Store) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID)
	return err
}

func (s *Store) CreateAuthCode(
	ctx context.Context,
	code, codeChallenge, redirectTo string,
	userID uuid.UUID,
	ttl time.Duration,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth_codes (id, code, code_challenge, redirect_to, user_id, expires_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, now() + $6::interval)`,
		uuid.New(), HashToken(code), codeChallenge, redirectTo, userID, ttl.String())
	return err
}

func (s *Store) ConsumeAuthCode(ctx context.Context, code string) (AuthCode, error) {
	const q = `
		UPDATE auth_codes SET consumed_at = now()
		WHERE code = $1 AND consumed_at IS NULL AND expires_at > now()
		RETURNING id, code, user_id, consumed_at`
	var ac AuthCode
	err := s.pool.QueryRow(ctx, q, HashToken(code)).Scan(
		&ac.ID, &ac.Code, &ac.UserID, &ac.Consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthCode{}, ErrNotFound
	}
	return ac, err
}

func (s *Store) AuthCodeChallenge(ctx context.Context, code string) (string, error) {
	const q = `SELECT COALESCE(code_challenge, '') FROM auth_codes WHERE code = $1`
	var challenge string
	err := s.pool.QueryRow(ctx, q, HashToken(code)).Scan(&challenge)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return challenge, err
}

func (s *Store) CreateLoginOTP(
	ctx context.Context,
	email, code, codeChallenge string,
	ttl time.Duration,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO login_otps (id, email, code_hash, code_challenge, expires_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), now() + $5::interval)`,
		uuid.New(), email, HashToken(code), codeChallenge, ttl.String())
	return err
}

func (s *Store) PendingLoginOTP(ctx context.Context, email string) (LoginOTP, error) {
	const q = `
		SELECT id, email, code_hash, COALESCE(code_challenge, ''), consumed_at
		FROM login_otps
		WHERE email = $1 AND consumed_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT 1`
	var otp LoginOTP
	err := s.pool.QueryRow(ctx, q, email).Scan(
		&otp.ID, &otp.Email, &otp.CodeHash, &otp.CodeChallenge, &otp.Consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginOTP{}, ErrNotFound
	}
	return otp, err
}

func (s *Store) ConsumeLoginOTP(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE login_otps SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
