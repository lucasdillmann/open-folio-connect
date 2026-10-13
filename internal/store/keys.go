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

func (s *Store) CreateChallenge(
	ctx context.Context,
	teamID, deviceID uuid.UUID,
	challenge, nonce string,
	keyVersion int,
	ttl time.Duration,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO key_challenges (id, team_id, device_id, challenge, nonce, key_version, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)`,
		uuid.New(), teamID, deviceID, challenge, nonce, keyVersion, ttl.String())
	return err
}

func (s *Store) PendingChallenge(
	ctx context.Context,
	teamID, deviceID uuid.UUID,
) (KeyChallenge, error) {
	const q = `
		SELECT id, team_id, device_id, challenge, nonce, key_version, consumed_at, expires_at
		FROM key_challenges
		WHERE team_id = $1 AND device_id = $2 AND consumed_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT 1`
	var c KeyChallenge
	err := s.pool.QueryRow(ctx, q, teamID, deviceID).Scan(
		&c.ID, &c.TeamID, &c.DeviceID, &c.Challenge, &c.Nonce,
		&c.KeyVersion, &c.ConsumedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyChallenge{}, ErrNotFound
	}
	return c, err
}

func (s *Store) CommitTeamKeys(
	ctx context.Context,
	teamID, deviceID, challengeID uuid.UUID,
	keyVersion int,
	envelope, signature, challengeResponse string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE key_challenges SET consumed_at = now()
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()`, challengeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}

	tag, err = tx.Exec(ctx, `
		INSERT INTO team_keys (team_id, key_version, state, device_id,
		                       device_key_envelope, signature, challenge_response)
		VALUES ($1, $2, 'ACTIVE', $3, $4, $5, $6)
		ON CONFLICT (team_id) DO NOTHING`,
		teamID, keyVersion, deviceID, envelope, signature, challengeResponse)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}

	if _, err := tx.Exec(ctx,
		`UPDATE devices SET trust_state = 'trusted', trusted_key_version = $3,
		        device_key_envelope = $4
		 WHERE team_id = $1 AND id = $2`,
		teamID, deviceID, keyVersion, envelope); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) CurrentKeyVersion(ctx context.Context, teamID uuid.UUID) (int, error) {
	var v int
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(key_version), 0) FROM team_keys WHERE team_id = $1`, teamID).Scan(&v)
	return v, err
}

func (s *Store) ResetTeamSync(ctx context.Context, teamID uuid.UUID) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, err := s.CurrentKeyVersion(ctx, teamID)
	if err != nil {
		return 0, err
	}

	if _, err := tx.Exec(ctx, `DELETE FROM oplog_events WHERE team_id = $1`, teamID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM snapshots WHERE team_id = $1`, teamID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices
		SET trust_state = 'untrusted', trusted_key_version = NULL WHERE team_id = $1`, teamID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(
		ctx,
		`UPDATE pairings SET status = 'cancelled' WHERE team_id = $1`,
		teamID,
	); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_keys WHERE team_id = $1`, teamID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM key_challenges WHERE team_id = $1`, teamID); err != nil {
		return 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return current + 1, nil
}

func ChallengeResponse(challenge, nonce string) string {
	sum := sha256.Sum256([]byte(challenge + ":" + nonce))
	return hex.EncodeToString(sum[:])
}
