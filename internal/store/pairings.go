package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreatePairing(ctx context.Context, in CreatePairingInput) (Pairing, error) {
	id := uuid.New()
	const q = `
		INSERT INTO pairings (id, team_id, code_hash, issuer_device_id,
		                      issuer_ephemeral_pub, key_version, require_sas, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, team_id, code_hash, issuer_device_id, issuer_ephemeral_pub,
		          claimer_device_id, claimer_ephemeral_pub, status, key_version,
		          require_sas, expires_at, created_at, updated_at`
	return scanPairing(s.pool.QueryRow(ctx, q,
		id, in.TeamID, in.CodeHash, in.IssuerDeviceID, in.IssuerEphemeralPub,
		in.KeyVersion, in.RequireSAS, in.ExpiresAt))
}

func (s *Store) PairingByID(ctx context.Context, teamID, id uuid.UUID) (Pairing, error) {
	const q = `
		SELECT id, team_id, code_hash, issuer_device_id, issuer_ephemeral_pub,
		       claimer_device_id, claimer_ephemeral_pub, status, key_version,
		       require_sas, expires_at, created_at, updated_at
		FROM pairings WHERE team_id = $1 AND id = $2`
	return scanPairing(s.pool.QueryRow(ctx, q, teamID, id))
}

func (s *Store) PairingByCodeHash(ctx context.Context, codeHash string) (Pairing, error) {
	const q = `
		SELECT id, team_id, code_hash, issuer_device_id, issuer_ephemeral_pub,
		       claimer_device_id, claimer_ephemeral_pub, status, key_version,
		       require_sas, expires_at, created_at, updated_at
		FROM pairings WHERE code_hash = $1`
	return scanPairing(s.pool.QueryRow(ctx, q, codeHash))
}

func (s *Store) ClaimPairing(
	ctx context.Context,
	id, claimerDeviceID uuid.UUID,
	claimerEphemeralPub string,
) (Pairing, error) {
	const q = `
		UPDATE pairings
		SET claimer_device_id = $2, claimer_ephemeral_pub = $3,
		    status = 'claimed', updated_at = now()
		WHERE id = $1 AND status = 'open' AND expires_at > now()
		RETURNING id, team_id, code_hash, issuer_device_id, issuer_ephemeral_pub,
		          claimer_device_id, claimer_ephemeral_pub, status, key_version,
		          require_sas, expires_at, created_at, updated_at`
	return scanPairing(s.pool.QueryRow(ctx, q, id, claimerDeviceID, claimerEphemeralPub))
}

func (s *Store) SetPairingStatus(
	ctx context.Context,
	id uuid.UUID,
	from []string,
	to string,
) (Pairing, error) {
	const q = `
		UPDATE pairings SET status = $2, updated_at = now()
		WHERE id = $1 AND status = ANY($3)
		RETURNING id, team_id, code_hash, issuer_device_id, issuer_ephemeral_pub,
		          claimer_device_id, claimer_ephemeral_pub, status, key_version,
		          require_sas, expires_at, created_at, updated_at`
	return scanPairing(s.pool.QueryRow(ctx, q, id, to, from))
}

func (s *Store) ExpirePairings(ctx context.Context, teamID uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE pairings SET status = 'expired', updated_at = now()
		WHERE team_id = $1 AND status IN ('open', 'claimed', 'approved') AND expires_at <= now()`,
		teamID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) AddPairingMessage(
	ctx context.Context,
	pairingID uuid.UUID,
	payloadType, payload string,
) (PairingMessage, error) {
	id := uuid.New()
	const q = `
		INSERT INTO pairing_messages (id, pairing_id, payload_type, payload)
		VALUES ($1, $2, $3, $4)
		RETURNING id, pairing_id, payload_type, payload, created_at`
	var m PairingMessage
	err := s.pool.QueryRow(ctx, q, id, pairingID, payloadType, payload).Scan(
		&m.ID, &m.PairingID, &m.PayloadType, &m.Payload, &m.CreatedAt)
	return m, err
}

func (s *Store) PairingMessages(
	ctx context.Context,
	pairingID uuid.UUID,
) ([]PairingMessage, error) {
	const q = `
		SELECT id, pairing_id, payload_type, payload, created_at
		FROM pairing_messages WHERE pairing_id = $1 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q, pairingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PairingMessage
	for rows.Next() {
		var m PairingMessage
		if err := rows.Scan(
			&m.ID,
			&m.PairingID,
			&m.PayloadType,
			&m.Payload,
			&m.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanPairing(row rowScanner) (Pairing, error) {
	var p Pairing
	err := row.Scan(
		&p.ID, &p.TeamID, &p.CodeHash, &p.IssuerDeviceID, &p.IssuerEphemeralPub,
		&p.ClaimerDeviceID, &p.ClaimerEphemeralPub, &p.Status, &p.KeyVersion,
		&p.RequireSAS, &p.ExpiresAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Pairing{}, ErrNotFound
	}
	return p, err
}
