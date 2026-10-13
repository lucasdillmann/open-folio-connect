package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) EnrollDevice(
	ctx context.Context,
	teamID, userID uuid.UUID,
	in RegisterDeviceInput,
) (Device, error) {
	const q = `
		INSERT INTO devices (id, team_id, user_id, device_nonce, display_name,
		                     platform, os_version, app_version, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (team_id, device_nonce) DO UPDATE
		SET display_name = EXCLUDED.display_name,
		    platform     = EXCLUDED.platform,
		    os_version   = EXCLUDED.os_version,
		    app_version  = EXCLUDED.app_version,
		    last_seen_at = now()
		RETURNING id, team_id, user_id, device_nonce, display_name, platform,
		          os_version, app_version, device_public_key, trust_state,
		          trusted_key_version, last_seen_at, created_at`
	return scanDevice(s.pool.QueryRow(ctx, q,
		uuid.New(), teamID, userID, in.DeviceNonce, in.DisplayName,
		in.Platform, in.OSVersion, in.AppVersion))
}

func (s *Store) DeviceByID(ctx context.Context, teamID, id uuid.UUID) (Device, error) {
	const q = `
		SELECT id, team_id, user_id, device_nonce, display_name, platform,
		       os_version, app_version, device_public_key, trust_state,
		       trusted_key_version, last_seen_at, created_at
		FROM devices WHERE team_id = $1 AND id = $2`
	return scanDevice(s.pool.QueryRow(ctx, q, teamID, id))
}

func (s *Store) ListDevices(ctx context.Context, teamID uuid.UUID) ([]Device, error) {
	const q = `
		SELECT id, team_id, user_id, device_nonce, display_name, platform,
		       os_version, app_version, device_public_key, trust_state,
		       trusted_key_version, last_seen_at, created_at
		FROM devices WHERE team_id = $1 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ListTrustedDevices(ctx context.Context, teamID uuid.UUID) ([]Device, error) {
	const q = `
		SELECT id, team_id, user_id, device_nonce, display_name, platform,
		       os_version, app_version, device_public_key, trust_state,
		       trusted_key_version, last_seen_at, created_at
		FROM devices WHERE team_id = $1 AND trust_state = 'trusted' ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) UpdateDevice(
	ctx context.Context,
	teamID, id uuid.UUID,
	displayName, publicKey *string,
) error {
	const q = `
		UPDATE devices
		SET display_name = COALESCE($3, display_name),
		    device_public_key = COALESCE($4, device_public_key)
		WHERE team_id = $1 AND id = $2`
	tag, err := s.pool.Exec(ctx, q, teamID, id, displayName, publicKey)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetDeviceTrust(
	ctx context.Context,
	teamID, id uuid.UUID,
	state string,
	keyVersion *int,
) error {
	const q = `
		UPDATE devices
		SET trust_state = $3,
		    trusted_key_version = CASE WHEN $3 = 'trusted' THEN $4 ELSE trusted_key_version END
		WHERE team_id = $1 AND id = $2`
	tag, err := s.pool.Exec(ctx, q, teamID, id, state, keyVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteDevice(ctx context.Context, teamID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM devices WHERE team_id = $1 AND id = $2`, teamID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchDevice(ctx context.Context, teamID, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = now() WHERE team_id = $1 AND id = $2`, teamID, id)
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDevice(row rowScanner) (Device, error) {
	var d Device
	err := row.Scan(
		&d.ID, &d.TeamID, &d.UserID, &d.DeviceNonce, &d.DisplayName, &d.Platform,
		&d.OSVersion, &d.AppVersion, &d.DevicePublicKey, &d.TrustState,
		&d.TrustedKeyVersion, &d.LastSeenAt, &d.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return d, err
}
