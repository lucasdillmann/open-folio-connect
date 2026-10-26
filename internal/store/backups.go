package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type BackupPolicy struct {
	SourceID           *string
	NextDueAt          *time.Time
	LastBackupAt       *time.Time
	ReadGraceExpiresAt *time.Time
	UserID             uuid.UUID
	Revision           int
	Enabled            bool
	UploadEntitled     bool
}

type BackupKey struct {
	RecoveryEnvelope string
	RecoveryRevision int
	TrustedRevision  int
	UserID           uuid.UUID
	KeyID            uuid.UUID
}

type BackupPoint struct {
	PublishedAt       time.Time
	SourceID          string
	Checksum          string
	StoragePath       string
	EncryptedMetadata string
	Trigger           string
	SizeBytes         int64
	Format            int
	BackupID          uuid.UUID
	UserID            uuid.UUID
	KeyID             uuid.UUID
}

type InsertBackupPointInput struct {
	SourceID          string
	Checksum          string
	StoragePath       string
	EncryptedMetadata string
	Trigger           string
	SizeBytes         int64
	Format            int
	BackupID          uuid.UUID
	KeyID             uuid.UUID
}

func (s *Store) BackupPolicy(ctx context.Context, userID uuid.UUID) (BackupPolicy, error) {
	const q = `
		SELECT user_id, enabled, source_id, revision, upload_entitled,
		       next_due_at, last_backup_at, read_grace_expires_at
		FROM backup_policy WHERE user_id = $1`
	return scanBackupPolicy(s.pool.QueryRow(ctx, q, userID))
}

func (s *Store) SetBackupPolicy(
	ctx context.Context,
	userID uuid.UUID,
	revision int,
	sourceID *string,
) (BackupPolicy, error) {
	const q = `
		INSERT INTO backup_policy (user_id, enabled, source_id, revision, upload_entitled, next_due_at)
		VALUES ($1, $2, $3, 1, true, CASE WHEN $2 THEN now() ELSE NULL END)
		ON CONFLICT (user_id) DO UPDATE
		SET enabled = EXCLUDED.enabled,
		    source_id = EXCLUDED.source_id,
		    revision = backup_policy.revision + 1,
		    next_due_at = CASE
		        WHEN NOT EXCLUDED.enabled THEN NULL
		        WHEN NOT backup_policy.enabled
		          OR backup_policy.source_id IS DISTINCT FROM EXCLUDED.source_id THEN now()
		        ELSE backup_policy.next_due_at
		    END,
		    updated_at = now()
		WHERE backup_policy.revision = $4
		RETURNING user_id, enabled, source_id, revision, upload_entitled,
		          next_due_at, last_backup_at, read_grace_expires_at`
	return scanBackupPolicy(s.pool.QueryRow(ctx, q, userID, sourceID != nil, sourceID, revision))
}

func (s *Store) BackupKey(ctx context.Context, userID uuid.UUID) (BackupKey, error) {
	const q = `
		SELECT user_id, key_id, recovery_envelope, recovery_revision, trusted_revision
		FROM backup_keys WHERE user_id = $1`
	return scanBackupKey(s.pool.QueryRow(ctx, q, userID))
}

func (s *Store) CreateBackupKey(
	ctx context.Context,
	userID, keyID uuid.UUID,
	envelope string,
) (BackupKey, bool, error) {
	const q = `
		INSERT INTO backup_keys (user_id, key_id, recovery_envelope, recovery_revision, trusted_revision)
		VALUES ($1, $2, $3, 1, 0)
		ON CONFLICT (user_id) DO UPDATE SET user_id = backup_keys.user_id
		RETURNING user_id, key_id, recovery_envelope, recovery_revision, trusted_revision,
		          (xmax = 0) AS inserted`
	var key BackupKey
	var inserted bool
	err := s.pool.QueryRow(ctx, q, userID, keyID, envelope).Scan(
		&key.UserID, &key.KeyID, &key.RecoveryEnvelope, &key.RecoveryRevision,
		&key.TrustedRevision, &inserted,
	)
	return key, inserted, err
}

func (s *Store) SetBackupRecoveryEnvelope(
	ctx context.Context,
	userID uuid.UUID,
	revision int,
	envelope string,
) (BackupKey, error) {
	const q = `
		UPDATE backup_keys
		SET recovery_envelope = $3, recovery_revision = recovery_revision + 1
		WHERE user_id = $1 AND recovery_revision = $2
		RETURNING user_id, key_id, recovery_envelope, recovery_revision, trusted_revision`
	key, err := scanBackupKey(s.pool.QueryRow(ctx, q, userID, revision, envelope))
	if errors.Is(err, ErrNotFound) {
		if _, lookupErr := s.BackupKey(ctx, userID); lookupErr == nil {
			return BackupKey{}, ErrConflict
		}
	}
	return key, err
}

func (s *Store) BackupTrustedEnvelope(
	ctx context.Context,
	userID, deviceID uuid.UUID,
) (uuid.UUID, int, *string, error) {
	const q = `
		SELECT k.key_id, k.trusted_revision, e.envelope
		FROM backup_keys k
		LEFT JOIN backup_trusted_envelopes e
		  ON e.key_id = k.key_id AND e.device_id = $2
		WHERE k.user_id = $1`
	var keyID uuid.UUID
	var revision int
	var envelope *string
	err := s.pool.QueryRow(ctx, q, userID, deviceID).Scan(&keyID, &revision, &envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, nil, ErrNotFound
	}
	return keyID, revision, envelope, err
}

func (s *Store) SetBackupTrustedEnvelope(
	ctx context.Context,
	userID, deviceID uuid.UUID,
	revision int,
	envelope string,
) (uuid.UUID, int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var keyID uuid.UUID
	var current int
	err = tx.QueryRow(ctx,
		`SELECT key_id, trusted_revision FROM backup_keys WHERE user_id = $1 FOR UPDATE`,
		userID).Scan(&keyID, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, 0, err
	}
	if current != revision {
		return uuid.Nil, 0, ErrConflict
	}

	next := current + 1
	if _, err := tx.Exec(ctx,
		`UPDATE backup_keys SET trusted_revision = $2 WHERE user_id = $1`,
		userID, next); err != nil {
		return uuid.Nil, 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO backup_trusted_envelopes (key_id, device_id, envelope)
		VALUES ($1, $2, $3)
		ON CONFLICT (key_id, device_id) DO UPDATE
		SET envelope = EXCLUDED.envelope, updated_at = now()`,
		keyID, deviceID, envelope); err != nil {
		return uuid.Nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, 0, err
	}
	return keyID, next, nil
}

func (s *Store) BackupHistory(ctx context.Context, userID uuid.UUID) ([]BackupPoint, error) {
	const q = `
		SELECT backup_id, user_id, key_id, source_id, size_bytes, checksum, format,
		       trigger_source, published_at, encrypted_metadata, storage_path
		FROM backup_points WHERE user_id = $1 ORDER BY published_at DESC`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []BackupPoint{}
	for rows.Next() {
		point, scanErr := scanBackupPoint(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, point)
	}
	return out, rows.Err()
}

func (s *Store) BackupPointByID(
	ctx context.Context,
	userID, backupID uuid.UUID,
) (BackupPoint, error) {
	const q = `
		SELECT backup_id, user_id, key_id, source_id, size_bytes, checksum, format,
		       trigger_source, published_at, encrypted_metadata, storage_path
		FROM backup_points WHERE user_id = $1 AND backup_id = $2`
	return scanBackupPoint(s.pool.QueryRow(ctx, q, userID, backupID))
}

func (s *Store) InsertBackupPoint(
	ctx context.Context,
	userID uuid.UUID,
	in InsertBackupPointInput,
) (BackupPoint, error) {
	const q = `
		INSERT INTO backup_points (backup_id, user_id, key_id, source_id, size_bytes,
		                           checksum, format, trigger_source, encrypted_metadata,
		                           storage_path)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (backup_id) DO UPDATE
		SET size_bytes = EXCLUDED.size_bytes,
		    checksum = EXCLUDED.checksum,
		    encrypted_metadata = EXCLUDED.encrypted_metadata,
		    storage_path = EXCLUDED.storage_path
		RETURNING backup_id, user_id, key_id, source_id, size_bytes, checksum, format,
		          trigger_source, published_at, encrypted_metadata, storage_path`
	return scanBackupPoint(s.pool.QueryRow(ctx, q,
		in.BackupID, userID, in.KeyID, in.SourceID, in.SizeBytes, in.Checksum,
		in.Format, in.Trigger, in.EncryptedMetadata, in.StoragePath))
}

func (s *Store) RecordBackupPublished(
	ctx context.Context,
	userID uuid.UUID,
	intervalSeconds int64,
) error {
	const q = `
		UPDATE backup_policy
		SET last_backup_at = now(),
		    next_due_at = now() + make_interval(secs => $2),
		    updated_at = now()
		WHERE user_id = $1`
	_, err := s.pool.Exec(ctx, q, userID, intervalSeconds)
	return err
}

func (s *Store) CountManualBackupsToday(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `
		SELECT COUNT(*) FROM backup_points
		WHERE user_id = $1
		  AND trigger_source = 'manual'
		  AND published_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`
	var count int
	err := s.pool.QueryRow(ctx, q, userID).Scan(&count)
	return count, err
}

func (s *Store) DeleteBackupPoints(
	ctx context.Context,
	userID uuid.UUID,
	backupID *uuid.UUID,
) ([]string, error) {
	var rows pgx.Rows
	var err error
	if backupID == nil {
		rows, err = s.pool.Query(ctx,
			`DELETE FROM backup_points WHERE user_id = $1 RETURNING storage_path`, userID)
	} else {
		rows, err = s.pool.Query(
			ctx,
			`DELETE FROM backup_points WHERE user_id = $1 AND backup_id = $2 RETURNING storage_path`,
			userID,
			*backupID,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStoragePaths(rows)
}

func (s *Store) PruneBackupPoints(
	ctx context.Context,
	userID uuid.UUID,
	before time.Time,
) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`DELETE FROM backup_points WHERE user_id = $1 AND published_at < $2 RETURNING storage_path`,
		userID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStoragePaths(rows)
}

func collectStoragePaths(rows pgx.Rows) ([]string, error) {
	out := []string{}
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		out = append(out, path)
	}
	return out, rows.Err()
}

func scanBackupPolicy(row rowScanner) (BackupPolicy, error) {
	var p BackupPolicy
	err := row.Scan(
		&p.UserID, &p.Enabled, &p.SourceID, &p.Revision, &p.UploadEntitled,
		&p.NextDueAt, &p.LastBackupAt, &p.ReadGraceExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupPolicy{}, ErrNotFound
	}
	return p, err
}

func scanBackupKey(row rowScanner) (BackupKey, error) {
	var k BackupKey
	err := row.Scan(
		&k.UserID, &k.KeyID, &k.RecoveryEnvelope, &k.RecoveryRevision, &k.TrustedRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupKey{}, ErrNotFound
	}
	return k, err
}

func scanBackupPoint(row rowScanner) (BackupPoint, error) {
	var p BackupPoint
	err := row.Scan(
		&p.BackupID, &p.UserID, &p.KeyID, &p.SourceID, &p.SizeBytes, &p.Checksum,
		&p.Format, &p.Trigger, &p.PublishedAt, &p.EncryptedMetadata, &p.StoragePath,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupPoint{}, ErrNotFound
	}
	return p, err
}
