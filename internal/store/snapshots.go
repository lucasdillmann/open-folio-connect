package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) InsertSnapshot(
	ctx context.Context,
	teamID uuid.UUID,
	in InsertSnapshotInput,
) (SnapshotMeta, error) {
	id := uuid.New()
	const q = `
		INSERT INTO snapshots (id, team_id, device_id, event_id, schema_version,
		                       covers_tables, size_bytes, checksum, storage_path,
		                       payload_key_version, oplog_seq)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (team_id, event_id) DO UPDATE SET storage_path = EXCLUDED.storage_path
		RETURNING id, team_id, device_id, event_id, schema_version, covers_tables,
		          size_bytes, checksum, storage_path, payload_key_version, oplog_seq, created_at`
	return scanSnapshot(s.pool.QueryRow(ctx, q,
		id, teamID, in.DeviceID, in.EventID, in.SchemaVersion, in.CoversTables,
		in.SizeBytes, in.Checksum, in.StoragePath, in.PayloadKeyVersion, in.OplogSeq))
}

func (s *Store) LatestSnapshot(ctx context.Context, teamID uuid.UUID) (SnapshotMeta, error) {
	const q = `
		SELECT id, team_id, device_id, event_id, schema_version, covers_tables,
		       size_bytes, checksum, storage_path, payload_key_version, oplog_seq, created_at
		FROM snapshots WHERE team_id = $1 ORDER BY created_at DESC LIMIT 1`
	return scanSnapshot(s.pool.QueryRow(ctx, q, teamID))
}

func (s *Store) SnapshotByID(ctx context.Context, teamID, id uuid.UUID) (SnapshotMeta, error) {
	const q = `
		SELECT id, team_id, device_id, event_id, schema_version, covers_tables,
		       size_bytes, checksum, storage_path, payload_key_version, oplog_seq, created_at
		FROM snapshots WHERE team_id = $1 AND id = $2`
	return scanSnapshot(s.pool.QueryRow(ctx, q, teamID, id))
}

func scanSnapshot(row rowScanner) (SnapshotMeta, error) {
	var m SnapshotMeta
	err := row.Scan(
		&m.ID, &m.TeamID, &m.DeviceID, &m.EventID, &m.SchemaVersion, &m.CoversTables,
		&m.SizeBytes, &m.Checksum, &m.StoragePath, &m.PayloadKeyVersion,
		&m.OplogSeq, &m.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SnapshotMeta{}, ErrNotFound
	}
	return m, err
}
