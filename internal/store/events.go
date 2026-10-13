package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) AppendEvents(
	ctx context.Context,
	teamID, userID uuid.UUID,
	events []PushEventInput,
) (PushOutcome, error) {
	out := PushOutcome{Accepted: []PushResultItem{}, Duplicate: []PushResultItem{}}
	if len(events) == 0 {
		out.ServerCursor, _ = s.Cursor(ctx, teamID)
		return out, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, e := range events {
		var seq int64
		insertErr := tx.QueryRow(ctx, `
			INSERT INTO oplog_events (team_id, event_id, device_id, user_id, event_type,
			                           entity, entity_id, client_timestamp, payload, payload_key_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (team_id, event_id) DO NOTHING
			RETURNING seq`,
			teamID, e.EventID, e.DeviceID, userID, e.EventType,
			e.Entity, e.EntityID, e.ClientTimestamp, e.Payload, e.PayloadKeyVersion,
		).Scan(&seq)

		if errors.Is(insertErr, pgx.ErrNoRows) {
			seqErr := tx.QueryRow(ctx,
				`SELECT seq FROM oplog_events WHERE team_id = $1 AND event_id = $2`,
				teamID, e.EventID).Scan(&seq)
			if seqErr != nil {
				return out, seqErr
			}
			out.Duplicate = append(out.Duplicate, PushResultItem{EventID: e.EventID, Seq: seq})
			continue
		}
		if insertErr != nil {
			return out, insertErr
		}
		out.Accepted = append(out.Accepted, PushResultItem{EventID: e.EventID, Seq: seq})
	}

	cursorErr := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM oplog_events WHERE team_id = $1`, teamID,
	).Scan(&out.ServerCursor)
	if cursorErr != nil {
		return out, cursorErr
	}

	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) PullEvents(
	ctx context.Context,
	teamID uuid.UUID,
	since int64,
	limit int,
) ([]StoredEvent, int64, bool, error) {
	if limit <= 0 {
		limit = 500
	}
	const q = `
		SELECT event_id, device_id, event_type, entity, entity_id, client_timestamp,
		       payload, payload_key_version, seq, user_id, team_id, server_timestamp
		FROM oplog_events
		WHERE team_id = $1 AND seq > $2
		ORDER BY seq
		LIMIT $3`
	rows, err := s.pool.Query(ctx, q, teamID, since, limit)
	if err != nil {
		return nil, since, false, err
	}
	defer rows.Close()

	var out []StoredEvent
	next := since
	for rows.Next() {
		var e StoredEvent
		if err := rows.Scan(
			&e.EventID, &e.DeviceID, &e.EventType, &e.Entity, &e.EntityID,
			&e.ClientTimestamp, &e.Payload, &e.PayloadKeyVersion,
			&e.Seq, &e.UserID, &e.TeamID, &e.ServerTimestamp,
		); err != nil {
			return nil, since, false, err
		}
		out = append(out, e)
		next = e.Seq
	}
	if err := rows.Err(); err != nil {
		return nil, since, false, err
	}

	hasMore := false
	if len(out) > 0 {
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM oplog_events WHERE team_id = $1 AND seq > $2)`,
			teamID, next).Scan(&hasMore); err != nil {
			return nil, since, false, err
		}
	}
	return out, next, hasMore, nil
}

func (s *Store) Cursor(ctx context.Context, teamID uuid.UUID) (int64, error) {
	var c int64
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM oplog_events WHERE team_id = $1`, teamID).Scan(&c)
	return c, err
}

func (s *Store) LatestSnapshotRef(ctx context.Context, teamID uuid.UUID) (SnapshotRef, error) {
	const q = `
		SELECT id, schema_version, oplog_seq, created_at
		FROM snapshots WHERE team_id = $1
		ORDER BY created_at DESC LIMIT 1`
	var r SnapshotRef
	err := s.pool.QueryRow(ctx, q, teamID).
		Scan(&r.SnapshotID, &r.SchemaVersion, &r.OplogSeq, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SnapshotRef{}, ErrNotFound
	}
	return r, err
}
