package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	const q = `
		SELECT id, email, password, created_at
		FROM users
		WHERE email = $1`
	var u User
	err := s.pool.QueryRow(ctx, q, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (User, error) {
	const q = `SELECT id, email, password, created_at FROM users WHERE id = $1`
	var u User
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) CreateUser(
	ctx context.Context,
	id uuid.UUID,
	email, passwordHash string,
) (User, error) {
	const q = `
		INSERT INTO users (id, email, password) VALUES ($1, $2, NULLIF($3, ''))
		RETURNING id, email, password, created_at`
	var u User
	err := s.pool.QueryRow(ctx, q, id, email, passwordHash).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt,
	)
	if isUniqueViolation(err) {
		return User{}, ErrConflict
	}
	return u, err
}

func (s *Store) SetUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password = $2, updated_at = now() WHERE id = $1`, id, passwordHash)
	return err
}

func (s *Store) CreateTeam(ctx context.Context, id uuid.UUID, name string) (Team, error) {
	const q = `
		INSERT INTO teams (id, name) VALUES ($1, $2)
		RETURNING id, name, created_at`
	var t Team
	err := s.pool.QueryRow(ctx, q, id, name).Scan(&t.ID, &t.Name, &t.CreatedAt)
	return t, err
}

func (s *Store) Team(ctx context.Context) (Team, error) {
	const q = `
		SELECT id, name, created_at FROM teams ORDER BY created_at LIMIT 1`
	var t Team
	err := s.pool.QueryRow(ctx, q).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	return t, err
}

func (s *Store) MembershipForUser(ctx context.Context, userID uuid.UUID) (Membership, error) {
	const q = `SELECT team_id, user_id, role FROM team_members WHERE user_id = $1`
	var m Membership
	err := s.pool.QueryRow(ctx, q, userID).Scan(&m.TeamID, &m.UserID, &m.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	return m, err
}

func (s *Store) AddMember(ctx context.Context, teamID, userID uuid.UUID, role string) error {
	const q = `
		INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (team_id, user_id) DO NOTHING`
	_, err := s.pool.Exec(ctx, q, teamID, userID, role)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
