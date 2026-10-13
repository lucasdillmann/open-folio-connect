package bootstrap

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/lucasdillmann/open-folio-connect/internal/config"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func Ensure(ctx context.Context, s *store.Store, cfg config.Config) error {
	user, err := ensureUser(ctx, s, cfg)
	if err != nil {
		return err
	}
	if user.ID == uuid.Nil {
		slog.Warn("no account exists yet; set OFC_ADMIN_EMAIL before signing in")
		return nil
	}

	team, err := s.Team(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		team, err = s.CreateTeam(ctx, uuid.New(), "Open Folio Connect")
		if err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
		slog.Info("created team", "teamId", team.ID.String())
	case err != nil:
		return err
	default:
	}

	return s.AddMember(ctx, team.ID, user.ID, "owner")
}

func ensureUser(ctx context.Context, s *store.Store, cfg config.Config) (store.User, error) {
	if user, lookupErr := s.UserByEmail(ctx, cfg.AdminEmail); lookupErr == nil {
		if passwordErr := ensurePassword(ctx, s, user, cfg); passwordErr != nil {
			return store.User{}, passwordErr
		}
		return user, nil
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		return store.User{}, lookupErr
	}

	if cfg.AdminEmail == "" {
		return store.User{}, nil
	}

	var hash []byte
	if cfg.AdminPassword != "" {
		var err error
		if hash, err = bcrypt.GenerateFromPassword(
			[]byte(cfg.AdminPassword),
			bcrypt.DefaultCost,
		); err != nil {
			return store.User{}, err
		}
	}

	user, err := s.CreateUser(ctx, uuid.New(), cfg.AdminEmail, string(hash))
	if errors.Is(err, store.ErrConflict) {
		return s.UserByEmail(ctx, cfg.AdminEmail)
	}
	if err != nil {
		return store.User{}, err
	}
	slog.Info("created account", "userId", user.ID.String(), "email", user.Email)
	return user, nil
}

func ensurePassword(ctx context.Context, s *store.Store, user store.User, cfg config.Config) error {
	if user.HasPassword() || cfg.AdminPassword == "" {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.SetUserPassword(ctx, user.ID, string(hash))
}
