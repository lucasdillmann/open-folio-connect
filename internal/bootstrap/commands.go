package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/lucasdillmann/open-folio-connect/internal/auth"
	"github.com/lucasdillmann/open-folio-connect/internal/config"
	"github.com/lucasdillmann/open-folio-connect/internal/db"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func Command(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return errors.New("usage: ofc code <email>")
	}

	cfg, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := store.New(pool)
	user, err := st.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account for %q; set OFC_ADMIN_EMAIL and restart to create one", email)
	}
	if err != nil {
		return err
	}

	code, err := auth.NewNumericCode(6)
	if err != nil {
		return err
	}
	if err := st.CreateLoginOTP(ctx, user.Email, code, "", cfg.OTPCodeTTL); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "\n  Sign-in code for %s\n\n    %s\n\n  valid for %s\n\n",
		user.Email, code, cfg.OTPCodeTTL)
	return nil
}

func SetPassword(ctx context.Context, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return errors.New("usage: ofc set-password <email> <password>")
	}

	cfg, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := store.New(pool)
	user, err := st.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account for %q", email)
	}
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := st.SetUserPassword(ctx, user.ID, string(hash)); err != nil {
		return err
	}

	slog.Info("password updated", "email", user.Email)
	_, _ = fmt.Fprintf(os.Stdout, "\n  Password updated for %s\n\n", user.Email)
	return nil
}
