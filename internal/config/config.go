package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

func Load() (Config, error) {
	return loadConfig(true)
}

func LoadForCLI() (Config, error) {
	return loadConfig(false)
}

func loadConfig(requireSecret bool) (Config, error) {
	c := Config{
		Addr:        env("OFC_ADDR", ":8080"),
		DatabaseURL: os.Getenv("OFC_DATABASE_URL"),
		AnonKey:     env("OFC_ANON_KEY", "sb_publishable_openfolioconnect"),
		DataDir:     env("OFC_DATA_DIR", "./data"),
		BaseURL:     env("OFC_BASE_URL", "http://localhost:8080"),
		LogLevel:    env("OFC_LOG_LEVEL", "info"),
	}

	var err error
	if c.JWTSecret, err = loadJWTSecret(requireSecret); err != nil {
		return Config{}, err
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("OFC_DATABASE_URL is required")
	}

	if c.AccessTokenTTL, err = durationEnv("OFC_ACCESS_TOKEN_TTL", time.Hour); err != nil {
		return Config{}, err
	}
	if c.RefreshTokenTTL, err = durationEnv("OFC_REFRESH_TOKEN_TTL", 30*24*time.Hour); err != nil {
		return Config{}, err
	}
	if c.OTPCodeTTL, err = durationEnv("OFC_OTP_CODE_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.AuthCodeTTL, err = durationEnv("OFC_AUTH_CODE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.PairingTTL, err = durationEnv("OFC_PAIRING_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.ChallengeTTL, err = durationEnv("OFC_CHALLENGE_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if c.TransferTTL, err = durationEnv("OFC_TRANSFER_TTL", 10*time.Minute); err != nil {
		return Config{}, err
	}
	if c.BackupInterval, err = durationEnv("OFC_BACKUP_INTERVAL", 24*time.Hour); err != nil {
		return Config{}, err
	}
	if c.MaxSnapshotBytes, err = int64Env("OFC_MAX_SNAPSHOT_BYTES", 512*1024*1024); err != nil {
		return Config{}, err
	}
	if c.MaxBackupBytes, err = int64Env("OFC_MAX_BACKUP_BYTES", 256*1024*1024); err != nil {
		return Config{}, err
	}
	if c.BackupRetentionDays, err = nonNegativeIntEnv("OFC_BACKUP_RETENTION_DAYS", 45); err != nil {
		return Config{}, err
	}
	if c.BackupManualDailyLimit, err = nonNegativeIntEnv(
		"OFC_BACKUP_MANUAL_DAILY_LIMIT",
		0,
	); err != nil {
		return Config{}, err
	}
	if c.PushBatchMax, err = intEnv("OFC_PUSH_BATCH_MAX", 2000); err != nil {
		return Config{}, err
	}
	if c.DevOTP, err = boolEnv("OFC_DEV_OTP", false); err != nil {
		return Config{}, err
	}
	if c.AllowedOrigins, err = parseAllowedOrigins(os.Getenv("OFC_ALLOWED_ORIGINS")); err != nil {
		return Config{}, err
	}

	c.AdminEmail = strings.ToLower(strings.TrimSpace(os.Getenv("OFC_ADMIN_EMAIL")))
	c.AdminPassword = os.Getenv("OFC_ADMIN_PASSWORD")

	return c, nil
}

func loadJWTSecret(requireSecret bool) ([]byte, error) {
	raw := os.Getenv("OFC_JWT_SECRET")
	if raw == "" {
		if requireSecret {
			return nil, errors.New("OFC_JWT_SECRET is required to serve requests")
		}

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate jwt secret: %w", err)
		}
		if os.Getenv("OFC_ENV") == "production" {
			return nil, errors.New("OFC_JWT_SECRET is required when OFC_ENV=production")
		}
		slog.Warn(
			"OFC_JWT_SECRET is unset; generated an ephemeral secret. All sessions reset on restart.",
		)
		return buf, nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len(raw) < 32 {
		if !requireSecret {
			return []byte(raw), nil
		}
		return nil, errors.New(
			"OFC_JWT_SECRET must be at least 32 characters (or 32 hex-encoded bytes)",
		)
	}
	return []byte(raw), nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func intEnv(key string, fallback int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return n, nil
}

func nonNegativeIntEnv(key string, fallback int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must not be negative", key)
	}
	return n, nil
}

func int64Env(key string, fallback int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return n, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}
