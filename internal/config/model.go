package config

import "time"

type Config struct {
	Addr                   string
	DatabaseURL            string
	LogLevel               string
	AnonKey                string
	DataDir                string
	BaseURL                string
	AdminPassword          string
	AdminEmail             string
	JWTSecret              []byte
	AllowedOrigins         AllowedOrigins
	PairingTTL             time.Duration
	ChallengeTTL           time.Duration
	TransferTTL            time.Duration
	BackupInterval         time.Duration
	AuthCodeTTL            time.Duration
	OTPCodeTTL             time.Duration
	RefreshTokenTTL        time.Duration
	AccessTokenTTL         time.Duration
	MaxSnapshotBytes       int64
	MaxBackupBytes         int64
	PushBatchMax           int
	BackupRetentionDays    int
	BackupManualDailyLimit int
	DevOTP                 bool
}

type AllowedOrigins struct {
	Origins []string
	All     bool
}

func (a AllowedOrigins) Enabled() bool {
	return a.All || len(a.Origins) > 0
}
