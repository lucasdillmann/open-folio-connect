package store

import (
	"time"

	"github.com/google/uuid"
)

const (
	TrustUntrusted = "untrusted"
	TrustTrusted   = "trusted"
	TrustRevoked   = "revoked"
)

const (
	PairingOpen      = "open"
	PairingClaimed   = "claimed"
	PairingApproved  = "approved"
	PairingCompleted = "completed"
	PairingCancelled = "canceled"
	PairingExpired   = "expired"
)

type User struct {
	CreatedAt    time.Time
	PasswordHash *string
	Email        string
	ID           uuid.UUID
}

func (u User) HasPassword() bool {
	return u.PasswordHash != nil && *u.PasswordHash != ""
}

type Team struct {
	CreatedAt time.Time
	Name      string
	ID        uuid.UUID
}

type Membership struct {
	Role   string
	TeamID uuid.UUID
	UserID uuid.UUID
}

type Device struct {
	CreatedAt         time.Time
	OSVersion         *string
	LastSeenAt        *time.Time
	TrustedKeyVersion *int
	DevicePublicKey   *string
	AppVersion        *string
	TrustState        string
	Platform          string
	DisplayName       string
	ID                uuid.UUID
	DeviceNonce       uuid.UUID
	UserID            uuid.UUID
	TeamID            uuid.UUID
}

type RegisterDeviceInput struct {
	OSVersion   *string
	AppVersion  *string
	DisplayName string
	Platform    string
	DeviceNonce uuid.UUID
}

type PushEventInput struct {
	EventID           string
	EventType         string
	Entity            string
	EntityID          string
	ClientTimestamp   string
	Payload           string
	PayloadKeyVersion int
	DeviceID          uuid.UUID
}

type StoredEvent struct {
	ServerTimestamp   time.Time
	EventID           string
	EventType         string
	Entity            string
	EntityID          string
	ClientTimestamp   string
	Payload           string
	PayloadKeyVersion int
	Seq               int64
	DeviceID          uuid.UUID
	UserID            uuid.UUID
	TeamID            uuid.UUID
}

type PushResultItem struct {
	EventID string `json:"eventId"`
	Seq     int64  `json:"seq"`
}

type PushOutcome struct {
	Accepted     []PushResultItem
	Duplicate    []PushResultItem
	ServerCursor int64
}

type SnapshotRef struct {
	CreatedAt     time.Time
	SnapshotID    string
	SchemaVersion int
	OplogSeq      int64
}

type TeamKey struct {
	DeviceID    *uuid.UUID
	State       string
	CommittedAt string
	KeyVersion  int
	TeamID      uuid.UUID
}

type KeyChallenge struct {
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	Challenge  string
	Nonce      string
	KeyVersion int
	ID         uuid.UUID
	TeamID     uuid.UUID
	DeviceID   uuid.UUID
}

type Pairing struct {
	ExpiresAt           time.Time
	UpdatedAt           time.Time
	CreatedAt           time.Time
	ClaimerDeviceID     *uuid.UUID
	ClaimerEphemeralPub *string
	CodeHash            string
	IssuerEphemeralPub  string
	Status              string
	KeyVersion          int
	IssuerDeviceID      uuid.UUID
	ID                  uuid.UUID
	TeamID              uuid.UUID
	RequireSAS          bool
}

type PairingMessage struct {
	CreatedAt   time.Time
	PayloadType string
	Payload     string
	ID          uuid.UUID
	PairingID   uuid.UUID
}

type CreatePairingInput struct {
	ExpiresAt          time.Time
	CodeHash           string
	IssuerEphemeralPub string
	KeyVersion         int
	TeamID             uuid.UUID
	IssuerDeviceID     uuid.UUID
	RequireSAS         bool
}

type SnapshotMeta struct {
	CreatedAt         time.Time
	Checksum          string
	StoragePath       string
	CoversTables      []string
	SchemaVersion     int
	SizeBytes         int64
	PayloadKeyVersion int
	OplogSeq          int64
	ID                uuid.UUID
	TeamID            uuid.UUID
	DeviceID          uuid.UUID
	EventID           uuid.UUID
}

type InsertSnapshotInput struct {
	Checksum          string
	StoragePath       string
	CoversTables      []string
	SchemaVersion     int
	SizeBytes         int64
	PayloadKeyVersion int
	OplogSeq          int64
	DeviceID          uuid.UUID
	EventID           uuid.UUID
}

type RefreshToken struct {
	ExpiresAt time.Time
	RotatedTo *uuid.UUID
	RevokedAt *time.Time
	ID        uuid.UUID
	UserID    uuid.UUID
}

type AuthCode struct {
	Consumed *time.Time
	Code     string
	ID       uuid.UUID
	UserID   uuid.UUID
}

type LoginOTP struct {
	Consumed      *time.Time
	Email         string
	CodeHash      string
	CodeChallenge string
	ID            uuid.UUID
}
