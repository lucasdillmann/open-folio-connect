package connect

const (
	PlanBasic = "basic"

	SubscriptionActive = "active"
)

type challengePair struct {
	Value string
	Nonce string
}

type deviceResponse struct {
	ID                string  `json:"id"`
	UserID            string  `json:"userId"`
	DisplayName       string  `json:"displayName"`
	Platform          string  `json:"platform"`
	DevicePublicKey   *string `json:"devicePublicKey"`
	TrustState        string  `json:"trustState"`
	TrustedKeyVersion *int    `json:"trustedKeyVersion"`
	OSVersion         *string `json:"osVersion"`
	AppVersion        *string `json:"appVersion"`
	LastSeenAt        *string `json:"lastSeenAt"`
	CreatedAt         string  `json:"createdAt"`
}

type trustedDeviceSummary struct {
	LastSeenAt *string `json:"lastSeenAt"`
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Platform   string  `json:"platform"`
}

type registerDeviceRequest struct {
	OSVersion   *string `json:"os_version"`
	AppVersion  *string `json:"app_version"`
	DeviceNonce string  `json:"device_nonce"`
	DisplayName string  `json:"display_name"`
	Platform    string  `json:"platform"`
}

type updateDeviceRequest struct {
	DisplayName *string `json:"display_name"`
}

type initializeKeysRequest struct {
	DeviceID string `json:"device_id"`
}

type commitKeysRequest struct {
	ChallengeResponse *string `json:"challenge_response"`
	RecoveryEnvelope  *string `json:"recovery_envelope"`
	DeviceID          string  `json:"device_id"`
	DeviceKeyEnvelope string  `json:"device_key_envelope"`
	Signature         string  `json:"signature"`
	KeyVersion        int     `json:"key_version"`
}

type resetTeamSyncRequest struct {
	Reason *string `json:"reason"`
}

type pushEventRequest struct {
	EventID           string `json:"event_id"`
	DeviceID          string `json:"device_id"`
	Type              string `json:"type"`
	Entity            string `json:"entity"`
	EntityID          string `json:"entity_id"`
	ClientTimestamp   string `json:"client_timestamp"`
	Payload           string `json:"payload"`
	PayloadKeyVersion int    `json:"payload_key_version"`
}

type pushRequest struct {
	Events []pushEventRequest `json:"events"`
}

type pushResultItem struct {
	EventID string `json:"eventId"`
	Seq     int64  `json:"seq"`
}

type pushResponse struct {
	Accepted     []pushResultItem `json:"accepted"`
	Duplicate    []pushResultItem `json:"duplicate"`
	ServerCursor int64            `json:"serverCursor"`
}

type syncEvent struct {
	EventID           string `json:"eventId"`
	DeviceID          string `json:"deviceId"`
	Type              string `json:"type"`
	Entity            string `json:"entity"`
	EntityID          string `json:"entityId"`
	ClientTimestamp   string `json:"clientTimestamp"`
	Payload           string `json:"payload"`
	UserID            string `json:"userId"`
	TeamID            string `json:"teamId"`
	ServerTimestamp   string `json:"serverTimestamp"`
	PayloadKeyVersion int    `json:"payloadKeyVersion"`
	Seq               int64  `json:"seq"`
}

type pullResponse struct {
	Events     []syncEvent `json:"events"`
	From       int64       `json:"from"`
	To         int64       `json:"to"`
	NextCursor int64       `json:"nextCursor"`
	HasMore    bool        `json:"hasMore"`
}

type latestSnapshotRef struct {
	SnapshotID    string `json:"snapshotId"`
	SchemaVersion int    `json:"schemaVersion"`
	OplogSeq      int64  `json:"oplogSeq"`
}

type cursorResponse struct {
	LatestSnapshot *latestSnapshotRef `json:"latestSnapshot,omitempty"`
	Cursor         int64              `json:"cursor"`
}

type createPairingRequest struct {
	CodeHash           string `json:"code_hash"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

type completePairingRequest struct {
	EncryptedKeyBundle string `json:"encrypted_key_bundle"`
	SASProof           any    `json:"sas_proof"`
	Signature          string `json:"signature"`
}

type claimPairingRequest struct {
	Code               string `json:"code"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

type confirmPairingRequest struct {
	Proof *string `json:"proof"`
}

type snapshotLatestResponse struct {
	SnapshotID    string   `json:"snapshotId"`
	Checksum      string   `json:"checksum"`
	CreatedAt     string   `json:"createdAt"`
	CoversTables  []string `json:"coversTables"`
	SchemaVersion int      `json:"schemaVersion"`
	OplogSeq      int64    `json:"oplogSeq"`
	SizeBytes     int64    `json:"sizeBytes"`
}

type prepareUploadRequest struct {
	EventID           string `json:"event_id"`
	Checksum          string `json:"checksum"`
	MetadataPayload   string `json:"metadata_payload"`
	SizeBytes         int64  `json:"size_bytes"`
	SnapshotSeq       int64  `json:"snapshot_seq"`
	SchemaVersion     int    `json:"schema_version"`
	PayloadKeyVersion int    `json:"payload_key_version"`
}

type completeUploadRequest struct {
	Ticket string `json:"ticket"`
}

type prepareUploadResponse struct {
	Transfer *transferDescriptor `json:"transfer"`
	Ticket   string              `json:"ticket"`
}

type snapshotUploadResponse struct {
	SnapshotID string `json:"snapshotId"`
	R2Key      string `json:"r2Key"`
	CreatedAt  string `json:"createdAt"`
	OplogSeq   int64  `json:"oplogSeq"`
}

type snapshotDownloadResponse struct {
	Transfer *transferDescriptor    `json:"transfer"`
	Snapshot snapshotLatestResponse `json:"snapshot"`
}

type apiUser struct {
	Timezone           *string  `json:"timezone"`
	Email              *string  `json:"email"`
	FullName           *string  `json:"fullName"`
	AvatarURL          *string  `json:"avatarUrl"`
	Locale             *string  `json:"locale"`
	WeekStartsOnMonday *bool    `json:"weekStartsOnMonday"`
	TimezoneAutoSync   *bool    `json:"timezoneAutoSync"`
	TimeFormat         *int     `json:"timeFormat"`
	DateFormat         *string  `json:"dateFormat"`
	TeamID             *string  `json:"teamId"`
	TeamRole           *string  `json:"teamRole"`
	Team               *apiTeam `json:"team"`
	ID                 string   `json:"id"`
}

type apiTeam struct {
	Name                          *string `json:"name"`
	LogoURL                       *string `json:"logoUrl"`
	Plan                          *string `json:"plan"`
	SubscriptionStatus            *string `json:"subscriptionStatus"`
	SubscriptionCurrentPeriodEnd  *string `json:"subscriptionCurrentPeriodEnd"`
	SubscriptionCancelAtPeriodEnd *bool   `json:"subscriptionCancelAtPeriodEnd"`
	CanceledAt                    *string `json:"canceledAt"`
	CountryCode                   *string `json:"countryCode"`
	CreatedAt                     *string `json:"createdAt"`
	ID                            string  `json:"id"`
}

type planLimits struct {
	HouseholdSize          any `json:"householdSize"`
	InstitutionConnections any `json:"institutionConnections"`
	Devices                any `json:"devices"`
}

type planPricing struct {
	Monthly any `json:"monthly"`
	Yearly  any `json:"yearly"`
}

type subscriptionPlan struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Tagline      *string     `json:"tagline"`
	Description  string      `json:"description"`
	Pricing      planPricing `json:"pricing"`
	Limits       planLimits  `json:"limits"`
	Features     []string    `json:"features"`
	IsAvailable  bool        `json:"isAvailable"`
	IsComingSoon bool        `json:"isComingSoon"`
}
