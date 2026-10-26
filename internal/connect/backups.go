package connect

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/blobs"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

const maxBackupMetadataBytes = 64 * 1024

type backupPolicyResponse struct {
	SourceID           *string `json:"sourceId"`
	NextDueAt          *string `json:"nextDueAt"`
	LastBackupAt       *string `json:"lastBackupAt"`
	ReadGraceExpiresAt *string `json:"readGraceExpiresAt"`
	TeamID             *string `json:"teamId"`
	UserID             string  `json:"userId"`
	Revision           int     `json:"revision"`
	Enabled            bool    `json:"enabled"`
	UploadEntitled     bool    `json:"uploadEntitled"`
}

type backupKeyResponse struct {
	KeyID            string          `json:"keyId"`
	RecoveryEnvelope json.RawMessage `json:"recoveryEnvelope"`
	RecoveryRevision int             `json:"recoveryRevision"`
	TrustedRevision  int             `json:"trustedRevision"`
	Created          bool            `json:"created"`
}

type backupPointResponse struct {
	BackupID          string `json:"backupId"`
	KeyID             string `json:"keyId"`
	UserID            string `json:"userId"`
	SourceID          string `json:"sourceId"`
	Checksum          string `json:"checksum"`
	PublishedAt       string `json:"publishedAt"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	SizeBytes         int64  `json:"sizeBytes"`
	Format            int    `json:"format"`
}

type trustedEnvelopeResponse struct {
	KeyID    string          `json:"keyId"`
	Envelope json.RawMessage `json:"envelope"`
	Revision int             `json:"revision"`
}

type prepareBackupUploadResponse struct {
	Published *backupPointResponse `json:"published,omitempty"`
	Transfer  *transferDescriptor  `json:"transfer,omitempty"`
	Ticket    string               `json:"ticket,omitempty"`
}

type backupDownloadResponse struct {
	Transfer *transferDescriptor `json:"transfer"`
	Backup   backupPointResponse `json:"backup"`
}

type backupPolicyPutRequest struct {
	SourceID *string `json:"source_id"`
	Revision int     `json:"revision"`
	Enabled  bool    `json:"enabled"`
}

type backupKeyPutRequest struct {
	KeyID            string          `json:"key_id"`
	RecoveryEnvelope json.RawMessage `json:"recovery_envelope"`
}

type backupEnvelopePutRequest struct {
	Envelope json.RawMessage `json:"envelope"`
	Revision int             `json:"revision"`
}

type backupPrepareRequest struct {
	BackupID          string `json:"backup_id"`
	KeyID             string `json:"key_id"`
	SourceID          string `json:"source_id"`
	Checksum          string `json:"checksum"`
	EncryptedMetadata string `json:"encrypted_metadata"`
	Trigger           string `json:"trigger"`
	SizeBytes         int64  `json:"size_bytes"`
	PolicyRevision    int    `json:"policy_revision"`
	Format            int    `json:"format"`
}

type backupPrepareValues struct {
	SourceID string
	Checksum string
	BackupID uuid.UUID
	KeyID    uuid.UUID
}

type backupTicket struct {
	UserID            string `json:"u"`
	BackupID          string `json:"b"`
	KeyID             string `json:"k"`
	SourceID          string `json:"s"`
	Path              string `json:"p"`
	Checksum          string `json:"c"`
	EncryptedMetadata string `json:"m"`
	Trigger           string `json:"t"`
	Size              int64  `json:"z"`
	Format            int    `json:"f"`
	Exp               int64  `json:"x"`
}

func (h *Handler) backupPolicy(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	policy, err := h.store.BackupPolicy(r.Context(), identity.UserID)
	if errors.Is(err, store.ErrNotFound) {
		policy = store.BackupPolicy{UserID: identity.UserID, UploadEntitled: true}
	} else if err != nil {
		h.internal(w, "load backup policy", err)
		return
	}
	h.writeBackupPolicy(w, policy, identity.TeamID)
}

func (h *Handler) putBackupPolicy(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req backupPolicyPutRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	policy, err := h.store.SetBackupPolicy(
		r.Context(), identity.UserID, req.Revision, normalizeBackupSource(req.SourceID))
	if errors.Is(err, store.ErrConflict) {
		httpx.Conflict(w, "BACKUP_POLICY_CONFLICT",
			"backup policy changed; reload and retry")
		return
	}
	if err != nil {
		h.internal(w, "update backup policy", err)
		return
	}
	h.writeBackupPolicy(w, policy, identity.TeamID)
}

func (h *Handler) writeBackupPolicy(w http.ResponseWriter, p store.BackupPolicy, teamID uuid.UUID) {
	team := teamID.String()
	httpx.WriteJSON(w, http.StatusOK, backupPolicyResponse{
		UserID:             p.UserID.String(),
		TeamID:             &team,
		SourceID:           p.SourceID,
		NextDueAt:          formatTimePtr(p.NextDueAt),
		LastBackupAt:       formatTimePtr(p.LastBackupAt),
		ReadGraceExpiresAt: formatTimePtr(p.ReadGraceExpiresAt),
		Revision:           p.Revision,
		Enabled:            p.Enabled,
		UploadEntitled:     p.UploadEntitled,
	})
}

func (h *Handler) backupKey(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	key, err := h.store.BackupKey(r.Context(), identity.UserID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteJSON(w, http.StatusOK, json.RawMessage("null"))
		return
	}
	if err != nil {
		h.internal(w, "load backup key", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newBackupKey(key, false))
}

func (h *Handler) putBackupKey(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req backupKeyPutRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	keyID, err := uuid.Parse(strings.TrimSpace(req.KeyID))
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_KEY", "key_id must be a uuid")
		return
	}
	if !validBackupEnvelope(req.RecoveryEnvelope) {
		httpx.BadRequest(w, "INVALID_BACKUP_KEY", "recovery_envelope is required")
		return
	}
	key, created, err := h.store.CreateBackupKey(
		r.Context(), identity.UserID, keyID, string(req.RecoveryEnvelope))
	if err != nil {
		h.internal(w, "create backup key", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newBackupKey(key, created))
}

func (h *Handler) backupTrustedEnvelope(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	device, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	keyID, revision, envelope, err := h.store.BackupTrustedEnvelope(
		r.Context(), identity.UserID, device.ID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "BACKUP_SETUP_REQUIRED", "no backup key has been set up")
		return
	}
	if err != nil {
		h.internal(w, "load backup trusted envelope", err)
		return
	}
	resp := trustedEnvelopeResponse{KeyID: keyID.String(), Revision: revision}
	if envelope != nil {
		resp.Envelope = json.RawMessage(*envelope)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) putBackupTrustedEnvelope(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	device, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	var req backupEnvelopePutRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !validBackupEnvelope(req.Envelope) {
		httpx.BadRequest(w, "INVALID_BACKUP_ENVELOPE", "envelope is required")
		return
	}
	keyID, revision, err := h.store.SetBackupTrustedEnvelope(
		r.Context(), identity.UserID, device.ID, req.Revision, string(req.Envelope))
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "BACKUP_SETUP_REQUIRED", "no backup key has been set up")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		httpx.Conflict(w, "BACKUP_TRUSTED_CONFLICT", "trusted envelope changed; retry")
		return
	}
	if err != nil {
		h.internal(w, "update backup trusted envelope", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, trustedEnvelopeResponse{
		KeyID:    keyID.String(),
		Revision: revision,
		Envelope: req.Envelope,
	})
}

func (h *Handler) putBackupRecoveryEnvelope(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req backupEnvelopePutRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !validBackupEnvelope(req.Envelope) {
		httpx.BadRequest(w, "INVALID_BACKUP_ENVELOPE", "envelope is required")
		return
	}
	key, err := h.store.SetBackupRecoveryEnvelope(
		r.Context(), identity.UserID, req.Revision, string(req.Envelope))
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "BACKUP_SETUP_REQUIRED", "no backup key has been set up")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		httpx.Conflict(w, "BACKUP_RECOVERY_CONFLICT", "recovery envelope changed; retry")
		return
	}
	if err != nil {
		h.internal(w, "update backup recovery envelope", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newBackupKey(key, false))
}

func (h *Handler) backupHistory(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	points, err := h.store.BackupHistory(r.Context(), identity.UserID)
	if err != nil {
		h.internal(w, "load backup history", err)
		return
	}
	out := make([]backupPointResponse, 0, len(points))
	for _, point := range points {
		out = append(out, newBackupPoint(point))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) prepareBackupUpload(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req backupPrepareRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	values, ok := h.validateBackupPrepare(w, req)
	if !ok {
		return
	}
	if h.backupAlreadyPublished(w, r, identity.UserID, values.BackupID) {
		return
	}
	if !h.backupSourceMatches(w, r, identity.UserID, values.SourceID, req.PolicyRevision) {
		return
	}
	if !h.backupKeyMatches(w, r, identity.UserID, values.KeyID) {
		return
	}
	if !h.backupManualAllowed(w, r, identity.UserID, req.Trigger) {
		return
	}

	expires := time.Now().Add(h.cfg.TransferTTL).Unix()
	path := blobs.BackupRelPath(values.BackupID.String())
	ticket, err := h.signPayload(backupTicket{
		UserID:            identity.UserID.String(),
		BackupID:          values.BackupID.String(),
		KeyID:             values.KeyID.String(),
		SourceID:          values.SourceID,
		Path:              path,
		Checksum:          values.Checksum,
		EncryptedMetadata: req.EncryptedMetadata,
		Trigger:           req.Trigger,
		Size:              req.SizeBytes,
		Format:            req.Format,
		Exp:               expires,
	})
	if err != nil {
		h.internal(w, "sign backup ticket", err)
		return
	}
	descriptor, err := h.uploadTransferDescriptor(transferClaims{
		Dir:      blobs.BackupDir,
		ID:       values.BackupID.String(),
		Path:     path,
		Mode:     "w",
		Checksum: values.Checksum,
		Size:     req.SizeBytes,
		Exp:      expires,
	})
	if err != nil {
		h.internal(w, "sign backup transfer", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, prepareBackupUploadResponse{
		Ticket:   ticket,
		Transfer: descriptor,
	})
}

func (h *Handler) validateBackupPrepare(
	w http.ResponseWriter,
	req backupPrepareRequest,
) (backupPrepareValues, bool) {
	backupID, err := uuid.Parse(strings.TrimSpace(req.BackupID))
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_ID", "backup_id must be a uuid")
		return backupPrepareValues{}, false
	}
	keyID, err := uuid.Parse(strings.TrimSpace(req.KeyID))
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_KEY", "key_id must be a uuid")
		return backupPrepareValues{}, false
	}
	sourceID := strings.TrimSpace(req.SourceID)
	if sourceID == "" {
		httpx.BadRequest(w, "INVALID_BACKUP_SOURCE", "source_id is required")
		return backupPrepareValues{}, false
	}
	if req.Format <= 0 {
		httpx.BadRequest(w, "INVALID_BACKUP_FORMAT", "format must be positive")
		return backupPrepareValues{}, false
	}
	switch req.Trigger {
	case "setup", "scheduled", "manual":
	default:
		httpx.BadRequest(w, "INVALID_BACKUP_TRIGGER", "trigger is invalid")
		return backupPrepareValues{}, false
	}
	if req.SizeBytes <= 0 {
		httpx.BadRequest(w, "INVALID_BACKUP_SIZE", "size_bytes must be positive")
		return backupPrepareValues{}, false
	}
	if req.SizeBytes > h.cfg.MaxBackupBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "BACKUP_TOO_LARGE",
			"backup exceeds the configured maximum size")
		return backupPrepareValues{}, false
	}
	checksum := blobs.FormatChecksum(req.Checksum)
	if !validChecksumFormat(checksum) {
		httpx.BadRequest(w, "INVALID_BACKUP_CHECKSUM", "checksum must be sha256:<64 hex chars>")
		return backupPrepareValues{}, false
	}
	if len(req.EncryptedMetadata) > maxBackupMetadataBytes {
		httpx.BadRequest(w, "INVALID_BACKUP_METADATA", "encrypted_metadata is too large")
		return backupPrepareValues{}, false
	}
	return backupPrepareValues{
		BackupID: backupID,
		KeyID:    keyID,
		SourceID: sourceID,
		Checksum: checksum,
	}, true
}

func (h *Handler) backupAlreadyPublished(
	w http.ResponseWriter,
	r *http.Request,
	userID, backupID uuid.UUID,
) bool {
	existing, err := h.store.BackupPointByID(r.Context(), userID, backupID)
	if err == nil {
		point := newBackupPoint(existing)
		httpx.WriteJSON(w, http.StatusOK, prepareBackupUploadResponse{Published: &point})
		return true
	}
	if !errors.Is(err, store.ErrNotFound) {
		h.internal(w, "load backup point", err)
		return true
	}
	return false
}

func (h *Handler) backupSourceMatches(
	w http.ResponseWriter,
	r *http.Request,
	userID uuid.UUID,
	sourceID string,
	revision int,
) bool {
	policy, err := h.store.BackupPolicy(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Conflict(w, "BACKUP_SOURCE_MISMATCH", "cloud backups are not enabled")
		return false
	}
	if err != nil {
		h.internal(w, "load backup policy", err)
		return false
	}
	if !policy.Enabled || policy.SourceID == nil || *policy.SourceID != sourceID {
		httpx.Conflict(w, "BACKUP_SOURCE_MISMATCH", "this profile is not the backup source")
		return false
	}
	if revision != policy.Revision {
		httpx.Conflict(w, "BACKUP_POLICY_CONFLICT", "backup policy changed; retry")
		return false
	}
	return true
}

func (h *Handler) backupKeyMatches(
	w http.ResponseWriter,
	r *http.Request,
	userID, keyID uuid.UUID,
) bool {
	key, err := h.store.BackupKey(r.Context(), userID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Conflict(w, "BACKUP_SETUP_REQUIRED", "no backup key has been set up")
		return false
	}
	if err != nil {
		h.internal(w, "load backup key", err)
		return false
	}
	if key.KeyID != keyID {
		httpx.Conflict(w, "BACKUP_KEY_MISMATCH", "backup key changed; reload and retry")
		return false
	}
	return true
}

func (h *Handler) backupManualAllowed(
	w http.ResponseWriter,
	r *http.Request,
	userID uuid.UUID,
	trigger string,
) bool {
	if trigger != "manual" || h.cfg.BackupManualDailyLimit <= 0 {
		return true
	}
	count, err := h.store.CountManualBackupsToday(r.Context(), userID)
	if err != nil {
		h.internal(w, "count manual backups", err)
		return false
	}
	if count >= h.cfg.BackupManualDailyLimit {
		httpx.Error(w, http.StatusTooManyRequests, "BACKUP_MANUAL_LIMIT",
			"daily manual backup limit reached")
		return false
	}
	return true
}

func (h *Handler) completeBackupUpload(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req completeUploadRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	var ticket backupTicket
	if err := h.verifyPayload(req.Ticket, &ticket); err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_TICKET", "ticket is invalid")
		return
	}
	if transferExpired(ticket.Exp) {
		httpx.Conflict(w, "BACKUP_UPLOAD_EXPIRED", "ticket has expired")
		return
	}
	if ticket.UserID != identity.UserID.String() {
		httpx.Forbidden(w, "BACKUP_USER_MISMATCH", "ticket belongs to another account")
		return
	}
	backupID, err := uuid.Parse(ticket.BackupID)
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_TICKET", "ticket backup id is invalid")
		return
	}

	existing, lookupErr := h.store.BackupPointByID(r.Context(), identity.UserID, backupID)
	if lookupErr == nil {
		httpx.WriteJSON(w, http.StatusOK, newBackupPoint(existing))
		return
	}
	if !errors.Is(lookupErr, store.ErrNotFound) {
		h.internal(w, "load backup point", lookupErr)
		return
	}

	file, size, err := h.blobs.Open(ticket.Path)
	if errors.Is(err, os.ErrNotExist) {
		httpx.NotFound(w, "TRANSFER_OBJECT_MISSING",
			"the backup bytes were not uploaded before completion")
		return
	}
	if err != nil {
		h.internal(w, "open backup for completion", err)
		return
	}
	_ = file.Close()
	if size != ticket.Size {
		httpx.Conflict(w, "BACKUP_SIZE_MISMATCH",
			"stored backup size does not match the prepared upload")
		return
	}
	keyID, err := uuid.Parse(ticket.KeyID)
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_TICKET", "ticket key id is invalid")
		return
	}

	point, err := h.store.InsertBackupPoint(
		r.Context(),
		identity.UserID,
		store.InsertBackupPointInput{
			BackupID:          backupID,
			KeyID:             keyID,
			SourceID:          ticket.SourceID,
			Checksum:          ticket.Checksum,
			StoragePath:       ticket.Path,
			EncryptedMetadata: ticket.EncryptedMetadata,
			Trigger:           ticket.Trigger,
			SizeBytes:         size,
			Format:            ticket.Format,
		},
	)
	if err != nil {
		h.internal(w, "record backup", err)
		return
	}

	if err := h.store.RecordBackupPublished(
		r.Context(), identity.UserID, int64(h.cfg.BackupInterval.Seconds())); err != nil {
		slog.Error("record backup schedule", "error", err)
	}
	h.pruneBackups(r, identity.UserID)

	slog.Info("backup uploaded",
		"backupId", point.BackupID.String(), "userId", identity.UserID.String(),
		"sizeBytes", point.SizeBytes, "trigger", point.Trigger,
		"requestId", httpx.RequestID(r))

	httpx.WriteJSON(w, http.StatusOK, newBackupPoint(point))
}

func (h *Handler) pruneBackups(r *http.Request, userID uuid.UUID) {
	if h.cfg.BackupRetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -h.cfg.BackupRetentionDays)
	paths, err := h.store.PruneBackupPoints(r.Context(), userID, cutoff)
	if err != nil {
		slog.Error("prune backups", "error", err)
		return
	}
	for _, path := range paths {
		if err := h.blobs.Remove(path); err != nil {
			slog.Error("remove pruned backup", "error", err, "path", path)
		}
	}
}

func (h *Handler) backupDownloadURL(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	backupID, err := uuid.Parse(r.PathValue("backupId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_BACKUP_ID", "backupId must be a uuid")
		return
	}
	point, err := h.store.BackupPointByID(r.Context(), identity.UserID, backupID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "BACKUP_NOT_FOUND", "backup not found")
		return
	}
	if err != nil {
		h.internal(w, "load backup", err)
		return
	}
	descriptor, err := h.downloadTransferDescriptor(transferClaims{
		Dir:      blobs.BackupDir,
		Path:     point.StoragePath,
		Mode:     "r",
		Checksum: point.Checksum,
		Size:     point.SizeBytes,
		Exp:      time.Now().Add(h.cfg.TransferTTL).Unix(),
	})
	if err != nil {
		h.internal(w, "sign backup download", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, backupDownloadResponse{
		Backup:   newBackupPoint(point),
		Transfer: descriptor,
	})
}

func (h *Handler) deleteBackups(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var backupID *uuid.UUID
	if raw := strings.TrimSpace(r.PathValue("backupId")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.BadRequest(w, "INVALID_BACKUP_ID", "backupId must be a uuid")
			return
		}
		backupID = &id
	}
	paths, err := h.store.DeleteBackupPoints(r.Context(), identity.UserID, backupID)
	if err != nil {
		h.internal(w, "delete backups", err)
		return
	}
	for _, path := range paths {
		if err := h.blobs.Remove(path); err != nil {
			slog.Error("remove deleted backup", "error", err, "path", path)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func newBackupKey(key store.BackupKey, created bool) backupKeyResponse {
	return backupKeyResponse{
		KeyID:            key.KeyID.String(),
		RecoveryEnvelope: json.RawMessage(key.RecoveryEnvelope),
		RecoveryRevision: key.RecoveryRevision,
		TrustedRevision:  key.TrustedRevision,
		Created:          created,
	}
}

func newBackupPoint(point store.BackupPoint) backupPointResponse {
	return backupPointResponse{
		BackupID:          point.BackupID.String(),
		KeyID:             point.KeyID.String(),
		UserID:            point.UserID.String(),
		SourceID:          point.SourceID,
		Checksum:          point.Checksum,
		PublishedAt:       formatTime(point.PublishedAt),
		EncryptedMetadata: point.EncryptedMetadata,
		SizeBytes:         point.SizeBytes,
		Format:            point.Format,
	}
}

func normalizeBackupSource(value *string) *string {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func validBackupEnvelope(value json.RawMessage) bool {
	if len(value) == 0 {
		return false
	}
	var object map[string]any
	return json.Unmarshal(value, &object) == nil && object != nil
}
