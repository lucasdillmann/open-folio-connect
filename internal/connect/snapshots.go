package connect

import (
	"crypto/sha256"
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

func (h *Handler) prepareSnapshotUpload(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}

	var req prepareUploadRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	eventID, err := uuid.Parse(strings.TrimSpace(req.EventID))
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_EVENT_ID", "event_id must be a uuid")
		return
	}
	if req.SnapshotSeq < 0 {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_BASE_SEQ",
			"snapshot_seq must be a non-negative integer")
		return
	}
	if req.SchemaVersion <= 0 {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_SCHEMA_VERSION",
			"schema_version must be positive")
		return
	}
	if req.PayloadKeyVersion <= 0 {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_KEY_VERSION",
			"payload_key_version must be positive")
		return
	}
	if req.SizeBytes <= 0 {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_SIZE", "size_bytes must be positive")
		return
	}
	if req.SizeBytes > h.cfg.MaxSnapshotBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "SNAPSHOT_TOO_LARGE",
			"snapshot exceeds the configured maximum size")
		return
	}
	checksum := blobs.FormatChecksum(req.Checksum)
	if !validChecksumFormat(checksum) {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_CHECKSUM",
			"checksum must be sha256:<64 hex chars>")
		return
	}

	snapshotID := deterministicSnapshotID(identity.TeamID, eventID)
	storagePath := blobs.SnapshotRelPath(snapshotID)
	expires := time.Now().Add(h.cfg.TransferTTL).Unix()

	ticket, err := h.signPayload(uploadTicket{
		TeamID:            identity.TeamID.String(),
		EventID:           eventID.String(),
		Path:              storagePath,
		Checksum:          checksum,
		Size:              req.SizeBytes,
		SnapshotSeq:       req.SnapshotSeq,
		SchemaVersion:     req.SchemaVersion,
		PayloadKeyVersion: req.PayloadKeyVersion,
		Exp:               expires,
	})
	if err != nil {
		h.internal(w, "sign upload ticket", err)
		return
	}

	descriptor, err := h.uploadTransferDescriptor(transferClaims{
		ID:       snapshotID,
		Path:     storagePath,
		Mode:     "w",
		Checksum: checksum,
		Size:     req.SizeBytes,
		Exp:      expires,
	})
	if err != nil {
		h.internal(w, "sign upload transfer", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, prepareUploadResponse{
		Transfer: descriptor,
		Ticket:   ticket,
	})
}

func (h *Handler) completeSnapshotUpload(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	device, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}

	var req completeUploadRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	var ticket uploadTicket
	if err := h.verifyPayload(req.Ticket, &ticket); err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_TICKET", "ticket is invalid")
		return
	}
	if transferExpired(ticket.Exp) {
		httpx.Conflict(w, "SNAPSHOT_UPLOAD_EXPIRED", "ticket has expired")
		return
	}
	if ticket.TeamID != identity.TeamID.String() {
		httpx.Forbidden(w, "SNAPSHOT_TEAM_MISMATCH", "ticket belongs to another team")
		return
	}
	eventID, err := uuid.Parse(ticket.EventID)
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_TICKET", "ticket event id is invalid")
		return
	}

	file, size, err := h.blobs.Open(ticket.Path)
	if errors.Is(err, os.ErrNotExist) {
		httpx.Conflict(w, "SNAPSHOT_TRANSFER_MISSING",
			"the snapshot bytes were not uploaded before completion")
		return
	}
	if err != nil {
		h.internal(w, "open snapshot for completion", err)
		return
	}
	_ = file.Close()

	if size != ticket.Size {
		httpx.Conflict(w, "SNAPSHOT_SIZE_MISMATCH",
			"stored snapshot size does not match the prepared upload")
		return
	}

	meta, err := h.store.InsertSnapshot(r.Context(), identity.TeamID, store.InsertSnapshotInput{
		DeviceID:          device.ID,
		EventID:           eventID,
		SchemaVersion:     ticket.SchemaVersion,
		CoversTables:      []string{},
		SizeBytes:         size,
		Checksum:          ticket.Checksum,
		StoragePath:       ticket.Path,
		PayloadKeyVersion: ticket.PayloadKeyVersion,
		OplogSeq:          ticket.SnapshotSeq,
	})
	if err != nil {
		h.internal(w, "record snapshot", err)
		return
	}

	slog.Info("snapshot uploaded",
		"snapshotId", meta.ID.String(), "teamId", identity.TeamID.String(),
		"sizeBytes", size, "oplogSeq", meta.OplogSeq, "requestId", httpx.RequestID(r))

	httpx.WriteJSON(w, http.StatusOK, snapshotUploadResponse{
		SnapshotID: meta.ID.String(),
		R2Key:      meta.StoragePath,
		OplogSeq:   meta.OplogSeq,
		CreatedAt:  formatTime(meta.CreatedAt),
	})
}

func (h *Handler) latestSnapshot(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}
	meta, err := h.store.LatestSnapshot(r.Context(), identity.TeamID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "SNAPSHOT_NOT_FOUND", "no snapshot has been uploaded yet")
		return
	}
	if err != nil {
		h.internal(w, "load latest snapshot", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newSnapshotLatest(meta))
}

func (h *Handler) snapshotDownloadURL(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}

	id, err := uuid.Parse(r.PathValue("snapshotId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_ID", "snapshotId must be a uuid")
		return
	}
	meta, err := h.store.SnapshotByID(r.Context(), identity.TeamID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "SNAPSHOT_NOT_FOUND", "snapshot not found")
		return
	}
	if err != nil {
		h.internal(w, "load snapshot", err)
		return
	}

	descriptor, err := h.downloadTransferDescriptor(transferClaims{
		Path:     meta.StoragePath,
		Mode:     "r",
		Checksum: meta.Checksum,
		Size:     meta.SizeBytes,
		Exp:      time.Now().Add(h.cfg.TransferTTL).Unix(),
	})
	if err != nil {
		h.internal(w, "sign download transfer", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, snapshotDownloadResponse{
		Transfer: descriptor,
		Snapshot: newSnapshotLatest(meta),
	})
}

func newSnapshotLatest(m store.SnapshotMeta) snapshotLatestResponse {
	tables := m.CoversTables
	if tables == nil {
		tables = []string{}
	}
	return snapshotLatestResponse{
		SnapshotID:    m.ID.String(),
		SchemaVersion: m.SchemaVersion,
		CoversTables:  tables,
		OplogSeq:      m.OplogSeq,
		SizeBytes:     m.SizeBytes,
		Checksum:      m.Checksum,
		CreatedAt:     formatTime(m.CreatedAt),
	}
}

func validChecksumFormat(v string) bool {
	hexPart, ok := strings.CutPrefix(strings.ToLower(v), blobs.ChecksumPrefix)
	if !ok || len(hexPart) != 64 {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func deterministicSnapshotID(teamID, eventID uuid.UUID) string {
	raw := teamID.String() + ":" + eventID.String()
	sum := sha256.Sum256([]byte(raw))
	var id uuid.UUID
	copy(id[:], sum[:16])

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}
