package connect

import (
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/blobs"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func (h *Handler) uploadSnapshot(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	device, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}

	headers := r.Header
	eventIDRaw := strings.TrimSpace(headers.Get("x-snapshot-event-id"))
	eventID, err := uuid.Parse(eventIDRaw)
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_EVENT_ID", "x-snapshot-event-id must be a uuid")
		return
	}
	schemaVersion, err := requiredIntHeader(r, "x-snapshot-schema-version")
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_SCHEMA_VERSION", err.Error())
		return
	}
	payloadKeyVersion, err := requiredIntHeader(r, "x-snapshot-payload-key-version")
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_KEY_VERSION", err.Error())
		return
	}
	declaredSize, err := requiredInt64Header(r, "x-snapshot-size-bytes")
	if err != nil {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_SIZE", err.Error())
		return
	}
	declaredChecksum := blobs.FormatChecksum(headers.Get("x-snapshot-checksum"))
	if !validChecksumFormat(declaredChecksum) {
		httpx.BadRequest(w, "INVALID_SNAPSHOT_CHECKSUM",
			"x-snapshot-checksum must be sha256:<64 hex chars>")
		return
	}
	coversTables := splitTables(headers.Get("x-snapshot-covers-tables"))
	metadataPayload := headers.Get("x-snapshot-metadata-payload")

	baseSeq := int64(0)
	if raw := strings.TrimSpace(headers.Get("x-snapshot-base-seq")); raw != "" {
		v, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || v < 0 {
			httpx.BadRequest(
				w,
				"INVALID_SNAPSHOT_BASE_SEQ",
				"x-snapshot-base-seq must be a non-negative integer",
			)
			return
		}
		baseSeq = v
	}

	if declaredSize > h.cfg.MaxSnapshotBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "SNAPSHOT_TOO_LARGE",
			"snapshot exceeds the configured maximum size")
		return
	}

	snapshotID := deterministicSnapshotID(identity.TeamID, eventID)
	relPath, size, checksum, err := h.blobs.Write(snapshotID, r.Body, h.cfg.MaxSnapshotBytes)
	if errors.Is(err, blobs.ErrTooLarge) {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "SNAPSHOT_TOO_LARGE",
			"snapshot exceeds the configured maximum size")
		return
	}
	if err != nil {
		h.internal(w, "write snapshot", err)
		return
	}
	if size != declaredSize {
		_ = h.blobs.Remove(relPath)
		httpx.BadRequest(w, "SNAPSHOT_SIZE_MISMATCH",
			"uploaded body length does not match x-snapshot-size-bytes")
		return
	}
	if checksum != blobs.FormatChecksum(declaredChecksum) {
		_ = h.blobs.Remove(relPath)
		httpx.BadRequest(w, "SNAPSHOT_CHECKSUM_MISMATCH",
			"uploaded bytes do not match x-snapshot-checksum")
		return
	}

	meta, err := h.store.InsertSnapshot(r.Context(), identity.TeamID, store.InsertSnapshotInput{
		DeviceID:          device.ID,
		EventID:           eventID,
		SchemaVersion:     schemaVersion,
		CoversTables:      coversTables,
		SizeBytes:         size,
		Checksum:          checksum,
		StoragePath:       relPath,
		PayloadKeyVersion: payloadKeyVersion,
		OplogSeq:          baseSeq,
	})
	if err != nil {
		h.internal(w, "record snapshot", err)
		return
	}

	_ = metadataPayload

	slog.Info("snapshot uploaded",
		"snapshotId", meta.ID.String(), "teamId", identity.TeamID.String(),
		"sizeBytes", size, "oplogSeq", meta.OplogSeq, "requestId", httpx.RequestID(r))

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"snapshotId": meta.ID.String(),
		"r2Key":      relPath,
		"oplogSeq":   meta.OplogSeq,
		"createdAt":  formatTime(meta.CreatedAt),
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

func (h *Handler) downloadSnapshot(w http.ResponseWriter, r *http.Request) {
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

	file, size, err := h.blobs.Open(meta.StoragePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpx.NotFound(w, "SNAPSHOT_NOT_FOUND", "snapshot payload is no longer stored")
			return
		}
		h.internal(w, "open snapshot payload", err)
		return
	}
	defer func() { _ = file.Close() }()

	tables := meta.CoversTables
	if tables == nil {
		tables = []string{}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("x-snapshot-schema-version", strconv.Itoa(meta.SchemaVersion))
	w.Header().Set("x-snapshot-covers-tables", strings.Join(tables, ","))
	w.Header().Set("x-snapshot-checksum", meta.Checksum)
	w.WriteHeader(http.StatusOK)

	if _, err := io.Copy(w, file); err != nil {
		slog.Error("stream snapshot", "error", err, "snapshotId", meta.ID.String())
	}
}

func requiredIntHeader(r *http.Request, name string) (int, error) {
	raw := strings.TrimSpace(r.Header.Get(name))
	if raw == "" {
		return 0, errors.New("missing header " + name)
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("invalid header " + name)
	}
	return v, nil
}

func requiredInt64Header(r *http.Request, name string) (int64, error) {
	raw := strings.TrimSpace(r.Header.Get(name))
	if raw == "" {
		return 0, errors.New("missing header " + name)
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errors.New("invalid header " + name)
	}
	return v, nil
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

func splitTables(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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
