package connect

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func (h *Handler) pushEvents(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	device, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}

	var req pushRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if len(req.Events) == 0 {
		cursor, err := h.store.Cursor(r.Context(), identity.TeamID)
		if err != nil {
			h.internal(w, "read cursor", err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, pushResponse{
			Accepted: []pushResultItem{}, Duplicate: []pushResultItem{}, ServerCursor: cursor,
		})
		return
	}
	if len(req.Events) > h.cfg.PushBatchMax {
		httpx.BadRequest(w, "BATCH_TOO_LARGE", "too many events in one push batch")
		return
	}

	currentKeyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}

	events := make([]store.PushEventInput, 0, len(req.Events))
	for _, e := range req.Events {
		if e.DeviceID == "" {
			e.DeviceID = device.ID.String()
		}
		deviceUUID, parseErr := uuid.Parse(e.DeviceID)
		if parseErr != nil {
			httpx.BadRequest(w, "INVALID_DEVICE_ID", "device_id must be a uuid")
			return
		}

		if currentKeyVersion > 0 && e.PayloadKeyVersion != currentKeyVersion {
			httpx.Error(w, http.StatusConflict, "KEY_VERSION_MISMATCH",
				"event payload key version does not match the team key version",
				map[string]any{"expected": currentKeyVersion, "received": e.PayloadKeyVersion})
			return
		}
		if !validEventType(e.Type) {
			httpx.BadRequest(w, "INVALID_EVENT_TYPE",
				"type must be {entity}.{create|update|delete}.vN")
			return
		}
		if strings.TrimSpace(e.EventID) == "" {
			httpx.BadRequest(w, "INVALID_EVENT_ID", "event_id is required")
			return
		}
		events = append(events, store.PushEventInput{
			EventID:           e.EventID,
			DeviceID:          deviceUUID,
			EventType:         e.Type,
			Entity:            e.Entity,
			EntityID:          e.EntityID,
			ClientTimestamp:   e.ClientTimestamp,
			Payload:           e.Payload,
			PayloadKeyVersion: e.PayloadKeyVersion,
		})
	}

	outcome, err := h.store.AppendEvents(r.Context(), identity.TeamID, identity.UserID, events)
	if err != nil {
		h.internal(w, "append events", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pushResponse{
		Accepted:     toResultItems(outcome.Accepted),
		Duplicate:    toResultItems(outcome.Duplicate),
		ServerCursor: outcome.ServerCursor,
	})
}

func validEventType(t string) bool {
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] == "" {
		return false
	}
	switch parts[1] {
	case "create", "update", "delete":
	default:
		return false
	}
	return strings.HasPrefix(parts[2], "v")
}

func toResultItems(in []store.PushResultItem) []pushResultItem {
	out := make([]pushResultItem, 0, len(in))
	for _, i := range in {
		out = append(out, pushResultItem{EventID: i.EventID, Seq: i.Seq})
	}
	return out
}

func (h *Handler) pullEvents(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}

	since := int64(0)
	if raw := r.URL.Query().Get("since"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			httpx.BadRequest(w, "INVALID_SINCE", "since must be a non-negative integer")
			return
		}
		since = v
	}
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			httpx.BadRequest(w, "INVALID_LIMIT", "limit must be a positive integer")
			return
		}
		limit = v
	}

	events, next, hasMore, err := h.store.PullEvents(r.Context(), identity.TeamID, since, limit)
	if err != nil {
		h.internal(w, "pull events", err)
		return
	}

	out := make([]syncEvent, 0, len(events))
	for _, e := range events {
		out = append(out, syncEvent{
			EventID:  e.EventID,
			DeviceID: e.DeviceID.String(),
			Type:     e.EventType,
			Entity:   e.Entity,
			EntityID: e.EntityID,

			ClientTimestamp:   e.ClientTimestamp,
			Payload:           e.Payload,
			PayloadKeyVersion: e.PayloadKeyVersion,
			Seq:               e.Seq,
			UserID:            e.UserID.String(),
			TeamID:            e.TeamID.String(),
			ServerTimestamp:   formatTime(e.ServerTimestamp),
		})
	}

	httpx.WriteJSON(w, http.StatusOK, pullResponse{
		From: since, To: next, NextCursor: next, HasMore: hasMore, Events: out,
	})
}

func (h *Handler) eventsCursor(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}
	cursor, err := h.store.Cursor(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read cursor", err)
		return
	}
	resp := cursorResponse{Cursor: cursor}
	if ref, err := h.store.LatestSnapshotRef(r.Context(), identity.TeamID); err == nil {
		resp.LatestSnapshot = newSnapshotRef(ref)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) reconcileReadyState(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	if _, ok := h.requireTrustedDevice(w, r, identity.TeamID); !ok {
		return
	}

	cursor, err := h.store.Cursor(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read cursor", err)
		return
	}
	body := map[string]any{"action": "PULL_TAIL", "cursor": cursor}
	if ref, err := h.store.LatestSnapshotRef(r.Context(), identity.TeamID); err == nil {
		snap := newSnapshotRef(ref)
		body["latestSnapshot"] = snap
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func newSnapshotRef(ref store.SnapshotRef) *latestSnapshotRef {
	return &latestSnapshotRef{
		SnapshotID:    ref.SnapshotID,
		SchemaVersion: ref.SchemaVersion,
		OplogSeq:      ref.OplogSeq,
	}
}
