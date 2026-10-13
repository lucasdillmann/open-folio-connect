package connect

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func newDeviceResponse(d store.Device) deviceResponse {
	return deviceResponse{
		ID:                d.ID.String(),
		UserID:            d.UserID.String(),
		DisplayName:       d.DisplayName,
		Platform:          d.Platform,
		DevicePublicKey:   d.DevicePublicKey,
		TrustState:        d.TrustState,
		TrustedKeyVersion: d.TrustedKeyVersion,
		OSVersion:         d.OSVersion,
		AppVersion:        d.AppVersion,
		LastSeenAt:        formatTimePtr(d.LastSeenAt),
		CreatedAt:         formatTime(d.CreatedAt),
	}
}

func (h *Handler) enrollDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req registerDeviceRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	nonce, err := uuid.Parse(strings.TrimSpace(req.DeviceNonce))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_NONCE", "device_nonce must be a uuid")
		return
	}
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	if platform == "" {
		httpx.BadRequest(w, "INVALID_PLATFORM", "platform is required")
		return
	}

	device, err := h.store.EnrollDevice(
		r.Context(),
		identity.TeamID,
		identity.UserID,
		store.RegisterDeviceInput{
			DeviceNonce: nonce,
			DisplayName: strings.TrimSpace(req.DisplayName),
			Platform:    platform,
			OSVersion:   req.OSVersion,
			AppVersion:  req.AppVersion,
		},
	)
	if err != nil {
		h.internal(w, "enroll device", err)
		return
	}

	keyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}

	switch {
	case keyVersion == 0:

		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mode":             "BOOTSTRAP",
			"device_id":        device.ID.String(),
			"e2ee_key_version": keyVersion,
		})
	case device.TrustState == store.TrustTrusted && intOrZero(device.TrustedKeyVersion) == keyVersion:
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mode":             "READY",
			"device_id":        device.ID.String(),
			"e2ee_key_version": keyVersion,
			"trust_state":      device.TrustState,
		})
	default:
		trusted, err := h.store.ListTrustedDevices(r.Context(), identity.TeamID)
		if err != nil {
			h.internal(w, "list trusted devices", err)
			return
		}
		summaries := make([]trustedDeviceSummary, 0, len(trusted))
		for _, d := range trusted {
			summaries = append(summaries, trustedDeviceSummary{
				ID: d.ID.String(), Name: d.DisplayName,
				Platform: d.Platform, LastSeenAt: formatTimePtr(d.LastSeenAt),
			})
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mode":                "PAIR",
			"device_id":           device.ID.String(),
			"e2ee_key_version":    keyVersion,
			"require_sas":         true,
			"pairing_ttl_seconds": int(h.cfgPairingTTL().Seconds()),
			"trusted_devices":     summaries,
		})
	}
}

func intOrZero(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId must be a uuid")
		return
	}
	device, err := h.store.DeviceByID(r.Context(), identity.TeamID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	if err != nil {
		h.internal(w, "get device", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newDeviceResponse(device))
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	devices, err := h.store.ListDevices(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "list devices", err)
		return
	}
	out := make([]deviceResponse, 0, len(devices))
	for _, d := range devices {
		out = append(out, newDeviceResponse(d))
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) updateDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId must be a uuid")
		return
	}
	var req updateDeviceRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.store.UpdateDevice(
		r.Context(),
		identity.TeamID,
		id,
		req.DisplayName,
		nil,
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.NotFound(w, "DEVICE_NOT_FOUND", "device not found")
			return
		}
		h.internal(w, "update device", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) deleteDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId must be a uuid")
		return
	}
	if err := h.store.DeleteDevice(r.Context(), identity.TeamID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.NotFound(w, "DEVICE_NOT_FOUND", "device not found")
			return
		}
		h.internal(w, "delete device", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId must be a uuid")
		return
	}
	if err := h.store.SetDeviceTrust(
		r.Context(),
		identity.TeamID,
		id,
		store.TrustRevoked,
		nil,
	); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.NotFound(w, "DEVICE_NOT_FOUND", "device not found")
			return
		}
		h.internal(w, "revoke device", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) initializeTeamKeys(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req initializeKeysRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	deviceIDRaw, err := uuid.Parse(strings.TrimSpace(req.DeviceID))
	if err != nil {
		if deviceIDRaw, err = deviceID(r); err != nil {
			httpx.BadRequest(w, "INVALID_DEVICE_ID", "device_id must be a uuid")
			return
		}
	}
	_, err = h.store.DeviceByID(r.Context(), identity.TeamID, deviceIDRaw)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.NotFound(w, "DEVICE_NOT_FOUND", "device not found")
			return
		}
		h.internal(w, "load device for key init", err)
		return
	}

	keyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}
	if keyVersion == 0 {
		challenge, chErr := newChallenge()
		if chErr != nil {
			h.internal(w, "generate challenge", chErr)
			return
		}
		createErr := h.store.CreateChallenge(r.Context(), identity.TeamID, deviceIDRaw,
			challenge.Value, challenge.Nonce, 1, h.cfgChallengeTTL())
		if createErr != nil {
			h.internal(w, "store challenge", createErr)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"mode":        "BOOTSTRAP",
			"challenge":   challenge.Value,
			"nonce":       challenge.Nonce,
			"key_version": 1,
		})
		return
	}

	trusted, err := h.store.ListTrustedDevices(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "list trusted devices", err)
		return
	}
	summaries := make([]trustedDeviceSummary, 0, len(trusted))
	for _, d := range trusted {
		summaries = append(summaries, trustedDeviceSummary{
			ID: d.ID.String(), Name: d.DisplayName,
			Platform: d.Platform, LastSeenAt: formatTimePtr(d.LastSeenAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"mode":                "PAIRING_REQUIRED",
		"e2ee_key_version":    keyVersion,
		"require_sas":         true,
		"pairing_ttl_seconds": int(h.cfgPairingTTL().Seconds()),
		"trusted_devices":     summaries,
	})
}

func (h *Handler) commitTeamKeys(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	var req commitKeysRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	deviceIDRaw, err := uuid.Parse(strings.TrimSpace(req.DeviceID))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "device_id must be a uuid")
		return
	}
	if req.ChallengeResponse == nil || *req.ChallengeResponse == "" {
		httpx.BadRequest(w, "MISSING_CHALLENGE_RESPONSE", "challenge_response is required")
		return
	}

	challenge, err := h.store.PendingChallenge(r.Context(), identity.TeamID, deviceIDRaw)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Conflict(w, "KEY_CHALLENGE_EXPIRED",
			"no pending key initialization challenge for this device; run keys/initialize again")
		return
	}
	if err != nil {
		h.internal(w, "load key challenge", err)
		return
	}

	if store.ChallengeResponse(challenge.Challenge, challenge.Nonce) != *req.ChallengeResponse {
		httpx.BadRequest(
			w,
			"INVALID_CHALLENGE_RESPONSE",
			"challenge_response does not match the issued challenge",
		)
		return
	}
	if req.KeyVersion != challenge.KeyVersion {
		httpx.BadRequest(
			w,
			"KEY_VERSION_MISMATCH",
			"key_version does not match the issued challenge",
		)
		return
	}

	if err := h.store.CommitTeamKeys(
		r.Context(),
		identity.TeamID,
		deviceIDRaw,
		challenge.ID,
		req.KeyVersion,
		req.DeviceKeyEnvelope,
		req.Signature,
		*req.ChallengeResponse,
	); err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.Conflict(w, "KEY_CHALLENGE_CONSUMED", "this challenge was already used")
			return
		}
		h.internal(w, "commit team keys", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"key_state": "ACTIVE",
	})
}

func (h *Handler) resetTeamSync(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}

	var req resetTeamSyncRequest
	if !httpx.DecodeJSONOptional(w, r, &req) {
		return
	}

	keyVersion, err := h.store.ResetTeamSync(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "reset team sync", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"keyVersion": keyVersion,
		"resetAt":    formatTime(time.Now()),
	})
}
