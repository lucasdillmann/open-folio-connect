package connect

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/pairingcode"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func (h *Handler) createPairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	issuer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pathID, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil || pathID != issuer.ID {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId does not match x-wf-device-id")
		return
	}

	var req createPairingRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	codeHash := strings.ToLower(strings.TrimSpace(req.CodeHash))
	if len(codeHash) != 64 {
		httpx.BadRequest(w, "INVALID_CODE_HASH", "code_hash must be a 64 character hex sha256")
		return
	}
	ephemeral := strings.TrimSpace(req.EphemeralPublicKey)
	if ephemeral == "" {
		httpx.BadRequest(w, "INVALID_EPHEMERAL_KEY", "ephemeral_public_key is required")
		return
	}

	keyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}
	if keyVersion == 0 {
		httpx.Conflict(
			w,
			"KEYS_NOT_INITIALIZED",
			"the team has not initialized encryption keys yet",
		)
		return
	}

	pairing, err := h.store.CreatePairing(r.Context(), store.CreatePairingInput{
		TeamID:             identity.TeamID,
		CodeHash:           codeHash,
		IssuerDeviceID:     issuer.ID,
		IssuerEphemeralPub: ephemeral,
		KeyVersion:         keyVersion,
		RequireSAS:         true,
		ExpiresAt:          time.Now().Add(h.cfgPairingTTL()),
	})
	if errors.Is(err, store.ErrConflict) {
		httpx.Conflict(w, "PAIRING_CODE_IN_USE", "that pairing code is already in use")
		return
	}
	if err != nil {
		h.internal(w, "create pairing", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"pairingId":  pairing.ID.String(),
		"expiresAt":  formatTime(pairing.ExpiresAt),
		"keyVersion": pairing.KeyVersion,
		"requireSas": pairing.RequireSAS,
	})
}

func (h *Handler) getPairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	issuer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, issuer.ID)
	if !ok {
		return
	}

	body := map[string]any{
		"pairingId": pairing.ID.String(),
		"status":    pairing.Status,
		"expiresAt": formatTime(pairing.ExpiresAt),
	}
	if pairing.ClaimerDeviceID != nil {
		body["claimerDeviceId"] = pairing.ClaimerDeviceID.String()
		body["claimerEphemeralPub"] = pairing.ClaimerEphemeralPub
	} else {
		body["claimerDeviceId"] = nil
		body["claimerEphemeralPub"] = nil
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func (h *Handler) approvePairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	issuer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, issuer.ID)
	if !ok {
		return
	}

	updated, err := h.store.SetPairingStatus(r.Context(), pairing.ID,
		[]string{store.PairingOpen, store.PairingClaimed}, store.PairingApproved)
	switch {
	case err == nil:
		_ = updated
	case errors.Is(err, store.ErrNotFound):
		if pairing.Status == store.PairingApproved {
			httpx.Conflict(w, "PAIRING_ALREADY_APPROVED", "this pairing is already approved")
			return
		}
		httpx.Conflict(w, "PAIRING_INVALID_STATE",
			"this pairing is not in a state that can be approved")
		return
	default:
		h.internal(w, "approve pairing", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) completePairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	issuer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, issuer.ID)
	if !ok {
		return
	}

	var req completePairingRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.EncryptedKeyBundle) == "" {
		httpx.BadRequest(w, "MISSING_KEY_BUNDLE", "encrypted_key_bundle is required")
		return
	}
	if pairing.ClaimerDeviceID == nil {
		httpx.Conflict(w, "PAIRING_NOT_CLAIMED", "no device has claimed this pairing yet")
		return
	}

	if _, err := h.store.AddPairingMessage(r.Context(), pairing.ID,
		store.RootKeyTransferPayloadType, req.EncryptedKeyBundle); err != nil {
		h.internal(w, "store pairing message", err)
		return
	}

	if _, err := h.store.SetPairingStatus(r.Context(), pairing.ID,
		[]string{store.PairingApproved}, store.PairingCompleted); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.internal(w, "complete pairing", err)
			return
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) cancelPairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	issuer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, issuer.ID)
	if !ok {
		return
	}
	if _, err := h.store.SetPairingStatus(r.Context(), pairing.ID,
		[]string{store.PairingOpen, store.PairingClaimed, store.PairingApproved},
		store.PairingCancelled); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.internal(w, "cancel pairing", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (h *Handler) claimPairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	claimer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}

	var req claimPairingRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	ephemeral := strings.TrimSpace(req.EphemeralPublicKey)
	if ephemeral == "" {
		httpx.BadRequest(w, "INVALID_EPHEMERAL_KEY", "ephemeral_public_key is required")
		return
	}

	pairing, err := h.store.PairingByCodeHash(r.Context(), pairingcode.Hash(req.Code))
	if errors.Is(err, store.ErrNotFound) {
		httpx.BadRequest(w, "PAIRING_NOT_FOUND", "no pairing matches that code")
		return
	}
	if err != nil {
		h.internal(w, "resolve pairing code", err)
		return
	}
	if pairing.TeamID != identity.TeamID {
		httpx.BadRequest(w, "PAIRING_NOT_FOUND", "no pairing matches that code")
		return
	}
	if pairing.Status != store.PairingOpen || time.Now().After(pairing.ExpiresAt) {
		httpx.Conflict(w, "PAIRING_NOT_AVAILABLE", "this pairing is no longer available")
		return
	}

	claimed, err := h.store.ClaimPairing(r.Context(), pairing.ID, claimer.ID, ephemeral)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Conflict(w, "PAIRING_NOT_AVAILABLE", "this pairing is no longer available")
		return
	}
	if err != nil {
		h.internal(w, "claim pairing", err)
		return
	}

	keyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"sessionId":          claimed.ID.String(),
		"issuerEphemeralPub": claimed.IssuerEphemeralPub,
		"e2eeKeyVersion":     keyVersion,
		"requireSas":         claimed.RequireSAS,
		"expiresAt":          formatTime(claimed.ExpiresAt),
	})
}

func (h *Handler) pairingMessages(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	claimer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, claimer.ID)
	if !ok {
		return
	}
	if pairing.ClaimerDeviceID == nil || *pairing.ClaimerDeviceID != claimer.ID {
		httpx.Forbidden(w, "PAIRING_NOT_CLAIMED_BY_THIS_DEVICE",
			"this pairing was claimed by a different device")
		return
	}

	messages, err := h.store.PairingMessages(r.Context(), pairing.ID)
	if err != nil {
		h.internal(w, "list pairing messages", err)
		return
	}
	out := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		out = append(out, map[string]any{
			"id":          m.ID.String(),
			"payloadType": m.PayloadType,
			"payload":     m.Payload,
			"createdAt":   formatTime(m.CreatedAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"sessionStatus": pairing.Status,
		"messages":      out,
	})
}

func (h *Handler) confirmPairing(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	claimer, ok := h.requireTrustedDevice(w, r, identity.TeamID)
	if !ok {
		return
	}
	pairing, ok := h.resolvePairing(w, r, identity.TeamID, claimer.ID)
	if !ok {
		return
	}

	var req confirmPairingRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if pairing.ClaimerDeviceID == nil || *pairing.ClaimerDeviceID != claimer.ID {
		httpx.Forbidden(w, "PAIRING_NOT_CLAIMED_BY_THIS_DEVICE",
			"this pairing was claimed by a different device")
		return
	}
	if pairing.Status == store.PairingCompleted && isTrusted(h, r, identity.TeamID, claimer.ID) {
		httpx.Conflict(w, "PAIRING_ALREADY_CONFIRMED", "this pairing is already confirmed")
		return
	}
	if pairing.Status != store.PairingCompleted {
		httpx.Conflict(w, "PAIRING_INVALID_STATE",
			"the issuer has not finished sending the key bundle yet")
		return
	}

	keyVersion, err := h.store.CurrentKeyVersion(r.Context(), identity.TeamID)
	if err != nil {
		h.internal(w, "read key version", err)
		return
	}
	if err := h.store.SetDeviceTrust(r.Context(), identity.TeamID, claimer.ID,
		store.TrustTrusted, &keyVersion); err != nil {
		h.internal(w, "trust claimer device", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"keyVersion": keyVersion,
	})
}

func isTrusted(h *Handler, r *http.Request, teamID, deviceID uuid.UUID) bool {
	device, err := h.store.DeviceByID(r.Context(), teamID, deviceID)
	return err == nil && device.TrustState == store.TrustTrusted
}

func (h *Handler) resolvePairing(w http.ResponseWriter, r *http.Request,
	teamID, actor uuid.UUID,
) (store.Pairing, bool) {
	pathID, err := uuid.Parse(r.PathValue("deviceId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_DEVICE_ID", "deviceId must be a uuid")
		return store.Pairing{}, false
	}
	pairingID, err := uuid.Parse(r.PathValue("pairingId"))
	if err != nil {
		httpx.BadRequest(w, "INVALID_PAIRING_ID", "pairingId must be a uuid")
		return store.Pairing{}, false
	}
	pairing, err := h.store.PairingByID(r.Context(), teamID, pairingID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "PAIRING_NOT_FOUND", "pairing not found")
		return store.Pairing{}, false
	}
	if err != nil {
		h.internal(w, "load pairing", err)
		return store.Pairing{}, false
	}
	if pathID != actor {
		httpx.Forbidden(w, "PAIRING_DEVICE_MISMATCH",
			"deviceId does not match x-wf-device-id")
		return store.Pairing{}, false
	}
	if pairing.IssuerDeviceID != actor &&
		(pairing.ClaimerDeviceID == nil || *pairing.ClaimerDeviceID != actor) {
		httpx.Forbidden(w, "PAIRING_FORBIDDEN", "this device is not part of the pairing")
		return store.Pairing{}, false
	}
	return pairing, true
}
