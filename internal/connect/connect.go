package connect

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/lucasdillmann/open-folio-connect/internal/auth"
	"github.com/lucasdillmann/open-folio-connect/internal/blobs"
	"github.com/lucasdillmann/open-folio-connect/internal/config"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

type Handler struct {
	store  *store.Store
	issuer *auth.Issuer
	blobs  *blobs.Store
	cfg    config.Config
}

func NewHandler(
	s *store.Store,
	issuer *auth.Issuer,
	blobStore *blobs.Store,
	cfg config.Config,
) *Handler {
	return &Handler{store: s, issuer: issuer, blobs: blobStore, cfg: cfg}
}

func (h *Handler) cfgPairingTTL() time.Duration {
	return h.cfg.PairingTTL
}

func (h *Handler) cfgChallengeTTL() time.Duration {
	return h.cfg.ChallengeTTL
}

func newChallenge() (challengePair, error) {
	value, err := auth.NewOpaqueToken(24)
	if err != nil {
		return challengePair{}, err
	}
	nonce, err := auth.NewOpaqueToken(16)
	if err != nil {
		return challengePair{}, err
	}
	return challengePair{Value: value, Nonce: nonce}, nil
}

func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) (auth.UserIdentity, bool) {
	raw, err := httpx.BearerToken(r)
	if err != nil {
		httpx.Unauthorized(w, "UNAUTHORIZED", "a valid access token is required")
		return auth.UserIdentity{}, false
	}
	identity, err := h.issuer.Verify(raw)
	if err != nil {
		httpx.Unauthorized(w, "UNAUTHORIZED", "a valid access token is required")
		return auth.UserIdentity{}, false
	}
	return identity, true
}

func deviceID(r *http.Request) (uuid.UUID, error) {
	raw := r.Header.Get("x-wf-device-id")
	if raw == "" {
		return uuid.Nil, errors.New("x-wf-device-id is required")
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, errors.New("x-wf-device-id is not a valid uuid")
	}
	return id, nil
}

func (h *Handler) requireTrustedDevice(w http.ResponseWriter, r *http.Request,
	teamID uuid.UUID,
) (store.Device, bool) {
	id, err := deviceID(r)
	if err != nil {
		httpx.Unauthorized(w, "DEVICE_REQUIRED", err.Error())
		return store.Device{}, false
	}
	device, err := h.store.DeviceByID(r.Context(), teamID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.NotFound(w, "DEVICE_NOT_FOUND", "device is not registered")
		return store.Device{}, false
	}
	if err != nil {
		h.internal(w, "load device", err)
		return store.Device{}, false
	}
	if device.TrustState == store.TrustRevoked {
		httpx.Forbidden(w, "DEVICE_REVOKED", "this device has been revoked")
		return store.Device{}, false
	}
	_ = h.store.TouchDevice(r.Context(), teamID, id)
	return device, true
}

func (h *Handler) internal(w http.ResponseWriter, what string, _ error) {
	httpx.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", what+" failed")
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatTime(*t)
	return &s
}
