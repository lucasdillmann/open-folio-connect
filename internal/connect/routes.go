package connect

import "net/http"

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/user/me", h.userMe)
	mux.HandleFunc("GET /api/v1/subscription/plans", h.subscriptionPlans)
	mux.HandleFunc("GET /api/v1/subscription/plans/public", h.subscriptionPlans)

	mux.HandleFunc("GET /api/v1/sync/brokerage/connections", h.brokerConnections)
	mux.HandleFunc("GET /api/v1/sync/brokerage/accounts", h.brokerAccounts)
	mux.HandleFunc("GET /api/v1/sync/brokerage/accounts/{accountId}/activities", h.brokerActivities)
	mux.HandleFunc("GET /api/v1/sync/brokerage/accounts/{accountId}/holdings", h.brokerHoldings)

	mux.HandleFunc("POST /api/v1/sync/team/devices", h.enrollDevice)
	mux.HandleFunc("GET /api/v1/sync/team/devices", h.listDevices)
	mux.HandleFunc("GET /api/v1/sync/team/devices/{deviceId}", h.getDevice)
	mux.HandleFunc("PATCH /api/v1/sync/team/devices/{deviceId}", h.updateDevice)
	mux.HandleFunc("DELETE /api/v1/sync/team/devices/{deviceId}", h.deleteDevice)
	mux.HandleFunc("POST /api/v1/sync/team/devices/{deviceId}/revoke", h.revokeDevice)

	mux.HandleFunc("POST /api/v1/sync/team/keys/initialize", h.initializeTeamKeys)
	mux.HandleFunc("POST /api/v1/sync/team/keys/initialize/commit", h.commitTeamKeys)
	mux.HandleFunc("POST /api/v1/sync/team/keys/reset", h.resetTeamSync)

	mux.HandleFunc("POST /api/v1/sync/events/push", h.pushEvents)
	mux.HandleFunc("GET /api/v1/sync/events/pull", h.pullEvents)
	mux.HandleFunc("GET /api/v1/sync/events/cursor", h.eventsCursor)
	mux.HandleFunc("GET /api/v1/sync/events/reconcile-ready-state", h.reconcileReadyState)

	mux.HandleFunc("POST /api/v1/sync/snapshots/upload", h.uploadSnapshot)
	mux.HandleFunc("GET /api/v1/sync/snapshots/latest", h.latestSnapshot)
	mux.HandleFunc("GET /api/v1/sync/snapshots/{snapshotId}", h.downloadSnapshot)

	mux.HandleFunc("POST /api/v1/sync/team/devices/{deviceId}/pairings", h.createPairing)
	mux.HandleFunc("GET /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}", h.getPairing)
	mux.HandleFunc(
		"POST /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}/approve",
		h.approvePairing,
	)
	mux.HandleFunc(
		"POST /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}/complete",
		h.completePairing,
	)
	mux.HandleFunc(
		"POST /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}/cancel",
		h.cancelPairing,
	)

	mux.HandleFunc("POST /api/v1/sync/team/devices/{deviceId}/pairings/claim", h.claimPairing)
	mux.HandleFunc(
		"GET /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}/messages",
		h.pairingMessages,
	)
	mux.HandleFunc(
		"POST /api/v1/sync/team/devices/{deviceId}/pairings/{pairingId}/confirm",
		h.confirmPairing,
	)
}
