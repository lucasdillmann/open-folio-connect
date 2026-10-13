package connect

import (
	"net/http"

	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
	"github.com/lucasdillmann/open-folio-connect/internal/store"
)

func (h *Handler) userMe(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.Authenticate(w, r)
	if !ok {
		return
	}
	user, err := h.store.UserByID(r.Context(), identity.UserID)
	if err != nil {
		h.internal(w, "load user", err)
		return
	}
	team, err := h.store.Team(r.Context())
	if err != nil {
		h.internal(w, "load team", err)
		return
	}
	membership, err := h.store.MembershipForUser(r.Context(), identity.UserID)
	if err != nil {
		h.internal(w, "load membership", err)
		return
	}

	email := user.Email
	teamID := team.ID.String()
	role := membership.Role
	httpx.WriteJSON(w, http.StatusOK, apiUser{
		ID:       user.ID.String(),
		Email:    &email,
		TeamID:   &teamID,
		TeamRole: &role,
		Team:     newAPITeam(team),
	})
}

func newAPITeam(t store.Team) *apiTeam {
	name := t.Name
	plan := PlanBasic
	status := SubscriptionActive
	cancel := false
	return &apiTeam{
		ID:                            t.ID.String(),
		Name:                          &name,
		Plan:                          &plan,
		SubscriptionStatus:            &status,
		SubscriptionCancelAtPeriodEnd: &cancel,
		CreatedAt:                     formatTimePtr(&t.CreatedAt),
	}
}

func (h *Handler) subscriptionPlans(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"plans": localPlans()})
}

func localPlans() []subscriptionPlan {
	tagline := "Self-hosted"
	return []subscriptionPlan{{
		ID:          PlanBasic,
		Name:        "Basic",
		Tagline:     &tagline,
		Description: "Self-hosted device sync. No broker connections or billing.",
		Pricing: planPricing{
			Monthly: map[string]any{"amount": 0, "currency": "USD"},
			Yearly:  map[string]any{"amount": 0, "currency": "USD"},
		},
		Limits: planLimits{
			HouseholdSize:          1,
			InstitutionConnections: "unlimited",
			Devices:                "unlimited",
		},
		Features:    []string{"Device sync", "Encrypted snapshots", "Device pairing"},
		IsAvailable: true,
	}}
}

func (h *Handler) brokerConnections(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.Authenticate(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"connections": []any{}})
}

func (h *Handler) brokerAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.Authenticate(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"accounts": []any{}})
}

func (h *Handler) brokerActivities(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.Authenticate(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"data":       []any{},
		"pagination": map[string]any{"total": 0, "count": 0, "offset": 0, "limit": 0},
	})
}

func (h *Handler) brokerHoldings(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.Authenticate(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"holdings":   []any{},
		"pagination": map[string]any{"total": 0, "count": 0, "offset": 0, "limit": 0},
	})
}
