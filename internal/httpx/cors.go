package httpx

import (
	"net/http"
	"strings"
)

type CORS struct {
	allowed map[string]struct{}
	All     bool
}

func NewCORS(origins []string, all bool) *CORS {
	c := &CORS{All: all, allowed: make(map[string]struct{}, len(origins))}
	for _, o := range origins {
		c.allowed[strings.ToLower(strings.TrimRight(o, "/"))] = struct{}{}
	}
	return c
}

func (c *CORS) Enabled() bool {
	return c.All || len(c.allowed) > 0
}

func (c *CORS) allows(origin string) bool {
	if origin == "" {
		return false
	}
	if c.All {
		return true
	}
	_, ok := c.allowed[strings.ToLower(strings.TrimRight(origin, "/"))]
	return ok
}

func (c *CORS) Middleware(next http.Handler) http.Handler {
	if !c.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if c.allows(origin) {
			setAllowed(w.Header(), origin, r)
		}
		w.Header().Add("Vary", "Origin")

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if c.allows(origin) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setAllowed(h http.Header, origin string, r *http.Request) {
	h.Set(
		"Access-Control-Expose-Headers",
		RequestIDHeader+", Content-Length, X-Snapshot-Schema-Version, X-Snapshot-Covers-Tables, X-Snapshot-Checksum",
	)

	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Origin", origin)

	if requested := r.Header.Get("Access-Control-Request-Method"); requested != "" {
		h.Set("Access-Control-Allow-Methods", requested)
	} else {
		h.Set("Access-Control-Allow-Methods", allowAnyMethods)
	}
	if requested := r.Header.Get("Access-Control-Request-Headers"); requested != "" {
		h.Set("Access-Control-Allow-Headers", requested)
	} else {
		h.Set(
			"Access-Control-Allow-Headers",
			"Authorization, Content-Type, "+ClientRequestIDHeader+", X-WF-Device-Id, X-Wf-Profile-Scope, X-Wf-Profile-Id",
		)
	}

	h.Set("Access-Control-Max-Age", corsMaxAge)
}
