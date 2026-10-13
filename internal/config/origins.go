package config

import (
	"errors"
	"net/url"
	"strings"
)

func parseAllowedOrigins(raw string) (AllowedOrigins, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AllowedOrigins{}, nil
	}

	var out AllowedOrigins
	var hadEntries bool
	seen := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		hadEntries = true
		if strings.EqualFold(entry, allowAllToken) || entry == "*" {
			out.All = true
			out.Origins = nil
			return out, nil
		}
		for _, origin := range expandOrigin(entry) {
			if seen[origin] {
				continue
			}
			seen[origin] = true
			out.Origins = append(out.Origins, origin)
		}
	}

	if !out.All && hadEntries && len(out.Origins) == 0 {
		return AllowedOrigins{}, errors.New(
			"OFC_ALLOWED_ORIGINS was set but contained no usable origin")
	}
	return out, nil
}

func expandOrigin(entry string) []string {
	entry = strings.TrimSuffix(entry, "/")
	if strings.ContainsAny(entry, "/?#") && !strings.HasPrefix(entry, "http://") &&
		!strings.HasPrefix(entry, "https://") {
		return nil
	}

	candidates := []string{entry}
	if !strings.HasPrefix(entry, "http://") && !strings.HasPrefix(entry, "https://") {
		candidates = []string{"https://" + entry, "http://" + entry}
	}

	var valid []string
	for _, candidate := range candidates {
		u, err := url.Parse(candidate)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" {
			continue
		}
		valid = append(valid, strings.ToLower(u.Scheme+"://"+u.Host))
	}
	return valid
}
