package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func Error(w http.ResponseWriter, status int, code, message string, details ...any) {
	e := &APIError{
		Kind:    code,
		Code:    code,
		Message: message,
		Status:  status,
	}
	if len(details) > 0 {
		e.Details = details[0]
	}
	WriteJSON(w, status, e)
}

func BadRequest(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusBadRequest, code, message)
}

func Unauthorized(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusUnauthorized, code, message)
}

func Forbidden(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusForbidden, code, message)
}

func NotFound(w http.ResponseWriter, code, message string) {
	Error(w, http.StatusNotFound, code, message)
}

func Conflict(w http.ResponseWriter, code, message string, details ...any) {
	Error(w, http.StatusConflict, code, message, details...)
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write json response", "error", err)
	}
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20))
	if err := dec.Decode(v); err != nil {
		BadRequest(w, "INVALID_REQUEST", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func RequestID(r *http.Request) string {
	candidate := strings.TrimSpace(r.Header.Get(ClientRequestIDHeader))
	if IsLogSafe(candidate) {
		return candidate
	}
	return "srv:" + uuid.NewString()
}

func IsLogSafe(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestID(r)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

func BearerToken(r *http.Request) (string, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return "", ErrUnauthorized
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrUnauthorized
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrUnauthorized
	}
	return token, nil
}

func DecodeJSONOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		BadRequest(w, "INVALID_REQUEST", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
