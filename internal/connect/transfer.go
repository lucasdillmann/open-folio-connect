package connect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lucasdillmann/open-folio-connect/internal/blobs"
	"github.com/lucasdillmann/open-folio-connect/internal/httpx"
)

type transferClaims struct {
	Dir      string `json:"d,omitempty"`
	Path     string `json:"p,omitempty"`
	ID       string `json:"id,omitempty"`
	Mode     string `json:"m"`
	Checksum string `json:"c,omitempty"`
	Size     int64  `json:"s,omitempty"`
	Exp      int64  `json:"x"`
}

type uploadTicket struct {
	TeamID            string `json:"t"`
	EventID           string `json:"e"`
	Path              string `json:"p"`
	Checksum          string `json:"c"`
	Size              int64  `json:"s"`
	SnapshotSeq       int64  `json:"q"`
	SchemaVersion     int    `json:"v"`
	PayloadKeyVersion int    `json:"k"`
	Exp               int64  `json:"x"`
}

type transferDescriptor struct {
	Headers   map[string]string `json:"headers"`
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	ExpiresAt string            `json:"expires_at"`
}

func (h *Handler) signPayload(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, h.cfg.JWTSecret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (h *Handler) verifyPayload(token string, v any) error {
	encoded, signature, ok := strings.Cut(strings.TrimSpace(token), ".")
	if !ok {
		return errors.New("malformed transfer token")
	}
	got, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("malformed transfer signature")
	}
	mac := hmac.New(sha256.New, h.cfg.JWTSecret)
	_, _ = mac.Write([]byte(encoded))
	if !hmac.Equal(mac.Sum(nil), got) {
		return errors.New("invalid transfer signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("malformed transfer payload")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("malformed transfer payload")
	}
	return nil
}

func transferExpired(exp int64) bool {
	return exp <= time.Now().Unix()
}

func (h *Handler) transferURL(token string) string {
	return strings.TrimRight(h.cfg.BaseURL, "/") + "/api/v1/sync/transfers/" + token
}

func (h *Handler) uploadTransferDescriptor(claims transferClaims) (*transferDescriptor, error) {
	token, err := h.signPayload(claims)
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(claims.Checksum, blobs.ChecksumPrefix))
	if err != nil {
		return nil, err
	}
	return &transferDescriptor{
		URL:    h.transferURL(token),
		Method: http.MethodPut,
		Headers: map[string]string{
			"content-length":        strconv.FormatInt(claims.Size, 10),
			"x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(digest),
		},
		ExpiresAt: time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339),
	}, nil
}

func (h *Handler) downloadTransferDescriptor(claims transferClaims) (*transferDescriptor, error) {
	token, err := h.signPayload(claims)
	if err != nil {
		return nil, err
	}
	return &transferDescriptor{
		URL:       h.transferURL(token),
		Method:    http.MethodGet,
		Headers:   map[string]string{},
		ExpiresAt: time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339),
	}, nil
}

func (h *Handler) uploadTransfer(w http.ResponseWriter, r *http.Request) {
	var claims transferClaims
	if err := h.verifyPayload(r.PathValue("token"), &claims); err != nil {
		httpx.Forbidden(w, "TRANSFER_INVALID", "transfer link is invalid")
		return
	}
	if transferExpired(claims.Exp) {
		httpx.Forbidden(w, "TRANSFER_EXPIRED", "transfer link has expired")
		return
	}
	if claims.Mode != "w" || claims.ID == "" {
		httpx.Forbidden(w, "TRANSFER_INVALID", "transfer link is not for an upload")
		return
	}

	dir := claims.Dir
	if dir == "" {
		dir = blobs.SnapshotDir
	}
	relPath, size, checksum, err := h.blobs.Write(dir, claims.ID, r.Body, h.maxTransferBytes(dir))
	if errors.Is(err, blobs.ErrTooLarge) {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "TRANSFER_TOO_LARGE",
			"transfer exceeds the configured maximum size")
		return
	}
	if err != nil {
		h.internal(w, "write transfer", err)
		return
	}
	if size != claims.Size || checksum != claims.Checksum ||
		(claims.Path != "" && relPath != claims.Path) {
		_ = h.blobs.Remove(relPath)
		httpx.Conflict(w, "TRANSFER_MISMATCH", "uploaded bytes do not match the prepared transfer")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) maxTransferBytes(dir string) int64 {
	if dir == blobs.BackupDir {
		return h.cfg.MaxBackupBytes
	}
	return h.cfg.MaxSnapshotBytes
}

func (h *Handler) downloadTransfer(w http.ResponseWriter, r *http.Request) {
	var claims transferClaims
	if err := h.verifyPayload(r.PathValue("token"), &claims); err != nil {
		httpx.Forbidden(w, "TRANSFER_INVALID", "transfer link is invalid")
		return
	}
	if transferExpired(claims.Exp) {
		httpx.Forbidden(w, "TRANSFER_EXPIRED", "transfer link has expired")
		return
	}
	if claims.Mode != "r" || claims.Path == "" {
		httpx.Forbidden(w, "TRANSFER_INVALID", "transfer link is not for a download")
		return
	}

	file, size, err := h.blobs.Open(claims.Path)
	if errors.Is(err, os.ErrNotExist) {
		httpx.NotFound(w, "TRANSFER_NOT_FOUND", "transfer payload is no longer stored")
		return
	}
	if err != nil {
		h.internal(w, "open transfer", err)
		return
	}
	defer func() { _ = file.Close() }()

	if claims.Size > 0 && size != claims.Size {
		h.internal(w, "transfer size", errors.New("stored transfer size changed"))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, file); err != nil {
		slog.Error("stream transfer", "error", err)
	}
}
