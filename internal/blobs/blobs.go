package blobs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Store struct {
	root string
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create blob dir: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

func (s *Store) Root() string {
	return s.root
}

const (
	SnapshotDir = "snapshots"
	BackupDir   = "backups"
)

func SnapshotRelPath(id string) string {
	return filepath.Join(SnapshotDir, id+".blob")
}

func BackupRelPath(id string) string {
	return filepath.Join(BackupDir, id+".blob")
}

func (s *Store) Write(dir, id string, r io.Reader, maxBytes int64) (string, int64, string, error) {
	dirPath := filepath.Join(s.root, dir)
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return "", 0, "", err
	}

	tmp, err := os.CreateTemp(dirPath, ".upload-*")
	if err != nil {
		return "", 0, "", err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	hasher := sha256.New()

	written, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(r, maxBytes+1))
	if copyErr != nil {
		return "", 0, "", copyErr
	}
	if written > maxBytes {
		return "", 0, "", ErrTooLarge
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, "", err
	}
	if err := tmp.Close(); err != nil {
		return "", 0, "", err
	}

	rel := filepath.Join(dir, id+".blob")
	final := filepath.Join(s.root, rel)
	if err := os.Rename(tmpName, final); err != nil {
		return "", 0, "", err
	}
	return rel, written, ChecksumPrefix + hex.EncodeToString(hasher.Sum(nil)), nil
}

func (s *Store) Open(rel string) (*os.File, int64, error) {
	full, err := s.resolve(rel)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(full)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, os.ErrNotExist
		}
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (s *Store) Remove(rel string) error {
	full, err := s.resolve(rel)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) resolve(rel string) (string, error) {
	if rel == "" || strings.ContainsRune(rel, 0) {
		return "", errors.New("invalid storage path")
	}
	full := filepath.Join(s.root, filepath.Clean("/"+rel))
	if !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", errors.New("invalid storage path")
	}
	return full, nil
}

func FormatChecksum(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	_, hexPart, _ := strings.Cut(lower, ":")
	if hexPart == "" {
		hexPart = lower
	}
	return ChecksumPrefix + hexPart
}
