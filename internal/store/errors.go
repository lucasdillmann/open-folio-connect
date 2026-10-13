package store

import "errors"

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrKeyVersionMismatch = errors.New("key version mismatch")
)
