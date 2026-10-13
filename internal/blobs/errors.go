package blobs

import "errors"

var ErrTooLarge = errors.New("snapshot exceeds the maximum allowed size")
