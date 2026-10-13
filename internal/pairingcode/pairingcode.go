package pairingcode

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode"
)

func Normalize(code string) string {
	out := make([]rune, 0, len(code))
	for _, r := range code {
		u := unicode.ToUpper(r)
		if u < 128 && (unicode.IsDigit(u) || (u >= 'A' && u <= 'Z')) {
			out = append(out, u)
		}
	}
	return string(out)
}

func Hash(code string) string {
	sum := sha256.Sum256([]byte(Normalize(code)))
	return hex.EncodeToString(sum[:])
}

func ConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
