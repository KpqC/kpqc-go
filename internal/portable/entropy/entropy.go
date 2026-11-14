//go:build !kpqc_kat

// Package entropy provides operating-system randomness to the portable cores.
package entropy

import "crypto/rand"

func Fill(output []byte) bool {
	_, err := rand.Read(output)
	return err == nil
}
