package fips202

import (
	"encoding/hex"
	"testing"
)

func decode(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStandardVectors(t *testing.T) {
	sha256 := SHA3256(nil)
	if string(sha256[:]) != string(decode(t, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")) {
		t.Fatal("SHA3-256 mismatch")
	}
	sha512 := SHA3512(nil)
	if string(sha512[:]) != string(decode(t, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")) {
		t.Fatal("SHA3-512 mismatch")
	}
	shake128 := make([]byte, 32)
	Shake128(shake128, nil)
	if string(shake128) != string(decode(t, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")) {
		t.Fatal("SHAKE128 mismatch")
	}
	shake256 := make([]byte, 64)
	Shake256(shake256, nil)
	if string(shake256) != string(decode(t, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")) {
		t.Fatal("SHAKE256 mismatch")
	}
}
