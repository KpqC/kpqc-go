//go:build kpqc_kat

package entropy

import (
	"crypto/rand"
	"sync"
)

var testState struct {
	sync.Mutex
	active bool
	bytes  []byte
	offset int
}

func Fill(output []byte) bool {
	testState.Lock()
	defer testState.Unlock()
	if testState.active {
		if len(output) > len(testState.bytes)-testState.offset {
			return false
		}
		copy(output, testState.bytes[testState.offset:])
		testState.offset += len(output)
		return true
	}
	_, err := rand.Read(output)
	return err == nil
}

func SetTestEntropy(input []byte) bool {
	testState.Lock()
	defer testState.Unlock()
	clearLocked()
	testState.bytes = append([]byte(nil), input...)
	testState.active = true
	return true
}

func ClearTestEntropy() int {
	testState.Lock()
	defer testState.Unlock()
	remaining := len(testState.bytes) - testState.offset
	clearLocked()
	return remaining
}

func clearLocked() {
	for i := range testState.bytes {
		testState.bytes[i] = 0
	}
	testState.bytes = nil
	testState.offset = 0
	testState.active = false
}
