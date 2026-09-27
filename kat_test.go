//go:build kpqc_kat

package kpqc_test

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KpqC/kpqc-go"
	"github.com/KpqC/kpqc-go/internal/native/aimer128f"
	"github.com/KpqC/kpqc-go/internal/native/aimer128s"
	"github.com/KpqC/kpqc-go/internal/native/aimer192f"
	"github.com/KpqC/kpqc-go/internal/native/aimer192s"
	"github.com/KpqC/kpqc-go/internal/native/aimer256f"
	"github.com/KpqC/kpqc-go/internal/native/aimer256s"
	"github.com/KpqC/kpqc-go/internal/native/haetae2"
	"github.com/KpqC/kpqc-go/internal/native/haetae3"
	"github.com/KpqC/kpqc-go/internal/native/haetae5"
	"github.com/KpqC/kpqc-go/internal/native/ntruplus1152"
	"github.com/KpqC/kpqc-go/internal/native/ntruplus768"
	"github.com/KpqC/kpqc-go/internal/native/ntruplus864"
	"github.com/KpqC/kpqc-go/internal/native/smaugt128"
	"github.com/KpqC/kpqc-go/internal/native/smaugt192"
	"github.com/KpqC/kpqc-go/internal/native/smaugt256"
	"github.com/KpqC/kpqc-go/internal/native/timer"
)

type entropyControl struct {
	set   func([]byte) bool
	clear func() int
}

func TestKnownAnswerVectors(t *testing.T) {
	vectorRoot := os.Getenv("KPQC_TEST_VECTORS")
	if vectorRoot == "" {
		vectorRoot = filepath.Join("..", "kpqc-test-vectors")
	}
	if info, err := os.Stat(vectorRoot); err != nil || !info.IsDir() {
		t.Skip("clone kpqc-test-vectors beside kpqc-go or set KPQC_TEST_VECTORS")
	}

	signatures := []struct {
		algorithm kpqc.SignatureAlgorithm
		path      string
		haetae    bool
		entropy   entropyControl
		seedBytes int
	}{
		{kpqc.AIMer128f(), "aimer/128f", false, entropyControl{aimer128f.SetTestEntropy, aimer128f.ClearTestEntropy}, 16},
		{kpqc.AIMer128s(), "aimer/128s", false, entropyControl{aimer128s.SetTestEntropy, aimer128s.ClearTestEntropy}, 16},
		{kpqc.AIMer192f(), "aimer/192f", false, entropyControl{aimer192f.SetTestEntropy, aimer192f.ClearTestEntropy}, 24},
		{kpqc.AIMer192s(), "aimer/192s", false, entropyControl{aimer192s.SetTestEntropy, aimer192s.ClearTestEntropy}, 24},
		{kpqc.AIMer256f(), "aimer/256f", false, entropyControl{aimer256f.SetTestEntropy, aimer256f.ClearTestEntropy}, 32},
		{kpqc.AIMer256s(), "aimer/256s", false, entropyControl{aimer256s.SetTestEntropy, aimer256s.ClearTestEntropy}, 32},
		{kpqc.HAETAE2(), "haetae/mode2", true, entropyControl{haetae2.SetTestEntropy, haetae2.ClearTestEntropy}, 32},
		{kpqc.HAETAE3(), "haetae/mode3", true, entropyControl{haetae3.SetTestEntropy, haetae3.ClearTestEntropy}, 32},
		{kpqc.HAETAE5(), "haetae/mode5", true, entropyControl{haetae5.SetTestEntropy, haetae5.ClearTestEntropy}, 32},
	}
	kems := []struct {
		algorithm kpqc.KEMAlgorithm
		path      string
		entropy   entropyControl
		keyCalls  int
		encBytes  int
	}{
		{kpqc.NTRUPlus768(), "ntruplus/768", entropyControl{ntruplus768.SetTestEntropy, ntruplus768.ClearTestEntropy}, 0, 96},
		{kpqc.NTRUPlus864(), "ntruplus/864", entropyControl{ntruplus864.SetTestEntropy, ntruplus864.ClearTestEntropy}, 0, 108},
		{kpqc.NTRUPlus1152(), "ntruplus/1152", entropyControl{ntruplus1152.SetTestEntropy, ntruplus1152.ClearTestEntropy}, 0, 144},
		{kpqc.SMAUGT128(), "smaugt/mode1", entropyControl{smaugt128.SetTestEntropy, smaugt128.ClearTestEntropy}, 2, 32},
		{kpqc.SMAUGT192(), "smaugt/mode3", entropyControl{smaugt192.SetTestEntropy, smaugt192.ClearTestEntropy}, 2, 32},
		{kpqc.SMAUGT256(), "smaugt/mode5", entropyControl{smaugt256.SetTestEntropy, smaugt256.ClearTestEntropy}, 2, 32},
		{kpqc.TiMER(), "smaugt/modet", entropyControl{timer.SetTestEntropy, timer.ClearTestEntropy}, 2, 16},
	}

	total := 0
	for _, test := range signatures {
		count := readVectors(t, filepath.Join(vectorRoot, test.path, "kat.rsp"), func(vector map[string]string) {
			drbg := newCTRDRBG(t, decodeField(t, vector, "seed"))
			var keys kpqc.KeyPair
			var err error
			if test.haetae {
				keyEntropy := drbg.generate(test.seedBytes)
				err = withExactEntropy(t, test.entropy, keyEntropy, func() error {
					keys, err = test.algorithm.GenerateKeyPair()
					return err
				})
			} else {
				err = withRepeatedEntropy(t, test.entropy, drbg, test.seedBytes, 128, func() error {
					keys, err = test.algorithm.GenerateKeyPair()
					return err
				})
			}
			if err != nil {
				t.Fatalf("%s vector %s key generation: %v", test.algorithm.ID(), vector["count"], err)
			}
			assertField(t, test.algorithm.ID(), vector, "pk", keys.PublicKey)
			assertField(t, test.algorithm.ID(), vector, "sk", keys.SecretKey)

			message := decodeField(t, vector, "msg")
			signature, hasDetachedSignature := vector["sig"]
			var signatureBytes []byte
			if hasDetachedSignature {
				signatureBytes = decodeHex(t, vector, "sig", signature)
			} else {
				signedMessage := decodeField(t, vector, "sm")
				if len(signedMessage) < len(message) {
					t.Fatal("signed message is shorter than message")
				}
				signatureBytes = signedMessage[len(message):]
			}
			var context []byte
			var signingEntropy []byte
			if test.haetae {
				signingEntropy = drbg.generate(test.seedBytes)
				context = drbg.generate(int(drbg.generate(1)[0]))
			} else {
				signingEntropy = drbg.generate(test.seedBytes)
			}
			var generatedSignature []byte
			err = withExactEntropy(t, test.entropy, signingEntropy, func() error {
				generatedSignature, err = test.algorithm.SignWithContext(message, keys.SecretKey, context)
				return err
			})
			if err != nil {
				t.Fatalf("%s vector %s signing: %v", test.algorithm.ID(), vector["count"], err)
			}
			if !bytes.Equal(generatedSignature, signatureBytes) {
				t.Fatalf("%s vector %s produced the wrong signature", test.algorithm.ID(), vector["count"])
			}
			valid, err := test.algorithm.VerifyWithContext(
				message, signatureBytes, decodeField(t, vector, "pk"), context)
			if err != nil || !valid {
				t.Fatalf("%s vector %s rejected: valid=%v err=%v", test.algorithm.ID(), vector["count"], valid, err)
			}
		})
		if count != 100 {
			t.Fatalf("%s: read %d vectors, want 100", test.algorithm.ID(), count)
		}
		total += count
	}
	for _, test := range kems {
		count := readVectors(t, filepath.Join(vectorRoot, test.path, "kat.rsp"), func(vector map[string]string) {
			drbg := newCTRDRBG(t, decodeField(t, vector, "seed"))
			var keys kpqc.KeyPair
			var err error
			if test.keyCalls == 0 {
				err = withRepeatedEntropy(t, test.entropy, drbg, 32, 128, func() error {
					keys, err = test.algorithm.GenerateKeyPair()
					return err
				})
			} else {
				keyEntropy := make([]byte, 0, test.keyCalls*32)
				for range test.keyCalls {
					keyEntropy = append(keyEntropy, drbg.generate(32)...)
				}
				err = withExactEntropy(t, test.entropy, keyEntropy, func() error {
					keys, err = test.algorithm.GenerateKeyPair()
					return err
				})
			}
			if err != nil {
				t.Fatalf("%s vector %s key generation: %v", test.algorithm.ID(), vector["count"], err)
			}
			assertField(t, test.algorithm.ID(), vector, "pk", keys.PublicKey)
			assertField(t, test.algorithm.ID(), vector, "sk", keys.SecretKey)

			encapsulationEntropy := drbg.generate(test.encBytes)
			var encapsulated kpqc.EncapsulatedSecret
			err = withExactEntropy(t, test.entropy, encapsulationEntropy, func() error {
				encapsulated, err = test.algorithm.Encapsulate(keys.PublicKey)
				return err
			})
			if err != nil {
				t.Fatalf("%s vector %s encapsulation: %v", test.algorithm.ID(), vector["count"], err)
			}
			assertField(t, test.algorithm.ID(), vector, "ct", encapsulated.Ciphertext)
			assertField(t, test.algorithm.ID(), vector, "ss", encapsulated.SharedSecret)

			secret, err := test.algorithm.Decapsulate(encapsulated.Ciphertext, keys.SecretKey)
			if err != nil {
				t.Fatalf("%s vector %s: %v", test.algorithm.ID(), vector["count"], err)
			}
			if !bytes.Equal(secret, decodeField(t, vector, "ss")) {
				t.Fatalf("%s vector %s produced the wrong shared secret", test.algorithm.ID(), vector["count"])
			}
		})
		if count != 100 {
			t.Fatalf("%s: read %d vectors, want 100", test.algorithm.ID(), count)
		}
		total += count
	}
	if total != 1600 {
		t.Fatalf("validated %d vectors, want 1600", total)
	}
}

func TestEntropyFailurePropagates(t *testing.T) {
	if !aimer128f.SetTestEntropy(nil) {
		t.Fatal("could not install failing test entropy")
	}
	defer aimer128f.ClearTestEntropy()

	_, err := kpqc.AIMer128f().GenerateKeyPair()
	var nativeError *kpqc.NativeError
	if !errors.As(err, &nativeError) {
		t.Fatalf("entropy failure returned %v, want *kpqc.NativeError", err)
	}
}

func withExactEntropy(t *testing.T, control entropyControl, entropy []byte, operation func() error) error {
	t.Helper()
	if !control.set(entropy) {
		t.Fatal("could not install deterministic entropy")
	}
	err := operation()
	if remaining := control.clear(); remaining != 0 {
		t.Fatalf("deterministic entropy has %d unconsumed bytes", remaining)
	}
	return err
}

func withRepeatedEntropy(t *testing.T, control entropyControl, drbg *ctrDRBG, callBytes, maxCalls int, operation func() error) error {
	t.Helper()
	probe := *drbg
	entropy := make([]byte, 0, callBytes*maxCalls)
	for range maxCalls {
		entropy = append(entropy, probe.generate(callBytes)...)
	}
	if !control.set(entropy) {
		t.Fatal("could not install deterministic entropy")
	}
	err := operation()
	remaining := control.clear()
	consumed := len(entropy) - remaining
	if consumed <= 0 || consumed%callBytes != 0 {
		t.Fatalf("consumed %d deterministic entropy bytes in %d-byte calls", consumed, callBytes)
	}
	for range consumed / callBytes {
		drbg.generate(callBytes)
	}
	return err
}

func assertField(t *testing.T, algorithm string, vector map[string]string, name string, actual []byte) {
	t.Helper()
	if !bytes.Equal(actual, decodeField(t, vector, name)) {
		t.Fatalf("%s vector %s produced the wrong %s", algorithm, vector["count"], name)
	}
}

func readVectors(t *testing.T, path string, check func(map[string]string)) int {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	count := 0
	vector := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), " = ")
		if !ok {
			continue
		}
		if name == "count" && len(vector) != 0 {
			check(vector)
			count++
			vector = make(map[string]string)
		}
		vector[name] = value
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(vector) != 0 {
		check(vector)
		count++
	}
	return count
}

func decodeField(t *testing.T, vector map[string]string, name string) []byte {
	t.Helper()
	value, ok := vector[name]
	if !ok {
		t.Fatalf("vector %s has no %s field", vector["count"], name)
	}
	return decodeHex(t, vector, name, value)
}

func decodeHex(t *testing.T, vector map[string]string, name, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("vector %s field %s: %v", vector["count"], name, err)
	}
	return decoded
}

type ctrDRBG struct {
	key     [32]byte
	counter [16]byte
}

func newCTRDRBG(t *testing.T, entropy []byte) *ctrDRBG {
	t.Helper()
	if len(entropy) != 48 {
		t.Fatalf("CTR DRBG entropy is %d bytes, want 48", len(entropy))
	}
	result := &ctrDRBG{}
	result.update(entropy)
	return result
}

func (d *ctrDRBG) generate(length int) []byte {
	result := make([]byte, length)
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}
	for offset := 0; offset < length; offset += aes.BlockSize {
		d.increment()
		var output [aes.BlockSize]byte
		block.Encrypt(output[:], d.counter[:])
		copy(result[offset:], output[:])
	}
	d.update(nil)
	return result
}

func (d *ctrDRBG) update(provided []byte) {
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}
	var material [48]byte
	for offset := 0; offset < len(material); offset += aes.BlockSize {
		d.increment()
		block.Encrypt(material[offset:offset+aes.BlockSize], d.counter[:])
	}
	for i := range provided {
		material[i] ^= provided[i]
	}
	copy(d.key[:], material[:32])
	copy(d.counter[:], material[32:])
}

func (d *ctrDRBG) increment() {
	for i := len(d.counter) - 1; i >= 0; i-- {
		d.counter[i]++
		if d.counter[i] != 0 {
			return
		}
	}
}
