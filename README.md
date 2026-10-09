# KpqC

KpqC provides synchronous Go APIs for the AIMer and HAETAE signature schemes
and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs).

## Runtime support

- Go 1.22 or newer
- cgo and a C11 compiler
- macOS or Linux

## Install

```sh
go get kpqc.dev
```

The package contains the native algorithm sources under `third_party/` and
builds them through cgo. It does not download native libraries during a build.

## Available schemes

| Algorithm | Type | Accessors |
| --- | --- | --- |
| **AIMer** | Signature | `AIMer128f`, `AIMer128s`, `AIMer192f`, `AIMer192s`, `AIMer256f`, `AIMer256s` |
| **HAETAE** | Signature | `HAETAE2`, `HAETAE3`, `HAETAE5` |
| **NTRU+** | KEM | `NTRUPlus768`, `NTRUPlus864`, `NTRUPlus1152` |
| **SMAUG&#8209;T** | KEM | `SMAUGT128`, `SMAUGT192`, `SMAUGT256`, `TiMER` |

### Signatures

```go
package main

import (
	"fmt"
	"log"

	"kpqc.dev"
)

func main() {
	algorithm := kpqc.AIMer128f()
	keys, err := algorithm.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("release-manifest:v3")
	signature, err := algorithm.Sign(message, keys.SecretKey)
	if err != nil {
		log.Fatal(err)
	}

	valid, err := algorithm.Verify(message, signature, keys.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(valid) // true
}
```

`SignWithContext` and `VerifyWithContext` bind a signature to an optional
application context of at most 255 bytes. Verification fails when the supplied
context does not match the one used for signing.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```go
algorithm := kpqc.SMAUGT192()
recipient, err := algorithm.GenerateKeyPair()
if err != nil {
	log.Fatal(err)
}

outbound, err := algorithm.Encapsulate(recipient.PublicKey)
if err != nil {
	log.Fatal(err)
}

inboundSecret, err := algorithm.Decapsulate(
	outbound.Ciphertext,
	recipient.SecretKey,
)
if err != nil {
	log.Fatal(err)
}

fmt.Println(bytes.Equal(inboundSecret, outbound.SharedSecret)) // true
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets use
`[]byte`. Every operation that can fail returns an error. Wrong-sized inputs
wrap `ErrInvalidSize`, contexts over 255 bytes wrap `ErrContextTooLong`, and
native failures return `*NativeError`.

Signature verification returns `false, nil` for an invalid signature. NTRU+
returns a native error for a non-canonical public key or invalid ciphertext.
SMAUG-T performs implicit rejection and returns a replacement secret for an
invalid ciphertext; that value does not equal the sender's shared secret.

### Parameter sizes

All sizes are in bytes.

#### Signatures

| Accessor | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| `AIMer128f` | 32 | 48 | 6,944 |
| `AIMer128s` | 32 | 48 | 4,704 |
| `AIMer192f` | 48 | 72 | 15,408 |
| `AIMer192s` | 48 | 72 | 10,320 |
| `AIMer256f` | 64 | 96 | 31,360 |
| `AIMer256s` | 64 | 96 | 20,224 |
| `HAETAE2` | 992 | 1,408 | 1,474 |
| `HAETAE3` | 1,472 | 2,112 | 2,349 |
| `HAETAE5` | 2,080 | 2,752 | 2,948 |

#### KEM

| Accessor | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| `NTRUPlus768` | 1,152 | 2,336 | 1,152 | 32 |
| `NTRUPlus864` | 1,296 | 2,624 | 1,296 | 32 |
| `NTRUPlus1152` | 1,728 | 3,488 | 1,728 | 32 |
| `SMAUGT128` | 672 | 832 | 672 | 32 |
| `SMAUGT192` | 1,088 | 1,312 | 992 | 32 |
| `SMAUGT256` | 1,440 | 1,728 | 1,376 | 32 |
| `TiMER` | 672 | 832 | 608 | 32 |

## Known-answer tests

Key generation, signing, encapsulation, verification, and decapsulation are
validated byte-for-byte against all 1,600 KAT records in
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da).
The KAT build uses a sibling `kpqc-test-vectors` checkout by default, or the
path in `KPQC_TEST_VECTORS`. Its deterministic entropy interface is compiled
only when the `kpqc_kat` build tag is enabled and is not present in normal
package builds.

```sh
go test ./...
go test -tags=kpqc_kat ./...
```

## Security

The native cores are compiled from the upstream algorithm implementations.
This package has not received an independent security audit and does not
provide a constant-time execution guarantee. Assess those constraints before
using it with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](https://github.com/KpqC/kpqc-go/blob/main/THIRD_PARTY_NOTICES.md).
