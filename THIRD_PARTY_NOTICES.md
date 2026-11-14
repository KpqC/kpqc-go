# Third-party notices

The portable Go implementations are based on the following upstream reference
implementations:

- [AIMer](https://github.com/samsungsds-opensource/AIMer/tree/734cc76fa4695ca8c8eaa070508db8ff62205e68), Copyright (c) 2022–2026 SAMSUNG SDS — [license](LICENSES/AIMer.txt)
- [HAETAE](https://github.com/CryptoLabInc/HAETAE/tree/743c31df48183fc8c8a39a4f50a634da1c4af03a), Copyright (c) 2026 Team HAETAE — [license](LICENSES/HAETAE.txt)
- [NTRU+](https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89), Copyright (c) 2024–2026 NTRU+ TEAM — [license](LICENSES/NTRUplus.txt)
- [SMAUG-T](https://github.com/CryptoLabInc/SMAUG-T/tree/bbc463cd788eae36c6d155cef667ac9dbd9054cd), Copyright (c) 2026 Team SMAUG-T — [license](LICENSES/SMAUG-T.txt)

These components are distributed under the MIT License. Their original license
texts are retained under `LICENSES/`. The reference C sources are identified by
the pinned links above but are not vendored or compiled into the Go package.

## Portability

The Go implementations use explicit little-endian serialization and defined
integer operations rather than host-memory representations or signed-overflow
behavior. Compatibility is checked byte-for-byte against the referenced
known-answer test vectors.
