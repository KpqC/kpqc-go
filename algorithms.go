package kpqc

import (
	"kpqc.dev/internal/native/aimer128f"
	"kpqc.dev/internal/native/aimer128s"
	"kpqc.dev/internal/native/aimer192f"
	"kpqc.dev/internal/native/aimer192s"
	"kpqc.dev/internal/native/aimer256f"
	"kpqc.dev/internal/native/aimer256s"
	"kpqc.dev/internal/native/haetae2"
	"kpqc.dev/internal/native/haetae3"
	"kpqc.dev/internal/native/haetae5"
	"kpqc.dev/internal/native/ntruplus1152"
	"kpqc.dev/internal/native/ntruplus768"
	"kpqc.dev/internal/native/ntruplus864"
	"kpqc.dev/internal/native/smaugt128"
	"kpqc.dev/internal/native/smaugt192"
	"kpqc.dev/internal/native/smaugt256"
	"kpqc.dev/internal/native/timer"
)

var (
	aimer128fAlgorithm = newSignature("aimer-128f", SignatureSizes{32, 48, 6944}, signatureBackend{aimer128f.KeyPair, aimer128f.Sign, aimer128f.Verify})
	aimer128sAlgorithm = newSignature("aimer-128s", SignatureSizes{32, 48, 4704}, signatureBackend{aimer128s.KeyPair, aimer128s.Sign, aimer128s.Verify})
	aimer192fAlgorithm = newSignature("aimer-192f", SignatureSizes{48, 72, 15408}, signatureBackend{aimer192f.KeyPair, aimer192f.Sign, aimer192f.Verify})
	aimer192sAlgorithm = newSignature("aimer-192s", SignatureSizes{48, 72, 10320}, signatureBackend{aimer192s.KeyPair, aimer192s.Sign, aimer192s.Verify})
	aimer256fAlgorithm = newSignature("aimer-256f", SignatureSizes{64, 96, 31360}, signatureBackend{aimer256f.KeyPair, aimer256f.Sign, aimer256f.Verify})
	aimer256sAlgorithm = newSignature("aimer-256s", SignatureSizes{64, 96, 20224}, signatureBackend{aimer256s.KeyPair, aimer256s.Sign, aimer256s.Verify})

	haetae2Algorithm = newSignature("haetae-mode2", SignatureSizes{992, 1408, 1474}, signatureBackend{haetae2.KeyPair, haetae2.Sign, haetae2.Verify})
	haetae3Algorithm = newSignature("haetae-mode3", SignatureSizes{1472, 2112, 2349}, signatureBackend{haetae3.KeyPair, haetae3.Sign, haetae3.Verify})
	haetae5Algorithm = newSignature("haetae-mode5", SignatureSizes{2080, 2752, 2948}, signatureBackend{haetae5.KeyPair, haetae5.Sign, haetae5.Verify})

	ntruplus768Algorithm  = newKEM("NTRU+768", KEMSizes{1152, 2336, 1152, 32}, kemBackend{ntruplus768.KeyPair, ntruplus768.Encapsulate, ntruplus768.Decapsulate})
	ntruplus864Algorithm  = newKEM("NTRU+864", KEMSizes{1296, 2624, 1296, 32}, kemBackend{ntruplus864.KeyPair, ntruplus864.Encapsulate, ntruplus864.Decapsulate})
	ntruplus1152Algorithm = newKEM("NTRU+1152", KEMSizes{1728, 3488, 1728, 32}, kemBackend{ntruplus1152.KeyPair, ntruplus1152.Encapsulate, ntruplus1152.Decapsulate})

	smaugt128Algorithm = newKEM("SMAUG-T128", KEMSizes{672, 832, 672, 32}, kemBackend{smaugt128.KeyPair, smaugt128.Encapsulate, smaugt128.Decapsulate})
	smaugt192Algorithm = newKEM("SMAUG-T192", KEMSizes{1088, 1312, 992, 32}, kemBackend{smaugt192.KeyPair, smaugt192.Encapsulate, smaugt192.Decapsulate})
	smaugt256Algorithm = newKEM("SMAUG-T256", KEMSizes{1440, 1728, 1376, 32}, kemBackend{smaugt256.KeyPair, smaugt256.Encapsulate, smaugt256.Decapsulate})
	timerAlgorithm     = newKEM("TiMER", KEMSizes{672, 832, 608, 32}, kemBackend{timer.KeyPair, timer.Encapsulate, timer.Decapsulate})
)

// AIMer128f returns the AIMer-128f signature algorithm.
func AIMer128f() SignatureAlgorithm { return aimer128fAlgorithm }

// AIMer128s returns the AIMer-128s signature algorithm.
func AIMer128s() SignatureAlgorithm { return aimer128sAlgorithm }

// AIMer192f returns the AIMer-192f signature algorithm.
func AIMer192f() SignatureAlgorithm { return aimer192fAlgorithm }

// AIMer192s returns the AIMer-192s signature algorithm.
func AIMer192s() SignatureAlgorithm { return aimer192sAlgorithm }

// AIMer256f returns the AIMer-256f signature algorithm.
func AIMer256f() SignatureAlgorithm { return aimer256fAlgorithm }

// AIMer256s returns the AIMer-256s signature algorithm.
func AIMer256s() SignatureAlgorithm { return aimer256sAlgorithm }

// HAETAE2 returns the HAETAE mode-2 signature algorithm.
func HAETAE2() SignatureAlgorithm { return haetae2Algorithm }

// HAETAE3 returns the HAETAE mode-3 signature algorithm.
func HAETAE3() SignatureAlgorithm { return haetae3Algorithm }

// HAETAE5 returns the HAETAE mode-5 signature algorithm.
func HAETAE5() SignatureAlgorithm { return haetae5Algorithm }

// NTRUPlus768 returns the NTRU+768 KEM.
func NTRUPlus768() KEMAlgorithm { return ntruplus768Algorithm }

// NTRUPlus864 returns the NTRU+864 KEM.
func NTRUPlus864() KEMAlgorithm { return ntruplus864Algorithm }

// NTRUPlus1152 returns the NTRU+1152 KEM.
func NTRUPlus1152() KEMAlgorithm { return ntruplus1152Algorithm }

// SMAUGT128 returns the SMAUG-T128 KEM.
func SMAUGT128() KEMAlgorithm { return smaugt128Algorithm }

// SMAUGT192 returns the SMAUG-T192 KEM.
func SMAUGT192() KEMAlgorithm { return smaugt192Algorithm }

// SMAUGT256 returns the SMAUG-T256 KEM.
func SMAUGT256() KEMAlgorithm { return smaugt256Algorithm }

// TiMER returns the TiMER KEM.
func TiMER() KEMAlgorithm { return timerAlgorithm }

// SignatureAlgorithms returns every supported signature parameter set.
func SignatureAlgorithms() []SignatureAlgorithm {
	return []SignatureAlgorithm{
		AIMer128f(), AIMer128s(), AIMer192f(), AIMer192s(), AIMer256f(), AIMer256s(),
		HAETAE2(), HAETAE3(), HAETAE5(),
	}
}

// KEMAlgorithms returns every supported KEM parameter set.
func KEMAlgorithms() []KEMAlgorithm {
	return []KEMAlgorithm{
		NTRUPlus768(), NTRUPlus864(), NTRUPlus1152(),
		SMAUGT128(), SMAUGT192(), SMAUGT256(), TiMER(),
	}
}
