package kpqc

import (
	"kpqc.dev/internal/portable/aimer"
	"kpqc.dev/internal/portable/haetae"
	"kpqc.dev/internal/portable/ntruplus"
	"kpqc.dev/internal/portable/smaugt"
)

var (
	aimer128fAlgorithm = newSignature("aimer-128f", SignatureSizes{32, 48, 6944}, signatureBackend{aimer.KeyPair128F, aimer.Sign128F, aimer.Verify128F})
	aimer128sAlgorithm = newSignature("aimer-128s", SignatureSizes{32, 48, 4704}, signatureBackend{aimer.KeyPair128S, aimer.Sign128S, aimer.Verify128S})
	aimer192fAlgorithm = newSignature("aimer-192f", SignatureSizes{48, 72, 15408}, signatureBackend{aimer.KeyPair192F, aimer.Sign192F, aimer.Verify192F})
	aimer192sAlgorithm = newSignature("aimer-192s", SignatureSizes{48, 72, 10320}, signatureBackend{aimer.KeyPair192S, aimer.Sign192S, aimer.Verify192S})
	aimer256fAlgorithm = newSignature("aimer-256f", SignatureSizes{64, 96, 31360}, signatureBackend{aimer.KeyPair256F, aimer.Sign256F, aimer.Verify256F})
	aimer256sAlgorithm = newSignature("aimer-256s", SignatureSizes{64, 96, 20224}, signatureBackend{aimer.KeyPair256S, aimer.Sign256S, aimer.Verify256S})

	haetae2Algorithm = newSignature("haetae-mode2", SignatureSizes{992, 1408, 1474}, signatureBackend{haetae.KeyPair2, haetae.Sign2, haetae.Verify2})
	haetae3Algorithm = newSignature("haetae-mode3", SignatureSizes{1472, 2112, 2349}, signatureBackend{haetae.KeyPair3, haetae.Sign3, haetae.Verify3})
	haetae5Algorithm = newSignature("haetae-mode5", SignatureSizes{2080, 2752, 2948}, signatureBackend{haetae.KeyPair5, haetae.Sign5, haetae.Verify5})

	ntruplus768Algorithm  = newKEM("NTRU+768", KEMSizes{1152, 2336, 1152, 32}, kemBackend{ntruplus.KeyPair768, ntruplus.Encapsulate768, ntruplus.Decapsulate768})
	ntruplus864Algorithm  = newKEM("NTRU+864", KEMSizes{1296, 2624, 1296, 32}, kemBackend{ntruplus.KeyPair864, ntruplus.Encapsulate864, ntruplus.Decapsulate864})
	ntruplus1152Algorithm = newKEM("NTRU+1152", KEMSizes{1728, 3488, 1728, 32}, kemBackend{ntruplus.KeyPair1152, ntruplus.Encapsulate1152, ntruplus.Decapsulate1152})

	smaugt128Algorithm = newKEM("SMAUG-T128", KEMSizes{672, 832, 672, 32}, kemBackend{smaugt.KeyPair128, smaugt.Encapsulate128, smaugt.Decapsulate128})
	smaugt192Algorithm = newKEM("SMAUG-T192", KEMSizes{1088, 1312, 992, 32}, kemBackend{smaugt.KeyPair192, smaugt.Encapsulate192, smaugt.Decapsulate192})
	smaugt256Algorithm = newKEM("SMAUG-T256", KEMSizes{1440, 1728, 1376, 32}, kemBackend{smaugt.KeyPair256, smaugt.Encapsulate256, smaugt.Decapsulate256})
	timerAlgorithm     = newKEM("TiMER", KEMSizes{672, 832, 608, 32}, kemBackend{smaugt.KeyPairTiMER, smaugt.EncapsulateTiMER, smaugt.DecapsulateTiMER})
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
