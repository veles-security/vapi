package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/veles-security/vapi"
)

const minimumRSABits = 2048

func configurationError(format string, args ...any) error {
	return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf(format, args...)}
}

func unsupportedAlgorithm(alg SigAlg) error {
	return &vapi.ErrorCategory{Category: vapi.ErrUnsupported, Cause: fmt.Errorf("unsupported signature algorithm %d", alg)}
}

func validateSigner(alg SigAlg, signer crypto.Signer) error {
	if signer == nil {
		return configurationError("nil signing key")
	}
	if isHMAC(alg) {
		key, ok := signer.(*HmacKey)
		if !ok || key == nil {
			return configurationError("invalid key type %T for HMAC", signer)
		}
		return validateHMACKey(alg, key.key)
	}
	if !isSupportedPublicKeyAlgorithm(alg) {
		return unsupportedAlgorithm(alg)
	}

	publicKey, err := signerPublicKey(signer)
	if err != nil {
		return err
	}
	return validatePublicKey(alg, publicKey)
}

func validateVerifierKey(alg SigAlg, key crypto.PublicKey) error {
	if isHMAC(alg) {
		secret, ok := key.([]byte)
		if !ok {
			return configurationError("invalid key type %T for HMAC", key)
		}
		return validateHMACKey(alg, secret)
	}
	if !isSupportedPublicKeyAlgorithm(alg) {
		return unsupportedAlgorithm(alg)
	}
	return validatePublicKey(alg, key)
}

func validatePublicKey(alg SigAlg, key crypto.PublicKey) error {
	switch alg {
	case SigAlgRS256, SigAlgRS384, SigAlgRS512, SigAlgPS256, SigAlgPS384, SigAlgPS512, SigAlgRSASHA1:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok || rsaKey == nil || rsaKey.N == nil {
			return configurationError("invalid key type %T for RSA", key)
		}
		if rsaKey.N.BitLen() < minimumRSABits {
			return configurationError("RSA key is too small: got %d bits, require at least %d", rsaKey.N.BitLen(), minimumRSABits)
		}
	case SigAlgES256, SigAlgES384, SigAlgES512, SigAlgES256K:
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok || ecKey == nil || ecKey.Curve == nil || ecKey.X == nil || ecKey.Y == nil {
			return configurationError("invalid key type %T for ECDSA", key)
		}
		if err := validateECDSACurve(alg, ecKey); err != nil {
			return err
		}
	case SigAlgEd25519:
		edKey, ok := key.(ed25519.PublicKey)
		if !ok || len(edKey) != ed25519.PublicKeySize {
			return configurationError("invalid key type or size %T for Ed25519", key)
		}
	}
	return nil
}

func validateECDSACurve(alg SigAlg, key *ecdsa.PublicKey) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = configurationError("invalid ECDSA curve: %v", recovered)
		}
	}()

	params := key.Curve.Params()
	if params == nil {
		return configurationError("ECDSA curve has no parameters")
	}
	want := map[SigAlg]string{
		SigAlgES256:  "P-256",
		SigAlgES384:  "P-384",
		SigAlgES512:  "P-521",
		SigAlgES256K: "secp256k1",
	}[alg]
	if params.Name != want {
		return configurationError("invalid curve %q for algorithm %d; require %s", params.Name, alg, want)
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return configurationError("ECDSA public key is not on curve %s", want)
	}
	return nil
}

func validateHMACKey(alg SigAlg, key []byte) error {
	minimum := alg.Hash().Size()
	if len(key) < minimum {
		return configurationError("HMAC key is too short: got %d bytes, require at least %d for algorithm %d", len(key), minimum, alg)
	}
	return nil
}

func signerPublicKey(signer crypto.Signer) (key crypto.PublicKey, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = configurationError("invalid signing key: %v", recovered)
		}
	}()
	key = signer.Public()
	if key == nil {
		return nil, configurationError("signing key has no public key")
	}
	return key, nil
}

func safeSign(signer crypto.Signer, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = configurationError("signing failed: %v", recovered)
		}
	}()
	return signer.Sign(rand.Reader, digest, opts)
}

func isHMAC(alg SigAlg) bool {
	return alg == SigAlgHS256 || alg == SigAlgHS384 || alg == SigAlgHS512
}

func isSupportedPublicKeyAlgorithm(alg SigAlg) bool {
	switch alg {
	case SigAlgRS256, SigAlgRS384, SigAlgRS512,
		SigAlgES256, SigAlgES384, SigAlgES512,
		SigAlgPS256, SigAlgPS384, SigAlgPS512,
		SigAlgEd25519, SigAlgES256K, SigAlgRSASHA1:
		return true
	default:
		return false
	}
}
