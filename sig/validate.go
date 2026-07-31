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

func validateSigner(alg SigAlg, signer crypto.Signer) error {
	if !alg.IsHMAC() && !alg.Available() {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: unsupported signature algorithm %d", ErrInvalidAlgorithm, alg)}
	}
	if signer == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: nil signing key", ErrInvalidKey)}
	}
	if alg.IsHMAC() {
		key, ok := signer.(*HmacKey)
		if !ok || key == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with HMAC", ErrAlgorithmKeyMismatch, signer)}
		}
		return validateHMACKey(alg, key.key)
	}
	publicKey, err := signerPublicKey(signer)
	if err != nil {
		return err
	}
	return validatePublicKey(alg, publicKey)
}

func validateVerifierKey(alg SigAlg, key crypto.PublicKey) error {
	if !alg.IsHMAC() && !alg.Available() {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: unsupported signature algorithm %d", ErrInvalidAlgorithm, alg)}
	}
	if alg.IsHMAC() {
		secret, ok := key.([]byte)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with HMAC", ErrAlgorithmKeyMismatch, key)}
		}
		return validateHMACKey(alg, secret)
	}
	return validatePublicKey(alg, key)
}

func validatePublicKey(alg SigAlg, key crypto.PublicKey) error {
	switch alg {
	case SigAlgRS256, SigAlgRS384, SigAlgRS512, SigAlgPS256, SigAlgPS384, SigAlgPS512, SigAlgRSASHA1:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok || rsaKey == nil {
			if key == nil || (ok && rsaKey == nil) {
				return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: nil RSA key", ErrInvalidKey)}
			}
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with RSA", ErrAlgorithmKeyMismatch, key)}
		}
		if rsaKey.N == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: RSA key has no modulus", ErrInvalidKey)}
		}
		if rsaKey.N.BitLen() < minimumRSABits {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: RSA key is too small: got %d bits, require at least %d", ErrInvalidKey, rsaKey.N.BitLen(), minimumRSABits)}
		}
	case SigAlgES256, SigAlgES384, SigAlgES512, SigAlgES256K:
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok || ecKey == nil {
			if key == nil || (ok && ecKey == nil) {
				return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: nil ECDSA key", ErrInvalidKey)}
			}
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with ECDSA", ErrAlgorithmKeyMismatch, key)}
		}
		if ecKey.Curve == nil || ecKey.X == nil || ecKey.Y == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: incomplete ECDSA key", ErrInvalidKey)}
		}
		if err := validateECDSACurve(alg, ecKey); err != nil {
			return err
		}
	case SigAlgEd25519:
		edKey, ok := key.(ed25519.PublicKey)
		if !ok || len(edKey) != ed25519.PublicKeySize {
			if !ok {
				return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with Ed25519", ErrAlgorithmKeyMismatch, key)}
			}
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: invalid Ed25519 public key size %d", ErrInvalidKey, len(edKey))}
		}
	}
	return nil
}

func validateECDSACurve(alg SigAlg, key *ecdsa.PublicKey) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: invalid ECDSA curve: %v", ErrInvalidKey, recovered)}
		}
	}()

	params := key.Curve.Params()
	if params == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: ECDSA curve has no parameters", ErrInvalidKey)}
	}
	want := map[SigAlg]string{
		SigAlgES256:  "P-256",
		SigAlgES384:  "P-384",
		SigAlgES512:  "P-521",
		SigAlgES256K: "secp256k1",
	}[alg]
	if params.Name != want {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: curve %q cannot be used with algorithm %d; require %s", ErrAlgorithmKeyMismatch, params.Name, alg, want)}
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: ECDSA public key is not on curve %s", ErrInvalidKey, want)}
	}
	return nil
}

func validateHMACKey(alg SigAlg, key []byte) error {
	minimum := alg.Hash().Size()
	if len(key) < minimum {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: HMAC key is too short: got %d bytes, require at least %d for algorithm %d", ErrInvalidKey, len(key), minimum, alg)}
	}
	return nil
}

func signerPublicKey(signer crypto.Signer) (key crypto.PublicKey, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: signing key panicked while returning its public key: %v", ErrInvalidKey, recovered)}
		}
	}()
	key = signer.Public()
	if key == nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: signing key has no public key", ErrInvalidKey)}
	}
	return key, nil
}

func safeSign(signer crypto.Signer, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: signing key panicked: %v", ErrInvalidKey, recovered)}
		}
	}()
	return signer.Sign(rand.Reader, digest, opts)
}
