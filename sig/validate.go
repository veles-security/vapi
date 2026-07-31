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
	if signer == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("nil signing key")}
	}
	if alg.IsHMAC() {
		key, ok := signer.(*HmacKey)
		if !ok || key == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for HMAC", signer)}
		}
		return validateHMACKey(alg, key.key)
	}
	if !alg.Available() {
		return &vapi.ErrorCategory{Category: vapi.ErrUnsupported, Cause: fmt.Errorf("unsupported signature algorithm %d", alg)}
	}

	publicKey, err := signerPublicKey(signer)
	if err != nil {
		return err
	}
	return validatePublicKey(alg, publicKey)
}

func validateVerifierKey(alg SigAlg, key crypto.PublicKey) error {
	if alg.IsHMAC() {
		secret, ok := key.([]byte)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for HMAC", key)}
		}
		return validateHMACKey(alg, secret)
	}
	if !alg.Available() {
		return &vapi.ErrorCategory{Category: vapi.ErrUnsupported, Cause: fmt.Errorf("unsupported signature algorithm %d", alg)}
	}
	return validatePublicKey(alg, key)
}

func validatePublicKey(alg SigAlg, key crypto.PublicKey) error {
	switch alg {
	case SigAlgRS256, SigAlgRS384, SigAlgRS512, SigAlgPS256, SigAlgPS384, SigAlgPS512, SigAlgRSASHA1:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok || rsaKey == nil || rsaKey.N == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for RSA", key)}
		}
		if rsaKey.N.BitLen() < minimumRSABits {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("RSA key is too small: got %d bits, require at least %d", rsaKey.N.BitLen(), minimumRSABits)}
		}
	case SigAlgES256, SigAlgES384, SigAlgES512, SigAlgES256K:
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok || ecKey == nil || ecKey.Curve == nil || ecKey.X == nil || ecKey.Y == nil {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for ECDSA", key)}
		}
		if err := validateECDSACurve(alg, ecKey); err != nil {
			return err
		}
	case SigAlgEd25519:
		edKey, ok := key.(ed25519.PublicKey)
		if !ok || len(edKey) != ed25519.PublicKeySize {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type or size %T for Ed25519", key)}
		}
	}
	return nil
}

func validateECDSACurve(alg SigAlg, key *ecdsa.PublicKey) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid ECDSA curve: %v", recovered)}
		}
	}()

	params := key.Curve.Params()
	if params == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("ECDSA curve has no parameters")}
	}
	want := map[SigAlg]string{
		SigAlgES256:  "P-256",
		SigAlgES384:  "P-384",
		SigAlgES512:  "P-521",
		SigAlgES256K: "secp256k1",
	}[alg]
	if params.Name != want {
		return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid curve %q for algorithm %d; require %s", params.Name, alg, want)}
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("ECDSA public key is not on curve %s", want)}
	}
	return nil
}

func validateHMACKey(alg SigAlg, key []byte) error {
	minimum := alg.Hash().Size()
	if len(key) < minimum {
		return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("HMAC key is too short: got %d bytes, require at least %d for algorithm %d", len(key), minimum, alg)}
	}
	return nil
}

func signerPublicKey(signer crypto.Signer) (key crypto.PublicKey, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid signing key: %v", recovered)}
		}
	}()
	key = signer.Public()
	if key == nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("signing key has no public key")}
	}
	return key, nil
}

func safeSign(signer crypto.Signer, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("signing failed: %v", recovered)}
		}
	}()
	return signer.Sign(rand.Reader, digest, opts)
}
