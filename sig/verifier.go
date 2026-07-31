package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/veles-security/vapi"
)

type SignVerifier struct {
	Kid string
	Alg SigAlg
	Key crypto.PublicKey
}

// VerifySignature implements [SignatureVerificationSchemer].
func (s *SignVerifier) VerifySignature(signature []byte, digest []byte, options ...SigAlg) (err error) {
	if s == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: nil signature verifier", ErrInvalidKey)}
	}
	alg := s.Alg
	if len(options) != 0 {
		alg = options[0]
	}
	if err := validateVerifierKey(alg, s.Key); err != nil {
		return err
	}
	if digest == nil {
		return &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: fmt.Errorf("%w: nil digest", ErrMalformedDigest)}
	}
	if err := validateSignatureEncoding(alg, s.Key, signature); err != nil {
		return err
	}

	message := digest
	hash := alg.Hash()
	if alg.IsHMAC() {
		if !hash.Available() {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: hash %v is unavailable", ErrInvalidAlgorithm, hash)}
		}
		key, ok := s.Key.([]byte)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: key type %T cannot be used with HMAC", ErrAlgorithmKeyMismatch, s.Key)}
		}
		mac := hmac.New(hash.New, key)
		_, _ = mac.Write(message)
		if !hmac.Equal(signature, mac.Sum(nil)) {
			return vapi.ErrInvalidSignature
		}
		return nil
	}
	if hash != 0 {
		if !hash.Available() {
			return &vapi.ErrorCategory{Category: vapi.ErrMisconfigured, Cause: fmt.Errorf("%w: hash %v is unavailable", ErrInvalidAlgorithm, hash)}
		}
		h := hash.New()
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}

	valid := false
	switch alg {
	case SigAlgRS256, SigAlgRS384, SigAlgRS512, SigAlgRSASHA1:
		key, ok := s.Key.(*rsa.PublicKey)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for RSA", s.Key)}
		}
		valid = rsa.VerifyPKCS1v15(key, hash, digest, signature) == nil

	case SigAlgPS256, SigAlgPS384, SigAlgPS512:
		key, ok := s.Key.(*rsa.PublicKey)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for RSA-PSS", s.Key)}
		}
		valid = rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil

	case SigAlgES256, SigAlgES384, SigAlgES512, SigAlgES256K:
		key, ok := s.Key.(*ecdsa.PublicKey)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for ECDSA", s.Key)}
		}
		valid = ecdsa.VerifyASN1(key, digest, signature)

	case SigAlgEd25519:
		key, ok := s.Key.(ed25519.PublicKey)
		if !ok {
			return &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("invalid key type %T for Ed25519", s.Key)}
		}
		valid = ed25519.Verify(key, message, signature)

	default:
		return &vapi.ErrorCategory{Category: vapi.ErrUnsupported, Cause: fmt.Errorf("unsupported signature algorithm %d", alg)}
	}

	if !valid {
		return vapi.ErrInvalidSignature
	}
	return nil
}

func validateSignatureEncoding(alg SigAlg, key crypto.PublicKey, signature []byte) error {
	switch {
	case alg.IsHMAC():
		if want := alg.Hash().Size(); len(signature) != want {
			return &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: fmt.Errorf("%w: got %d bytes, require %d for algorithm %d", ErrMalformedSignature, len(signature), want, alg)}
		}
	case alg == SigAlgEd25519:
		if len(signature) != ed25519.SignatureSize {
			return &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: fmt.Errorf("%w: got %d bytes, require %d for Ed25519", ErrMalformedSignature, len(signature), ed25519.SignatureSize)}
		}
	case alg == SigAlgES256 || alg == SigAlgES384 || alg == SigAlgES512 || alg == SigAlgES256K:
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
			return &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: fmt.Errorf("%w: invalid ECDSA ASN.1 encoding", ErrMalformedSignature)}
		}
	case alg == SigAlgRS256 || alg == SigAlgRS384 || alg == SigAlgRS512 ||
		alg == SigAlgPS256 || alg == SigAlgPS384 || alg == SigAlgPS512 || alg == SigAlgRSASHA1:
		rsaKey := key.(*rsa.PublicKey) // key type was checked by validateVerifierKey.
		if want := rsaKey.Size(); len(signature) != want {
			return &vapi.ErrorCategory{Category: vapi.ErrMalformed, Cause: fmt.Errorf("%w: got %d bytes, require %d for RSA key", ErrMalformedSignature, len(signature), want)}
		}
	}
	return nil
}

var _ vapi.SignatureVerifier[SigAlg] = &SignVerifier{}
