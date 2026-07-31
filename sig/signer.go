package sig

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/veles-security/vapi"
)

type Signer struct {
	Kid string
	Alg SigAlg
	Key crypto.Signer
}

// Sign implements [SignerSchemer].
func (s *Signer) Sign(ctx context.Context, artifact Message, options ...SigAlg) ([]byte, error) {
	if s == nil {
		return nil, &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("nil signer")}
	}
	alg := s.Alg
	if len(options) != 0 {
		alg = options[0]
	}
	if err := validateSigner(alg, s.Key); err != nil {
		return nil, err
	}
	if alg.IsHMAC() {
		return safeSign(s.Key, artifact, alg)
	}
	digest := []byte(artifact)
	if hash := alg.Hash(); hash != 0 {
		if !hash.Available() {
			return nil, &vapi.ErrorCategory{Category: vapi.ErrNotApplicable, Cause: fmt.Errorf("hash %v is unavailable", hash)}
		}
		h := hash.New()
		_, _ = h.Write(artifact)
		digest = h.Sum(nil)
	}
	opts := crypto.SignerOpts(alg)
	if alg == SigAlgPS256 || alg == SigAlgPS384 || alg == SigAlgPS512 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: alg.Hash()}
	}
	return safeSign(s.Key, digest, opts)
}

var _ vapi.Signer[Message, SigAlg] = &Signer{}
