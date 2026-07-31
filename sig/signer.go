package sig

import (
	"context"
	"crypto"
	"crypto/rand"
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
	alg := s.Alg
	if len(options) != 0 {
		alg = options[0]
	}
	if alg == SigAlgHS256 || alg == SigAlgHS384 || alg == SigAlgHS512 {
		return s.Key.Sign(rand.Reader, artifact, alg)
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
	return s.Key.Sign(rand.Reader, digest, alg)
}

var _ vapi.Signer[Message, SigAlg] = &Signer{}
