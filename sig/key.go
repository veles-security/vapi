package sig

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"io"
)

// ----------------------------------------------------------------------------

type HmacKey struct {
	key []byte
}

func NewHmacKey(key []byte) *HmacKey {
	return &HmacKey{key: key}
}

func (k HmacKey) Public() crypto.PublicKey { return k.key }

func (k HmacKey) Sign(random io.Reader, artifact []byte, opts crypto.SignerOpts) ([]byte, error) {
	mac := hmac.New(opts.HashFunc().New, k.key)
	_, _ = mac.Write(artifact)
	return mac.Sum(nil), nil
}

// ----------------------------------------------------------------------------

type PssKey struct {
	*rsa.PrivateKey
}

func (s PssKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return rsa.SignPSS(random, s.PrivateKey, opts.HashFunc(), digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

var _ crypto.Signer = &HmacKey{}
var _ crypto.Signer = &PssKey{}
