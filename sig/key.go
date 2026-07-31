package sig

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"fmt"
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
	if opts == nil {
		return nil, fmt.Errorf("HMAC signer options are nil")
	}
	hash := opts.HashFunc()
	if hash == 0 || !hash.Available() {
		return nil, fmt.Errorf("HMAC hash %v is unavailable", hash)
	}
	mac := hmac.New(hash.New, k.key)
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
