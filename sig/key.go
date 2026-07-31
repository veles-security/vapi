package sig

import (
	"crypto"
	"crypto/ed25519"
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

// ----------------------------------------------------------------------------

type Ed448PrivateKey ed25519.PrivateKey

func (s Ed448PrivateKey) Public() crypto.PublicKey {
	return Ed448PublicKey(ed25519.PrivateKey(s).Public().(ed25519.PublicKey))
}
func (s Ed448PrivateKey) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(s), message), nil
}

type Ed448PublicKey ed25519.PublicKey

func (k Ed448PublicKey) Verify(message, signature []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(k), message, signature)
}

// ----------------------------------------------------------------------------

var _ crypto.Signer = &HmacKey{}
var _ crypto.Signer = &PssKey{}
var _ crypto.Signer = &Ed448PrivateKey{}
