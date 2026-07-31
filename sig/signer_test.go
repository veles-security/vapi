package sig_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"testing"

	"github.com/veles-security/vapi/sig"
)

func TestSigner_Sign(t *testing.T) {
	keyRSA2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newECDSA := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	keyES256 := newECDSA(elliptic.P256())
	keyES384 := newECDSA(elliptic.P384())
	keyES512 := newECDSA(elliptic.P521())
	keyEd25519Public, keyEd25519, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("a sufficiently long shared secret for all HMAC signature tests!!!")
	artifact := sig.Message("digest")
	hmacSignerKey := sig.NewHmacKey(hmacKey)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		artifact        sig.Message
		signerOptions   []sig.SigAlg
		verifierOptions []sig.SigAlg
		signer          *sig.Signer
		verifier        *sig.SignVerifier
		wantErr         bool
	}{
		{name: "HS256", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgHS256, Key: hmacSignerKey}, verifier: &sig.SignVerifier{Alg: sig.SigAlgHS256, Key: hmacKey}},
		{name: "HS384", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgHS384, Key: hmacSignerKey}, verifier: &sig.SignVerifier{Alg: sig.SigAlgHS384, Key: hmacKey}},
		{name: "HS512", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgHS512, Key: hmacSignerKey}, verifier: &sig.SignVerifier{Alg: sig.SigAlgHS512, Key: hmacKey}},
		{name: "RS256", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgRS256, Key: keyRSA2048}, verifier: &sig.SignVerifier{Alg: sig.SigAlgRS256, Key: &keyRSA2048.PublicKey}},
		{name: "RS384", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgRS384, Key: keyRSA2048}, verifier: &sig.SignVerifier{Alg: sig.SigAlgRS384, Key: &keyRSA2048.PublicKey}},
		{name: "RS512", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgRS512, Key: keyRSA2048}, verifier: &sig.SignVerifier{Alg: sig.SigAlgRS512, Key: &keyRSA2048.PublicKey}},
		{name: "ES256", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgES256, Key: keyES256}, verifier: &sig.SignVerifier{Alg: sig.SigAlgES256, Key: &keyES256.PublicKey}},
		{name: "ES384", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgES384, Key: keyES384}, verifier: &sig.SignVerifier{Alg: sig.SigAlgES384, Key: &keyES384.PublicKey}},
		{name: "ES512", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgES512, Key: keyES512}, verifier: &sig.SignVerifier{Alg: sig.SigAlgES512, Key: &keyES512.PublicKey}},
		{name: "PS256", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgPS256, Key: sig.PssKey{keyRSA2048}}, verifier: &sig.SignVerifier{Alg: sig.SigAlgPS256, Key: &keyRSA2048.PublicKey}},
		{name: "PS384", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgPS384, Key: sig.PssKey{keyRSA2048}}, verifier: &sig.SignVerifier{Alg: sig.SigAlgPS384, Key: &keyRSA2048.PublicKey}},
		{name: "PS512", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgPS512, Key: sig.PssKey{keyRSA2048}}, verifier: &sig.SignVerifier{Alg: sig.SigAlgPS512, Key: &keyRSA2048.PublicKey}},
		{name: "Ed25519", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgEd25519, Key: keyEd25519}, verifier: &sig.SignVerifier{Alg: sig.SigAlgEd25519, Key: keyEd25519Public}},
		{name: "RSASHA1", artifact: artifact, signer: &sig.Signer{Alg: sig.SigAlgRSASHA1, Key: keyRSA2048}, verifier: &sig.SignVerifier{Alg: sig.SigAlgRSASHA1, Key: &keyRSA2048.PublicKey}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.artifact == nil {
				tt.artifact = artifact
			}
			got, gotErr := tt.signer.Sign(context.Background(), tt.artifact, tt.signerOptions...)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Sign() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Sign() succeeded unexpectedly")
			}
			if err := tt.verifier.VerifySignature(got, tt.artifact, tt.verifierOptions...); err != nil {
				t.Errorf("VerifySignature() failed: %v", err)
			}
		})
	}
}

func TestRejectsInsecureOrIncompatibleKeys(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		alg      sig.SigAlg
		signer   *sig.Signer
		verifier *sig.SignVerifier
	}{
		{
			name:     "short HMAC key",
			alg:      sig.SigAlgHS256,
			signer:   &sig.Signer{Alg: sig.SigAlgHS256, Key: sig.NewHmacKey([]byte("short"))},
			verifier: &sig.SignVerifier{Alg: sig.SigAlgHS256, Key: []byte("short")},
		},
		{
			name:     "weak RSA key",
			alg:      sig.SigAlgRS256,
			signer:   &sig.Signer{Alg: sig.SigAlgRS256, Key: weakRSA},
			verifier: &sig.SignVerifier{Alg: sig.SigAlgRS256, Key: &weakRSA.PublicKey},
		},
		{
			name:     "wrong ES256 curve",
			alg:      sig.SigAlgES256,
			signer:   &sig.Signer{Alg: sig.SigAlgES256, Key: p384},
			verifier: &sig.SignVerifier{Alg: sig.SigAlgES256, Key: &p384.PublicKey},
		},
		{
			name:     "P-256 is not secp256k1",
			alg:      sig.SigAlgES256K,
			signer:   &sig.Signer{Alg: sig.SigAlgES256K, Key: p256},
			verifier: &sig.SignVerifier{Alg: sig.SigAlgES256K, Key: &p256.PublicKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.signer.Sign(context.Background(), sig.Message("message")); err == nil {
				t.Fatal("Sign() accepted insecure or incompatible key")
			}
			if err := tt.verifier.VerifySignature(nil, []byte("message")); err == nil {
				t.Fatal("VerifySignature() accepted insecure or incompatible key")
			}
		})
	}
}

func TestInvalidSignerConfigurationReturnsError(t *testing.T) {
	tests := []struct {
		name   string
		signer *sig.Signer
	}{
		{name: "nil key", signer: &sig.Signer{Alg: sig.SigAlgRS256}},
		{name: "unknown algorithm", signer: &sig.Signer{Alg: sig.SigAlgUnknown, Key: sig.NewHmacKey(make([]byte, 64))}},
		{name: "algorithm and key mismatch", signer: &sig.Signer{Alg: sig.SigAlgRS256, Key: sig.NewHmacKey(make([]byte, 64))}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.signer.Sign(context.Background(), sig.Message("message")); err == nil {
				t.Fatal("Sign() succeeded unexpectedly")
			}
		})
	}
}

func TestNilReceiverReturnsError(t *testing.T) {
	var signer *sig.Signer
	if _, err := signer.Sign(context.Background(), sig.Message("message")); err == nil {
		t.Fatal("nil Signer did not return an error")
	}

	var verifier *sig.SignVerifier
	if err := verifier.VerifySignature(nil, []byte("message")); err == nil {
		t.Fatal("nil SignVerifier did not return an error")
	}
}
