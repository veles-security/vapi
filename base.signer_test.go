package vapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"testing"

	"github.com/veles-security/vapi"
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
	keyEd448Public, keyEd448, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hmacKey := []byte("a sufficiently long shared secret for signature tests")
	artifact := vapi.Message("digest")
	hmacSignerKey := vapi.NewHmacKey(hmacKey)

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		artifact        vapi.Message
		signerOptions   []vapi.SigAlg
		verifierOptions []vapi.SigAlg
		signer          *vapi.Signer
		verifier        *vapi.SignVerifier
		wantErr         bool
	}{
		{name: "HS256", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgHS256, Key: hmacSignerKey}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgHS256, Key: hmacKey}},
		{name: "HS384", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgHS384, Key: hmacSignerKey}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgHS384, Key: hmacKey}},
		{name: "HS512", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgHS512, Key: hmacSignerKey}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgHS512, Key: hmacKey}},
		{name: "RS256", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgRS256, Key: keyRSA2048}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgRS256, Key: &keyRSA2048.PublicKey}},
		{name: "RS384", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgRS384, Key: keyRSA2048}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgRS384, Key: &keyRSA2048.PublicKey}},
		{name: "RS512", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgRS512, Key: keyRSA2048}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgRS512, Key: &keyRSA2048.PublicKey}},
		{name: "ES256", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgES256, Key: keyES256}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgES256, Key: &keyES256.PublicKey}},
		{name: "ES384", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgES384, Key: keyES384}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgES384, Key: &keyES384.PublicKey}},
		{name: "ES512", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgES512, Key: keyES512}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgES512, Key: &keyES512.PublicKey}},
		{name: "PS256", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgPS256, Key: vapi.PssKey{keyRSA2048}}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgPS256, Key: &keyRSA2048.PublicKey}},
		{name: "PS384", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgPS384, Key: vapi.PssKey{keyRSA2048}}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgPS384, Key: &keyRSA2048.PublicKey}},
		{name: "PS512", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgPS512, Key: vapi.PssKey{keyRSA2048}}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgPS512, Key: &keyRSA2048.PublicKey}},
		{name: "Ed25519", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgEd25519, Key: keyEd25519}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgEd25519, Key: keyEd25519Public}},
		{name: "Ed448", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgEd448, Key: vapi.Ed448PrivateKey(keyEd448)}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgEd448, Key: vapi.Ed448PublicKey(keyEd448Public)}},
		{name: "ES256K", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgES256K, Key: keyES256}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgES256K, Key: &keyES256.PublicKey}},
		{name: "RSASHA1", artifact: artifact, signer: &vapi.Signer{Alg: vapi.SigAlgRSASHA1, Key: keyRSA2048}, verifier: &vapi.SignVerifier{Alg: vapi.SigAlgRSASHA1, Key: &keyRSA2048.PublicKey}},
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
