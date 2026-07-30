package vapi_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/veles-security/vapi"
)

func TestSigner_Sign(t *testing.T) {
	keyRSA2048, _ := rsa.GenerateKey(rand.Reader, 2048)
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
		{
			name:     "success",
			artifact: vapi.Message("digest"),
			signer:   &vapi.Signer{Alg: vapi.SigAlgRS256, Key: keyRSA2048},
			verifier: &vapi.SignVerifier{Alg: vapi.SigAlgRS256, Key: &keyRSA2048.PublicKey},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
