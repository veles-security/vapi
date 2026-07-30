package vapi_test

import (
	"bytes"
	"context"
	"crypto"
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
		artifact vapi.Message
		options  []vapi.SigAlg
		signer   crypto.Signer
		want     []byte
		wantErr  bool
	}{
		{
			name:     "success",
			artifact: vapi.Message("digest"),
			options:  []vapi.SigAlg{vapi.SigAlgRS256},
			signer:   keyRSA2048,
			want:     []byte("signature"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &vapi.Signer{Alg: vapi.SigAlgRS256, Key: tt.signer}
			got, gotErr := s.Sign(context.Background(), tt.artifact, tt.options...)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Sign() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Sign() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}
