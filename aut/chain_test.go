package aut

import (
	"context"
	"errors"
	"testing"

	"github.com/veles-security/vapi"
)

type authenticatorFunc[R any] func(context.Context, R) (vapi.Principal, error)

func (f authenticatorFunc[R]) Authenticate(ctx context.Context, request R) (vapi.Principal, error) {
	return f(ctx, request)
}

type testPrincipal struct {
	vapi.Principal
	subject string
}

func (p testPrincipal) Subject() string { return p.subject }

func TestBooleanChain(t *testing.T) {
	principal := testPrincipal{subject: "api-key-user"}
	invalid := errors.New("invalid credentials")

	tests := []struct {
		name        string
		bearerErr   error
		apiKeyErr   error
		mtlsErr     error
		wantErr     error
		wantSubject string
	}{
		{name: "bearer satisfies first alternative", apiKeyErr: invalid, mtlsErr: invalid, wantSubject: "bearer-user"},
		{name: "api key and mtls satisfy second alternative", bearerErr: vapi.ErrNotApplicable, wantSubject: principal.Subject()},
		{name: "api key alone does not satisfy and", bearerErr: vapi.ErrNotApplicable, mtlsErr: vapi.ErrNotApplicable, wantErr: vapi.ErrUnauthenticated},
		{name: "mtls alone does not satisfy and", bearerErr: vapi.ErrNotApplicable, apiKeyErr: vapi.ErrNotApplicable, wantErr: vapi.ErrUnauthenticated},
		{name: "recognized invalid credentials stop evaluation", bearerErr: invalid, wantErr: invalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := map[string]int{}
			auth := func(name, subject string, err error) vapi.Authenticator[string] {
				return authenticatorFunc[string](func(context.Context, string) (vapi.Principal, error) {
					called[name]++
					if err != nil {
						return nil, err
					}
					return testPrincipal{subject: subject}, nil
				})
			}

			policy := OR(
				auth("bearer", "bearer-user", tt.bearerErr),
				AND(
					auth("api-key", principal.Subject(), tt.apiKeyErr),
					auth("mtls", "certificate-user", tt.mtlsErr),
				),
			)

			got, err := policy.Authenticate(context.Background(), "request")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Authenticate() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantSubject != "" && (got == nil || got.Subject() != tt.wantSubject) {
				t.Fatalf("Authenticate() subject = %v, want %q", got, tt.wantSubject)
			}
			if tt.bearerErr == nil && (called["api-key"] != 0 || called["mtls"] != 0) {
				t.Fatalf("successful OR alternative did not short circuit: calls = %v", called)
			}
		})
	}
}

func TestEmptyBooleanChainsAreUnauthenticated(t *testing.T) {
	for name, authenticator := range map[string]vapi.Authenticator[string]{
		"OR":  OR[string](),
		"AND": AND[string](),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := authenticator.Authenticate(context.Background(), "request")
			if !errors.Is(err, vapi.ErrUnauthenticated) {
				t.Fatalf("Authenticate() error = %v, want %v", err, vapi.ErrUnauthenticated)
			}
		})
	}
}
