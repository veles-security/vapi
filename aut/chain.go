package aut

import (
	"context"
	"errors"

	"github.com/veles-security/vapi"
)

type Chain[R any] []vapi.Authenticator[R]

// OR constructs an authentication chain in which any one of the supplied
// authenticators may authenticate the request.
//
// Alternatives are tried from left to right. ErrNotApplicable selects the
// next alternative; any other error stops the chain so that recognized but
// invalid credentials cannot fall through to another mechanism.
func OR[R any](authenticators ...vapi.Authenticator[R]) Chain[R] {
	return Chain[R](authenticators)
}

// AND constructs an authenticator that requires every supplied authenticator
// to succeed. The principal returned by the first authenticator is retained;
// subsequent authenticators are additional required authentication factors.
//
// AND and OR can be nested to describe an authentication policy. For example:
//
//	policy := aut.OR(bearerToken, aut.AND(apiKey, mtls))
func AND[R any](authenticators ...vapi.Authenticator[R]) vapi.Authenticator[R] {
	return allOf[R](authenticators)
}

func (c Chain[R]) Authenticate(ctx context.Context, request R) (vapi.Principal, error) {
	var zero vapi.Principal
	for _, authenticator := range c {
		result, err := authenticator.Authenticate(ctx, request)
		switch {
		case err == nil:
			return result, nil
		case errors.Is(err, vapi.ErrNotApplicable):
			continue
		default:
			// Credentials recognized by an authenticator must not fall through
			// to a weaker or unrelated authentication mechanism.
			return zero, err
		}
	}
	return zero, vapi.ErrUnauthenticated
}

type allOf[R any] []vapi.Authenticator[R]

func (a allOf[R]) Authenticate(ctx context.Context, request R) (vapi.Principal, error) {
	var principal vapi.Principal
	if len(a) == 0 {
		return nil, vapi.ErrUnauthenticated
	}

	for i, authenticator := range a {
		result, err := authenticator.Authenticate(ctx, request)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			principal = result
		}
	}
	return principal, nil
}

var _ vapi.Authenticator[any] = &Chain[any]{}
var _ vapi.Authenticator[any] = allOf[any]{}
