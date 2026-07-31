package aut

import (
	"context"
	"errors"

	"github.com/veles-security/vapi"
)

type Chain[R any] []vapi.Authenticator[R]

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

var _ vapi.Authenticator[any] = &Chain[any]{}
