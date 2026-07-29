package vapi

import (
	"context"
	"errors"
)

type Chain[R any] []AuthSchemer[R]

func (c Chain[R]) Authenticate(ctx context.Context, request R) (Principaler, error) {
	var zero Principaler
	for _, authenticator := range c {
		result, err := authenticator.Authenticate(ctx, request)
		switch {
		case err == nil:
			return result, nil
		case errors.Is(err, ErrNotApplicable):
			continue
		default:
			// Credentials recognized by an authenticator must not fall through
			// to a weaker or unrelated authentication mechanism.
			return zero, err
		}
	}
	return zero, ErrUnauthenticated
}

var _ AuthSchemer[any] = &Chain[any]{}
